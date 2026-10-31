//! User-space half of the executable-mapping allowlist (milestone 8): which
//! files go into the kernel's EXEC_ALLOWED and EXEC_TRUSTED_FS maps.
//!
//! - At startup, [`trusted_filesystems`] names the system filesystem(s)
//!   (where root-owned, not group/other-writable files are allowed without
//!   an entry) and the kernel's internal shmem mount (memfd, treated like
//!   anonymous memory).
//! - Approved overlays (`--overlay`) get an entry for every domain.
//! - At each launch, [`launch_files`] walks the install directory and lists
//!   every ELF or PE file in it that the system rule doesn't already cover.
//!
//! Files are identified as the kernel sees them, by the superblock's device
//! and the inode number (plus the inode generation where the filesystem
//! reports it), so a file created or replaced after launch is not allowed.
//! Known weakness: a file that *was* allowed can still be rewritten in place
//! if the user can write to it; content hashes (IMA / fs-verity) would close
//! that, and are a design question for later.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::File,
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use fairplay_api::{ApiError, ErrorCode};
use fairplay_common::{
    ExecAllow, ExecKey, EXEC_ALLOWED_CAPACITY, EXEC_CHECK_GENERATION, FS_ANON, FS_SYSTEM,
};

use crate::state::ProtectedMap;

/// Most code files (ELF or PE) one launch may add to the allowlist. Big
/// games ship hundreds; a Proton prefix a few thousand.
pub const MAX_FILES_PER_LAUNCH: usize = 8192;
/// Most directory entries one walk looks at, code or not. Keeps a launcher
/// from making the daemon walk the whole disk (`install_dir: "/"`).
pub const MAX_VISITED: usize = 200_000;
/// Deepest directory nesting a walk follows.
pub const MAX_DEPTH: usize = 32;

/// Directories whose filesystems are "system": files there that root owns
/// and only root can write need no allowlist entry.
const SYSTEM_DIRS: &[&str] = &[
    "/",
    "/usr",
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/lib",
    "/lib",
    "/lib64",
    "/opt",
];

/// A file as the kernel's allowlist check sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileId {
    /// `MKDEV(major, minor)` of the file's superblock.
    pub dev: u32,
    pub ino: u64,
    /// `inode->i_generation`, if the filesystem reports it.
    pub generation: Option<u32>,
}

impl FileId {
    /// The allowlist map entry (EXEC_ALLOWED or INPUT_ALLOWED) for this
    /// file in `domain`.
    pub fn entry(&self, domain: u32) -> (ExecKey, ExecAllow) {
        let key = ExecKey {
            domain,
            dev: self.dev,
            ino: self.ino,
        };
        let value = match self.generation {
            Some(generation) => ExecAllow {
                generation,
                flags: EXEC_CHECK_GENERATION,
            },
            None => ExecAllow {
                generation: 0,
                flags: 0,
            },
        };
        (key, value)
    }
}

/// The kernel's dev_t encoding (`MKDEV`), which is what BPF reads from
/// `super_block.s_dev`. Not glibc's `makedev`.
pub fn kdev(major: u32, minor: u32) -> u32 {
    (major << 20) | (minor & 0xf_ffff)
}

/// Mount id -> kernel device of the mount's superblock, from
/// `/proc/self/mountinfo`. `stat`'s `st_dev` is not always that device
/// (btrfs reports one per subvolume), the mount's major:minor is.
#[derive(Debug, Default)]
pub struct Mounts(HashMap<u64, u32>);

impl Mounts {
    pub fn read() -> Result<Self> {
        Ok(Self::parse(
            &std::fs::read_to_string("/proc/self/mountinfo")
                .context("reading /proc/self/mountinfo")?,
        ))
    }

    /// `36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw`
    pub fn parse(text: &str) -> Self {
        Self(
            text.lines()
                .filter_map(|l| {
                    let mut f = l.split_whitespace();
                    let id = f.next()?.parse().ok()?;
                    let (ma, mi) = f.nth(1)?.split_once(':')?;
                    Some((id, kdev(ma.parse().ok()?, mi.parse().ok()?)))
                })
                .collect(),
        )
    }
}

/// What `statx` says about an open file.
struct Stat {
    dev: u32,
    ino: u64,
    uid: u32,
    mode: u32,
}

fn statx(fd: &impl AsRawFd, mounts: &Mounts) -> std::io::Result<Stat> {
    // SAFETY: zeroed statx is a valid out-parameter.
    let mut st: libc::statx = unsafe { std::mem::zeroed() };
    let mask = libc::STATX_TYPE
        | libc::STATX_MODE
        | libc::STATX_UID
        | libc::STATX_INO
        | libc::STATX_MNT_ID;
    // SAFETY: an empty C string with AT_EMPTY_PATH stats the fd itself.
    let rc = unsafe {
        libc::statx(
            fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            mask,
            &mut st,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Internal mounts (memfd's) aren't in mountinfo; their st_dev is the
    // superblock's.
    let dev = (st.stx_mask & libc::STATX_MNT_ID != 0)
        .then(|| mounts.0.get(&st.stx_mnt_id).copied())
        .flatten()
        .unwrap_or_else(|| kdev(st.stx_dev_major, st.stx_dev_minor));
    Ok(Stat {
        dev,
        ino: st.stx_ino,
        uid: st.stx_uid,
        mode: u32::from(st.stx_mode),
    })
}

/// `FS_IOC_GETVERSION`: the inode generation, on filesystems that have one
/// (ext4, btrfs, xfs, ...).
fn generation(f: &File) -> Option<u32> {
    // _IOR('v', 1, long)
    const FS_IOC_GETVERSION: libc::c_ulong = 0x8008_7601;
    let mut g: libc::c_long = 0;
    // SAFETY: the kernel writes one int (we pass room for a long).
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), FS_IOC_GETVERSION as _, &mut g) };
    (rc == 0).then_some(g as u32)
}

/// The filesystems the BPF program trusts wholesale, as (kernel dev, kind).
pub fn trusted_filesystems() -> Result<Vec<(u32, u32)>> {
    let mounts = Mounts::read()?;
    let mut out = BTreeSet::new();
    for dir in SYSTEM_DIRS {
        let Ok(d) = File::open(dir) else { continue };
        let st = statx(&d, &mounts).with_context(|| format!("statx {dir}"))?;
        out.insert((st.dev, FS_SYSTEM));
    }
    // SAFETY: plain syscall; the fd it returns is ours.
    let fd = unsafe { libc::memfd_create(c"fairplayd-probe".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        bail!("memfd_create: {}", std::io::Error::last_os_error());
    }
    // SAFETY: memfd_create just returned it.
    let memfd = unsafe { OwnedFd::from_raw_fd(fd) };
    let st = statx(&memfd, &mounts).context("statx memfd")?;
    if out.iter().any(|&(d, _)| d == st.dev) {
        bail!("memfd shares a device with a system filesystem; refusing to trust it");
    }
    out.insert((st.dev, FS_ANON));
    Ok(out.into_iter().collect())
}

/// Starts of the executable formats a game maps: ELF (Linux code) and
/// MZ/PE (Windows code, mapped by Wine).
pub fn is_code(header: &[u8]) -> bool {
    header.starts_with(b"\x7fELF") || header.starts_with(b"MZ")
}

/// Opens a file for inspection without blocking on a FIFO, following a
/// final symlink only if `follow`. `None` if it isn't a regular file we can
/// open.
fn open_regular(path: &Path, follow: bool) -> Option<File> {
    let nofollow = if follow { 0 } else { libc::O_NOFOLLOW };
    let f = File::options()
        .read(true)
        .custom_flags(nofollow | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .ok()?;
    f.metadata().ok()?.is_file().then_some(f)
}

fn id_of(f: &File, st: &Stat) -> FileId {
    FileId {
        dev: st.dev,
        ino: st.ino,
        generation: generation(f),
    }
}

/// Identity of an approved overlay (`--overlay`). Any regular file, with
/// symlinks resolved now; no format check, the operator named it.
pub fn overlay_file(path: &Path, mounts: &Mounts) -> Result<FileId> {
    named_file("overlay", path, mounts)
}

/// Identity of an executable allowed to make virtual input
/// (`--input-allow`, milestone 7), the same way as an overlay. The kernel
/// compares it with the creating process's `mm->exe_file`.
pub fn input_tool_file(path: &Path, mounts: &Mounts) -> Result<FileId> {
    named_file("input tool", path, mounts)
}

fn named_file(what: &str, path: &Path, mounts: &Mounts) -> Result<FileId> {
    if !path.is_absolute() {
        bail!("{what} {}: must be an absolute path", path.display());
    }
    let f = open_regular(path, true)
        .with_context(|| format!("{what} {}: not a regular file", path.display()))?;
    let st = statx(&f, mounts).with_context(|| format!("statx {}", path.display()))?;
    Ok(id_of(&f, &st))
}

/// The EXEC_ALLOWED entries this daemon made, per domain, so they can be
/// removed when the domain's last process exits and so the map never
/// overflows: a launch that wouldn't fit is refused, never half-applied.
#[derive(Debug, Default)]
pub struct ExecEntries {
    by_domain: BTreeMap<u32, BTreeSet<ExecKey>>,
    used: usize,
}

impl ExecEntries {
    pub fn used(&self) -> usize {
        self.used
    }

    /// Adds `files` for `domain`. Returns how many were new.
    pub fn allow(
        &mut self,
        map: &mut impl ProtectedMap,
        domain: u32,
        files: &[FileId],
    ) -> Result<usize, ApiError> {
        let have = self.by_domain.get(&domain);
        let new: BTreeSet<ExecKey> = files
            .iter()
            .map(|f| ExecKey {
                domain,
                dev: f.dev,
                ino: f.ino,
            })
            .filter(|k| !have.is_some_and(|h| h.contains(k)))
            .collect();
        if new.is_empty() {
            return Ok(0);
        }
        if self.used + new.len() > EXEC_ALLOWED_CAPACITY as usize {
            return Err(ApiError::new(
                ErrorCode::LimitReached,
                format!(
                    "the executable allowlist is full ({} of {EXEC_ALLOWED_CAPACITY} entries used, {} more needed)",
                    self.used,
                    new.len()
                ),
            ));
        }
        let by_key: BTreeMap<(u32, u64), &FileId> =
            files.iter().map(|f| ((f.dev, f.ino), f)).collect();
        let mut added = vec![];
        for &key in &new {
            let (_, value) = by_key[&(key.dev, key.ino)].entry(domain);
            if let Err(e) = map.allow_exec(key, value) {
                for &k in &added {
                    let _ = map.disallow_exec(k);
                }
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    format!("adding to the executable allowlist: {e:#}"),
                ));
            }
            added.push(key);
        }
        self.used += added.len();
        self.by_domain.entry(domain).or_default().extend(added);
        Ok(new.len())
    }

    /// Removes everything `domain` was allowed.
    pub fn release(&mut self, map: &mut impl ProtectedMap, domain: u32) {
        for key in self.by_domain.remove(&domain).unwrap_or_default() {
            if let Err(e) = map.disallow_exec(key) {
                eprintln!("fairplayd: removing {key:?} from EXEC_ALLOWED: {e:#}");
            }
            self.used -= 1;
        }
    }
}

/// Limits for one walk; [`Limits::DEFAULT`] in the daemon, small ones in
/// tests.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_files: usize,
    pub max_visited: usize,
    pub max_depth: usize,
}

impl Limits {
    pub const DEFAULT: Limits = Limits {
        max_files: MAX_FILES_PER_LAUNCH,
        max_visited: MAX_VISITED,
        max_depth: MAX_DEPTH,
    };
}

/// The install directory a launch names, or by default the program's own
/// directory. Must be an absolute path to a directory.
pub fn install_dir(program: &str, install_dir: Option<&str>) -> Result<PathBuf, ApiError> {
    let bad = |m: String| ApiError::new(ErrorCode::BadRequest, m);
    let dir = match install_dir {
        Some(d) if !d.starts_with('/') => {
            return Err(bad("install_dir must be an absolute path".into()))
        }
        Some(d) => PathBuf::from(d),
        None => Path::new(program)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| bad("program has no directory".into()))?
            .to_owned(),
    };
    if !dir.is_dir() {
        return Err(bad(format!(
            "install_dir {} is not a directory",
            dir.display()
        )));
    }
    // The walk runs as root and reads the start of files: never on kernel
    // pseudo-filesystems, where reading can have side effects (/proc/kmsg).
    if let Some(fs) = pseudo_filesystem(&dir) {
        return Err(bad(format!(
            "install_dir {} is on {fs}, not a real filesystem",
            dir.display()
        )));
    }
    Ok(dir)
}

/// The name of the kernel pseudo-filesystem `dir` is on, if it is on one.
fn pseudo_filesystem(dir: &Path) -> Option<&'static str> {
    const PSEUDO: &[(i64, &str)] = &[
        (0x9fa0, "proc"),
        (0x6265_6572, "sysfs"),
        (0x6462_6720, "debugfs"),
        (0x7472_6163, "tracefs"),
        (0x7363_6673, "securityfs"),
        (0x6367_7270, "cgroup2"),
        (0x0027_e0eb, "cgroup"),
        (0xcafe_4a11, "bpf"),
        (0x6265_6570, "configfs"),
        (0xde5e_81e4, "efivarfs"),
        (0x6165_676c, "pstore"),
    ];
    let c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(dir.as_os_str())).ok()?;
    // SAFETY: zeroed statfs is a valid out-parameter; c is NUL-terminated.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    PSEUDO
        .iter()
        .find(|&&(magic, _)| st.f_type as i64 == magic)
        .map(|&(_, name)| name)
}

/// Everything a launch adds to its domain's allowlist: the program itself
/// plus every code file under `dir`, minus files the system rule already
/// allows. Fails (and the launch is refused) if the directory is too big;
/// a partial allowlist would only fail later and less clearly.
pub fn launch_files(
    program: &Path,
    dir: &Path,
    system_devs: &[u32],
    limits: Limits,
) -> Result<Vec<FileId>, ApiError> {
    let internal = |e: anyhow::Error| ApiError::new(ErrorCode::Internal, format!("{e:#}"));
    let mounts = Mounts::read().map_err(internal)?;
    let needs_entry =
        |st: &Stat| !(system_devs.contains(&st.dev) && st.uid == 0 && st.mode & 0o022 == 0);
    let mut out = BTreeSet::new();
    // The program, whatever its format (it may be a script; harmless), and
    // through symlinks, as execve will.
    if let Some(f) = open_regular(program, true) {
        if let Ok(st) = statx(&f, &mounts) {
            if needs_entry(&st) {
                out.insert(id_of(&f, &st));
            }
        }
    }
    let too_many = |what: String| ApiError::new(ErrorCode::LimitReached, what);
    // Like `find -xdev`: stay on the install directory's filesystem.
    let root_dev = std::fs::metadata(dir).map(|m| m.dev()).ok();
    let mut visited = 0usize;
    let mut stack = vec![(dir.to_owned(), 0usize)];
    while let Some((d, depth)) = stack.pop() {
        // Unreadable subdirectories are skipped: the game can't load from
        // them either (it runs as the user, we walk as root).
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            visited += 1;
            if visited > limits.max_visited {
                return Err(too_many(format!(
                    "install_dir {} has more than {} entries",
                    dir.display(),
                    limits.max_visited
                )));
            }
            // file_type() doesn't follow symlinks: symlinked files and
            // directories are skipped (their targets count only if they
            // are inside the directory too).
            let Ok(ft) = e.file_type() else { continue };
            let path = e.path();
            if ft.is_dir() {
                if std::fs::symlink_metadata(&path).map(|m| m.dev()).ok() != root_dev {
                    continue; // a mount point
                }
                if depth + 1 > limits.max_depth {
                    return Err(too_many(format!(
                        "install_dir {} nests deeper than {} directories",
                        dir.display(),
                        limits.max_depth
                    )));
                }
                stack.push((path, depth + 1));
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let Some(mut f) = open_regular(&path, false) else {
                continue;
            };
            let Ok(st) = statx(&f, &mounts) else { continue };
            if !needs_entry(&st) {
                continue;
            }
            let mut header = [0u8; 4];
            let n = f.read(&mut header).unwrap_or(0);
            if !is_code(&header[..n]) {
                continue;
            }
            out.insert(id_of(&f, &st));
            if out.len() > limits.max_files {
                return Err(too_many(format!(
                    "install_dir {} has more than {} code files",
                    dir.display(),
                    limits.max_files
                )));
            }
        }
    }
    Ok(out.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn kernel_dev_encoding() {
        assert_eq!(kdev(252, 1), 0x0fc0_0001);
        assert_eq!(kdev(0, 23), 23);
    }

    #[test]
    fn mountinfo_parsing() {
        let m = Mounts::parse(
            "22 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw\n\
             41 22 0:38 /@home /home rw shared:2 - btrfs /dev/vdb rw\n\
             garbage\n",
        );
        assert_eq!(m.0.get(&22), Some(&kdev(252, 1)));
        assert_eq!(m.0.get(&41), Some(&38));
        assert_eq!(m.0.len(), 2);
    }

    #[test]
    fn code_magic() {
        assert!(is_code(b"\x7fELF\x02"));
        assert!(is_code(b"MZ\x90\x00"));
        assert!(!is_code(b"#!/b"));
        assert!(!is_code(b"\x7fEL"));
        assert!(!is_code(b""));
    }

    #[test]
    fn install_dir_defaults_and_validation() {
        assert_eq!(install_dir("/bin/sh", None).unwrap(), Path::new("/bin"));
        assert_eq!(
            install_dir("/bin/sh", Some("/usr")).unwrap(),
            Path::new("/usr")
        );
        for (program, dir) in [
            ("/bin/sh", Some("usr")),
            ("/bin/sh", Some("/nonexistent-fairplay")),
            ("/bin/sh", Some("/etc/hostname")),
            ("sh", None),
            // Pseudo-filesystems: walking them as root has side effects.
            ("/bin/sh", Some("/proc")),
            ("/bin/sh", Some("/sys/kernel")),
            ("/proc/self/exe", None),
        ] {
            assert_eq!(
                install_dir(program, dir).unwrap_err().code,
                ErrorCode::BadRequest,
                "{program} {dir:?}"
            );
        }
    }

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("fairplayd-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ino(p: &Path) -> u64 {
        std::fs::metadata(p).unwrap().ino()
    }

    #[test]
    fn walk_lists_code_files_only() {
        let t = TempDir::new("walk");
        let d = &t.0;
        std::fs::create_dir_all(d.join("bin/plugins")).unwrap();
        std::fs::write(d.join("bin/game"), b"\x7fELF....").unwrap();
        std::fs::write(d.join("bin/plugins/mod.dll"), b"MZ......").unwrap();
        std::fs::write(d.join("bin/plugins/libx.so"), b"\x7fELF....").unwrap();
        std::fs::write(d.join("data.pak"), b"PAK!....").unwrap();
        std::fs::write(d.join("empty"), b"").unwrap();
        std::fs::hard_link(d.join("bin/game"), d.join("bin/game-link")).unwrap();
        // Symlinks are skipped, even to code outside the directory.
        let outside = TempDir::new("walk-outside");
        std::fs::write(outside.0.join("cheat.so"), b"\x7fELF....").unwrap();
        symlink(outside.0.join("cheat.so"), d.join("cheat.so")).unwrap();
        symlink(&outside.0, d.join("linked-dir")).unwrap();

        let files = launch_files(&d.join("bin/game"), d, &[], Limits::DEFAULT).unwrap();
        let mut inos: Vec<u64> = files.iter().map(|f| f.ino).collect();
        inos.sort();
        let mut want = vec![
            ino(&d.join("bin/game")),
            ino(&d.join("bin/plugins/mod.dll")),
            ino(&d.join("bin/plugins/libx.so")),
        ];
        want.sort();
        assert_eq!(inos, want, "hard links count once; data and symlinks don't");
        let dev = std::fs::metadata(d).unwrap().dev();
        let (ma, mi) = (libc::major(dev), libc::minor(dev));
        // On non-btrfs filesystems the mount's device is stat's device.
        if std::fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .lines()
            .all(|l| !l.contains(" - btrfs "))
        {
            assert!(files.iter().all(|f| f.dev == kdev(ma, mi)));
        }

        // A program outside the directory is added too, whatever it is.
        std::fs::write(outside.0.join("run.sh"), b"#!/bin/sh\n").unwrap();
        let files = launch_files(&outside.0.join("run.sh"), d, &[], Limits::DEFAULT).unwrap();
        assert!(files
            .iter()
            .any(|f| f.ino == ino(&outside.0.join("run.sh"))));
    }

    #[test]
    fn walk_skips_files_the_system_rule_covers() {
        // /bin/sh is root-owned and not group/other-writable; on a system
        // filesystem it needs no entry, elsewhere it does.
        let sh = Path::new("/bin/sh").canonicalize().unwrap();
        let dir = sh.parent().unwrap();
        let mounts = Mounts::read().unwrap();
        let dev = statx(&File::open(&sh).unwrap(), &mounts).unwrap().dev;
        let limits = Limits {
            max_files: usize::MAX,
            max_visited: usize::MAX,
            max_depth: MAX_DEPTH,
        };
        let with = launch_files(&sh, dir, &[dev], limits).unwrap();
        assert!(with.iter().all(|f| f.ino != ino(&sh)));
        let without = launch_files(&sh, dir, &[], limits).unwrap();
        assert!(without.iter().any(|f| f.ino == ino(&sh)));
    }

    #[test]
    fn walk_limits_refuse_the_launch() {
        let t = TempDir::new("limits");
        let d = &t.0;
        for i in 0..3 {
            std::fs::write(d.join(format!("lib{i}.so")), b"\x7fELF").unwrap();
        }
        std::fs::create_dir_all(d.join("a/b")).unwrap();
        let ok = Limits {
            max_files: 3,
            max_visited: 10,
            max_depth: 2,
        };
        assert_eq!(
            launch_files(Path::new("/nonexistent"), d, &[], ok)
                .unwrap()
                .len(),
            3
        );
        for limits in [
            Limits { max_files: 2, ..ok },
            Limits {
                max_visited: 4,
                ..ok
            },
            Limits { max_depth: 1, ..ok },
        ] {
            let e = launch_files(Path::new("/nonexistent"), d, &[], limits).unwrap_err();
            assert_eq!(e.code, ErrorCode::LimitReached, "{limits:?}: {}", e.message);
        }
    }

    #[test]
    fn overlay_must_be_an_absolute_regular_file() {
        let t = TempDir::new("overlay");
        let f = t.0.join("overlay.so");
        std::fs::write(&f, b"anything").unwrap();
        let m = Mounts::read().unwrap();
        assert_eq!(overlay_file(&f, &m).unwrap().ino, ino(&f));
        assert!(overlay_file(Path::new("overlay.so"), &m).is_err());
        assert!(overlay_file(&t.0, &m).is_err());
        assert!(overlay_file(&t.0.join("missing.so"), &m).is_err());
        // A symlink is resolved once, at startup.
        symlink(&f, t.0.join("link.so")).unwrap();
        assert_eq!(overlay_file(&t.0.join("link.so"), &m).unwrap().ino, ino(&f));
        // Input tools are identified the same way.
        assert_eq!(
            input_tool_file(&f, &m).unwrap(),
            overlay_file(&f, &m).unwrap()
        );
        let e = input_tool_file(Path::new("remapper"), &m).unwrap_err();
        assert!(e.to_string().starts_with("input tool remapper"), "{e}");
    }

    #[test]
    fn map_entries_check_the_generation_when_known() {
        let f = FileId {
            dev: 1,
            ino: 2,
            generation: Some(3),
        };
        let (k, v) = f.entry(9);
        assert_eq!((k.domain, k.dev, k.ino), (9, 1, 2));
        assert_eq!((v.generation, v.flags), (3, EXEC_CHECK_GENERATION));
        let (_, v) = FileId {
            generation: None,
            ..f
        }
        .entry(9);
        assert_eq!((v.generation, v.flags), (0, 0));
    }

    #[test]
    fn trusted_filesystems_has_system_and_memfd() {
        let fs = trusted_filesystems().unwrap();
        assert!(fs.iter().any(|&(_, k)| k == FS_SYSTEM));
        assert_eq!(fs.iter().filter(|&&(_, k)| k == FS_ANON).count(), 1);
    }
}
