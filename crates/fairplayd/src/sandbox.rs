//! The vendor anti-cheat's sandbox (milestone 9, part B): what it may see
//! of the file system.
//!
//! The design doc lets the anti-cheat see the game's memory, the game's
//! install directory, its own data and the fairplayd socket: not the home
//! directory, not other programs, not the browser. Memory is the kernel's
//! job (`ptrace_access_check`: a protected process can't reach outside its
//! domain). Files are this module's: for an `anti_cheat` join, fairplayd
//! starts the program in a **mount namespace** of its own, whose root is an
//! empty tmpfs holding only
//!
//! - read-only: `/usr` and the merged-`/usr` symlinks (`/bin`, `/lib`, ...),
//!   a few files from `/etc` ([`ETC`]), the anti-cheat's install directory
//!   and the game's;
//! - read-write: its data directory, `$XDG_DATA_HOME/fairplay/<signer>/`,
//!   created as the user it runs as;
//! - the fairplayd socket, a fresh `/proc`, a minimal `/dev` ([`DEV`], and
//!   `/dev/shm`), and a private `/tmp`.
//!
//! Paths keep their host names, so `/proc/<game>/exe` and the game's files
//! mean the same inside and out. Network stays: the vendor talks to its
//! server.
//!
//! Not Landlock: a Landlocked process may not ptrace (or
//! `process_vm_readv`) a process outside its Landlock domain, and the game
//! isn't in one, so a Landlocked anti-cheat couldn't read the game.
//!
//! [`plan`] decides what to mount (pure, unit-tested); [`Prepared::new`]
//! turns that into C strings before `fork`, because the child may only
//! make async-signal-safe system calls; `launch` runs the steps in the
//! child, then `pivot_root`s into [`NEW_ROOT`].
//!
//! Directories that come from the user (the install directories and the
//! data directory) are opened with the user's permissions first, then
//! cloned into detached mounts (`open_tree(OPEN_TREE_CLONE)`) that the
//! child attaches with `move_mount`: never re-resolved by path as root. (A
//! plain bind from `/proc/self/fd/<n>` fails with EINVAL once the child is
//! in its new namespace: the source mount belongs to the old one.)

use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
};

use fairplay_api::{ApiError, ErrorCode, SandboxInfo};

use crate::state::{Identity, Peer};

/// Where the child mounts the new root's tmpfs, in its own mount namespace
/// (so nothing shows up there on the host).
pub const NEW_ROOT: &str = "/run/fairplay-sandbox";

/// System directories: bound read-only if they are directories, recreated
/// as symlinks if they are symlinks (merged `/usr`), skipped if missing.
pub const SYSTEM: &[&str] = &[
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
];

/// What the dynamic loader, TLS, name resolution, user names and the time
/// zone need from `/etc`; bound read-only if present (symlinks followed).
pub const ETC: &[&str] = &[
    "/etc/ld.so.cache",
    "/etc/ssl",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/localtime",
];

/// Device nodes bound from the host's `/dev`.
pub const DEV: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
];

/// Environment variables dropped for a sandboxed program: they name things
/// that aren't in its mount namespace (display, D-Bus and agent sockets,
/// the runtime directory). `HOME` and `TMPDIR` are replaced.
const HIDDEN_ENV: &[&str] = &[
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
    "SSH_AUTH_SOCK",
    "HOME",
    "TMPDIR",
    "XDG_DATA_HOME",
    "FAIRPLAY_DATA_DIR",
];

/// What a path on the host is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Dir,
    /// Anything else that exists: a file, a device node, a socket.
    File,
    Symlink(PathBuf),
    Missing,
}

/// Looks at the host file system (a fake in tests).
pub trait Host {
    /// Without following a final symlink.
    fn lstat(&self, p: &Path) -> Kind;
    /// Following symlinks.
    fn stat(&self, p: &Path) -> Kind;
}

pub struct RealHost;

impl Host for RealHost {
    fn lstat(&self, p: &Path) -> Kind {
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.file_type().is_symlink() => match std::fs::read_link(p) {
                Ok(to) => Kind::Symlink(to),
                Err(_) => Kind::Missing,
            },
            Ok(m) if m.is_dir() => Kind::Dir,
            Ok(_) => Kind::File,
            Err(_) => Kind::Missing,
        }
    }
    fn stat(&self, p: &Path) -> Kind {
        match std::fs::metadata(p) {
            Ok(m) if m.is_dir() => Kind::Dir,
            Ok(_) => Kind::File,
            Err(_) => Kind::Missing,
        }
    }
}

/// Where a bind mount comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A root-owned system path.
    Path(PathBuf),
    /// A detached mount of a directory fairplayd opened as the user
    /// (an `open_tree` descriptor).
    Fd(i32),
}

/// Mount flags beyond `nosuid`, which every mount gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags {
    pub read_only: bool,
    pub nodev: bool,
    pub noexec: bool,
}

/// Read-only, no devices: system files and install directories.
pub const RO: Flags = Flags {
    read_only: true,
    nodev: true,
    noexec: false,
};
/// The data directory: writable, but nothing in it runs.
pub const DATA: Flags = Flags {
    read_only: false,
    nodev: true,
    noexec: true,
};
/// Device nodes.
pub const DEVICE: Flags = Flags {
    read_only: false,
    nodev: false,
    noexec: true,
};

/// One thing the child does, in order. Paths are inside the new root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// A tmpfs with this root mode (the new root itself is `/`).
    Tmpfs {
        target: PathBuf,
        mode: u32,
    },
    /// `mkdir` (0755); an existing directory is fine.
    Dir(PathBuf),
    /// An empty file to bind a non-directory onto.
    File(PathBuf),
    Bind {
        source: Source,
        target: PathBuf,
        flags: Flags,
    },
    /// A fresh procfs.
    Proc(PathBuf),
    Symlink {
        link: PathBuf,
        to: PathBuf,
    },
}

/// The directories one anti-cheat sees besides the system's, each a
/// canonical absolute path and the descriptor fairplayd opened it by.
#[derive(Debug, Clone, Copy)]
pub struct Dirs<'a> {
    pub game: (&'a Path, i32),
    pub own: (&'a Path, i32),
    pub data: (&'a Path, i32),
    pub socket: &'a Path,
}

/// What to mount, in order: sorted by depth, so a mount never lands under
/// one that comes later; symlinks last, once every directory exists.
pub fn plan(d: Dirs, host: &impl Host) -> Result<Vec<Step>, String> {
    enum What {
        Tmpfs(u32),
        Proc,
        Bind(Source, Flags, bool), // is a directory
    }
    let mut items: Vec<(PathBuf, What)> = vec![("/".into(), What::Tmpfs(0o755))];
    let mut links = vec![];
    for s in SYSTEM {
        let p = Path::new(s);
        match host.lstat(p) {
            Kind::Dir => items.push((p.into(), What::Bind(Source::Path(p.into()), RO, true))),
            Kind::Symlink(to) => links.push(Step::Symlink { link: p.into(), to }),
            _ => {}
        }
    }
    for s in ETC {
        let p = Path::new(s);
        match host.stat(p) {
            Kind::Missing | Kind::Symlink(_) => {}
            k => items.push((
                p.into(),
                What::Bind(Source::Path(p.into()), RO, k == Kind::Dir),
            )),
        }
    }
    items.push(("/dev".into(), What::Tmpfs(0o755)));
    for s in DEV {
        let p = Path::new(s);
        if host.stat(p) != Kind::Missing {
            items.push((p.into(), What::Bind(Source::Path(p.into()), DEVICE, false)));
        }
    }
    items.push(("/dev/shm".into(), What::Tmpfs(0o1777)));
    for (name, to) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        links.push(Step::Symlink {
            link: Path::new("/dev").join(name),
            to: to.into(),
        });
    }
    items.push(("/proc".into(), What::Proc));
    items.push(("/tmp".into(), What::Tmpfs(0o1777)));
    if host.stat(d.socket) == Kind::Missing {
        return Err(format!("socket {} is missing", d.socket.display()));
    }
    items.push((
        d.socket.into(),
        What::Bind(Source::Path(d.socket.into()), RO, false),
    ));

    // The user's directories may not cover any of the above: an install
    // directory of `/` or `/etc` would expose everything under it.
    let fixed: Vec<PathBuf> = items.iter().map(|(p, _)| p.clone()).collect();
    let mut user = vec![(d.game, RO, "game install directory")];
    if !d.own.0.starts_with(d.game.0) {
        user.push((d.own, RO, "anti-cheat install directory"));
    }
    user.push((d.data, DATA, "data directory"));
    for ((path, fd), flags, what) in user {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        {
            return Err(format!("{what} {} is not canonical", path.display()));
        }
        if let Some(f) = fixed.iter().find(|f| f.starts_with(path)) {
            return Err(format!(
                "{what} {} would expose {} to the sandbox",
                path.display(),
                f.display()
            ));
        }
        items.push((path.into(), What::Bind(Source::Fd(fd), flags, true)));
    }

    let depth = |p: &Path| p.components().count();
    items.sort_by_key(|(p, _)| depth(p)); // stable: same depth keeps order
    let mut made = BTreeSet::from([PathBuf::from("/")]);
    let mut steps = vec![];
    for (target, what) in items {
        // Ancestors first (the root exists).
        let mut need: Vec<PathBuf> = target
            .ancestors()
            .skip(1)
            .filter(|a| !made.contains(*a))
            .map(Path::to_path_buf)
            .collect();
        need.reverse();
        for a in need {
            made.insert(a.clone());
            steps.push(Step::Dir(a));
        }
        let is_dir = !matches!(what, What::Bind(_, _, false));
        if made.insert(target.clone()) {
            steps.push(if is_dir {
                Step::Dir(target.clone())
            } else {
                Step::File(target.clone())
            });
        }
        steps.push(match what {
            What::Tmpfs(mode) => Step::Tmpfs { target, mode },
            What::Proc => Step::Proc(target),
            What::Bind(source, flags, _) => Step::Bind {
                source,
                target,
                flags,
            },
        });
    }
    steps.extend(links);
    Ok(steps)
}

/// One [`Step`] as the child runs it: C strings, all paths under
/// [`NEW_ROOT`].
#[derive(Debug)]
enum CStep {
    Mkdir(CString),
    Touch(CString),
    Mount {
        source: CString,
        target: CString,
        fstype: CString,
        flags: libc::c_ulong,
        data: CString,
    },
    /// `mount --bind` (or `move_mount` of a detached tree), then a remount
    /// for the flags (a bind ignores them).
    Bind {
        source: BindSource,
        target: CString,
        flags: libc::c_ulong,
    },
    Symlink {
        to: CString,
        link: CString,
    },
}

#[derive(Debug)]
enum BindSource {
    Path(CString),
    Tree(i32),
}

/// `<linux/mount.h>`, not in the libc crate.
const OPEN_TREE_CLONE: libc::c_uint = 1;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;

/// A sandbox ready for the child: every step as C strings, the directories
/// it binds held open until the child has exec'd, and what
/// `session_status` reports.
#[derive(Debug)]
pub struct Prepared {
    steps: Vec<CStep>,
    /// What each step does, for errors ("mount /usr: ...").
    names: Vec<String>,
    new_root: CString,
    _dirs: Vec<OwnedFd>,
    /// Installed by [`Prepared::seccomp`].
    filter: Vec<libc::sock_filter>,
    pub info: SandboxInfo,
    pub data_dir: PathBuf,
    /// Where the program starts: the requested directory if the sandbox
    /// has it, else the data directory.
    pub cwd: PathBuf,
}

fn cpath(p: &Path) -> CString {
    // Paths come from the OS or from validated strings: no NUL bytes.
    CString::new(p.as_os_str().as_bytes()).expect("path without NUL")
}

fn under_root(p: &Path) -> CString {
    let rel = p.strip_prefix("/").unwrap_or(p);
    if rel.as_os_str().is_empty() {
        cpath(Path::new(NEW_ROOT))
    } else {
        cpath(&Path::new(NEW_ROOT).join(rel))
    }
}

/// `MS_*` flags for a bind remount: what the step asks for, plus whatever
/// the source mount already enforces (`statvfs`), so a bind never lifts a
/// host `noexec` or `ro`.
fn bind_flags(f: Flags, source_mount: libc::c_ulong) -> libc::c_ulong {
    let mut m = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID;
    let has = |st: libc::c_ulong| source_mount & st != 0;
    if f.read_only || has(libc::ST_RDONLY) {
        m |= libc::MS_RDONLY;
    }
    if f.nodev || has(libc::ST_NODEV) {
        m |= libc::MS_NODEV;
    }
    if f.noexec || has(libc::ST_NOEXEC) {
        m |= libc::MS_NOEXEC;
    }
    m
}

fn source_mount_flags(src: &BindSource) -> libc::c_ulong {
    // SAFETY: (f)statvfs fills `st`; the path is a valid C string.
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        let rc = match src {
            BindSource::Path(p) => libc::statvfs(p.as_ptr(), &mut st),
            BindSource::Tree(fd) => libc::fstatvfs(*fd, &mut st),
        };
        if rc == 0 {
            st.f_flag
        } else {
            0
        }
    }
}

/// A detached copy of the mount at `dir` (non-recursive, like `MS_BIND`).
fn clone_tree(dir: &OwnedFd) -> std::io::Result<OwnedFd> {
    // SAFETY: plain system call; on success it returns a new descriptor
    // that nothing else owns.
    unsafe {
        let fd = libc::syscall(
            libc::SYS_open_tree,
            dir.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH as libc::c_uint | OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint,
        );
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(OwnedFd::from_raw_fd(fd as i32))
    }
}

fn steps_to_c(steps: &[Step]) -> (Vec<CStep>, Vec<String>) {
    let mut out = vec![];
    let mut names = vec![];
    for s in steps {
        let (c, name) = match s {
            Step::Dir(p) => (
                CStep::Mkdir(under_root(p)),
                format!("mkdir {}", p.display()),
            ),
            Step::File(p) => (
                CStep::Touch(under_root(p)),
                format!("create {}", p.display()),
            ),
            Step::Tmpfs { target, mode } => (
                CStep::Mount {
                    source: c"tmpfs".into(),
                    target: under_root(target),
                    fstype: c"tmpfs".into(),
                    flags: libc::MS_NOSUID
                        | libc::MS_NODEV
                        | if target == Path::new("/dev") {
                            libc::MS_NOEXEC
                        } else {
                            0
                        },
                    data: CString::new(format!("mode={mode:o}")).expect("no NUL"),
                },
                format!("mount tmpfs on {}", target.display()),
            ),
            Step::Proc(p) => (
                CStep::Mount {
                    source: c"proc".into(),
                    target: under_root(p),
                    fstype: c"proc".into(),
                    flags: libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    // Only processes it may look at (its own, and the game
                    // for a reader) show up at all: the kernel asks
                    // ptrace_access_check about each one. hidepid exempts
                    // members of the mount's `gid`, 0 by default, which
                    // would exempt a root anti-cheat: name a group nobody
                    // is in.
                    data: PROC_OPTIONS.into(),
                },
                format!("mount proc on {}", p.display()),
            ),
            Step::Bind {
                source,
                target,
                flags,
            } => {
                let src = match source {
                    Source::Path(p) => BindSource::Path(cpath(p)),
                    Source::Fd(fd) => BindSource::Tree(*fd),
                };
                let host = source_mount_flags(&src);
                (
                    CStep::Bind {
                        source: src,
                        target: under_root(target),
                        flags: bind_flags(*flags, host),
                    },
                    format!("bind {}", target.display()),
                )
            }
            Step::Symlink { link, to } => (
                CStep::Symlink {
                    to: cpath(to),
                    link: under_root(link),
                },
                format!("symlink {}", link.display()),
            ),
        };
        out.push(c);
        names.push(name);
    }
    (out, names)
}

/// Opens a directory without following it anywhere later: an `O_PATH`
/// descriptor, and its canonical path as the kernel resolved it.
fn open_dir(p: &Path) -> std::io::Result<(OwnedFd, PathBuf)> {
    let f = File::options()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open(p)?;
    let real = std::fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd()))?;
    Ok((f.into(), real))
}

/// `ed25519:ab12...` -> `ed25519-ab12...`: one plain path component.
pub fn vendor_dir_name(fingerprint: &str) -> String {
    fingerprint
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// `$XDG_DATA_HOME/fairplay/<vendor>`, with `XDG_DATA_HOME` from the
/// launch's environment if it is absolute, else `<home>/.local/share`.
pub fn data_dir(env: &[String], home: &Path, fingerprint: &str) -> PathBuf {
    let xdg = env
        .iter()
        .filter_map(|kv| kv.strip_prefix("XDG_DATA_HOME="))
        .rfind(|v| v.starts_with('/'))
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"));
    xdg.join("fairplay").join(vendor_dir_name(fingerprint))
}

/// The environment a sandboxed program gets: `env` without what points
/// outside the sandbox, plus `HOME` and `FAIRPLAY_DATA_DIR` set to its data
/// directory and `TMPDIR=/tmp`.
pub fn sandbox_env(env: &[String], data_dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = env
        .iter()
        .filter(|kv| {
            let key = kv.split_once('=').map_or(kv.as_str(), |(k, _)| k);
            !HIDDEN_ENV.contains(&key)
        })
        .cloned()
        .collect();
    let d = data_dir.display();
    out.push(format!("HOME={d}"));
    out.push(format!("FAIRPLAY_DATA_DIR={d}"));
    out.push("TMPDIR=/tmp".into());
    out
}

/// One `anti_cheat` join, as [`prepare`] needs it.
pub struct Request<'a> {
    /// Who the anti-cheat runs as.
    pub id: &'a Identity,
    /// Their home directory (from the user database).
    pub home: &'a Path,
    /// The launch's environment (for `XDG_DATA_HOME`).
    pub env: &'a [String],
    /// The session manifest's signer: one data directory per vendor key.
    pub fingerprint: &'a str,
    pub game_dir: &'a Path,
    pub own_dir: &'a Path,
    pub socket: &'a Path,
    /// The requested working directory.
    pub cwd: &'a str,
}

/// Everything the sandbox for one `anti_cheat` join needs, opened and
/// checked before `fork`: creates the data directory as the user (owned by
/// them, mode 0700), opens the three directories with their permissions,
/// and builds the steps.
pub fn prepare(r: Request) -> Result<Prepared, ApiError> {
    let Request {
        id,
        home,
        env,
        fingerprint,
        game_dir,
        own_dir,
        socket,
        cwd,
    } = r;
    let bad = |m: String| ApiError::new(ErrorCode::BadRequest, m);
    let data = data_dir(env, home, fingerprint);
    let as_user = Peer {
        pid: 0,
        uid: id.uid,
        gid: id.gid,
        groups: id.groups.clone(),
    };
    let (game, own) = (game_dir.to_owned(), own_dir.to_owned());
    let uid = id.uid;
    let opened = crate::verify::as_caller(&as_user, move || {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&data)
            .map_err(|e| bad(format!("creating data directory {}: {e}", data.display())))?;
        let open = |p: &Path, what: &str| {
            open_dir(p).map_err(|e| bad(format!("{what} {}: {e}", p.display())))
        };
        let data = open(&data, "data directory")?;
        let owner = std::fs::metadata(&data.1).map(|m| m.uid()).ok();
        if owner != Some(uid) {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                format!(
                    "data directory {} is not owned by uid {uid}",
                    data.1.display()
                ),
            ));
        }
        Ok((
            open(&game, "game install directory")?,
            open(&own, "anti-cheat install directory")?,
            data,
        ))
    })?;
    let ((game_fd, game), (own_fd, own), (data_fd, data)) = opened;
    let tree = |fd: &OwnedFd, p: &Path| {
        clone_tree(fd).map_err(|e| {
            ApiError::new(
                ErrorCode::Internal,
                format!("open_tree {}: {e}", p.display()),
            )
        })
    };
    let (game_fd, own_fd, data_fd) = (
        tree(&game_fd, &game)?,
        tree(&own_fd, &own)?,
        tree(&data_fd, &data)?,
    );
    let steps = plan(
        Dirs {
            game: (&game, game_fd.as_raw_fd()),
            own: (&own, own_fd.as_raw_fd()),
            data: (&data, data_fd.as_raw_fd()),
            socket,
        },
        &RealHost,
    )
    .map_err(bad)?;
    std::fs::create_dir_all(NEW_ROOT)
        .map_err(|e| ApiError::new(ErrorCode::Internal, format!("{NEW_ROOT}: {e}")))?;
    let (steps, names) = steps_to_c(&steps);
    let mut read_only = vec![game.display().to_string()];
    if !own.starts_with(&game) {
        read_only.push(own.display().to_string());
    }
    let cwd = Path::new(cwd);
    let cwd = if [&game, &own, &data].iter().any(|d| cwd.starts_with(d)) {
        cwd.to_owned()
    } else {
        data.clone()
    };
    Ok(Prepared {
        steps,
        names,
        new_root: cpath(Path::new(NEW_ROOT)),
        _dirs: vec![game_fd, own_fd, data_fd],
        filter: seccomp_filter(),
        info: SandboxInfo {
            data_dir: data.display().to_string(),
            read_only,
        },
        data_dir: data,
        cwd,
    })
}

/// Mount options for the sandbox's `/proc`. 2147483646 is a group id no
/// account uses (the kernel only refuses -1).
pub const PROC_OPTIONS: &std::ffi::CStr = c"hidepid=invisible,gid=2147483646";

/// Stage numbers [`Prepared::enter`] reports, after `launch`'s own.
pub const STAGE_UNSHARE: u32 = 1000;
pub const STAGE_PRIVATE: u32 = 1001;
pub const STAGE_PIVOT: u32 = 1002;
pub const STAGE_ROOT_RO: u32 = 1003;
pub const STAGE_SECCOMP: u32 = 1004;
/// Step `i` fails as stage `STAGE_STEP + i`.
pub const STAGE_STEP: u32 = 2000;

impl Prepared {
    /// The name of a failing stage from [`Prepared::enter`].
    pub fn stage_name(&self, stage: u32) -> Option<String> {
        Some(match stage {
            STAGE_UNSHARE => "unshare(CLONE_NEWNS)".into(),
            STAGE_PRIVATE => "making mounts private".into(),
            STAGE_PIVOT => "pivot_root".into(),
            STAGE_ROOT_RO => "remounting / read-only".into(),
            STAGE_SECCOMP => "seccomp filter".into(),
            s if s >= STAGE_STEP => self.names.get((s - STAGE_STEP) as usize)?.clone(),
            _ => return None,
        })
    }

    /// Runs in the forked child: a new mount namespace, the steps, then
    /// `pivot_root`. Async-signal-safe system calls only. `Err` is the
    /// failing stage (errno is left set).
    ///
    /// # Safety
    /// Only in a single-threaded child about to exec.
    pub unsafe fn enter(&self) -> Result<(), u32> {
        let null = std::ptr::null::<libc::c_char>();
        unsafe {
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return Err(STAGE_UNSHARE);
            }
            // Nothing we mount propagates back to the host.
            if libc::mount(
                null,
                c"/".as_ptr(),
                null,
                libc::MS_REC | libc::MS_PRIVATE,
                null.cast(),
            ) != 0
            {
                return Err(STAGE_PRIVATE);
            }
            for (i, s) in self.steps.iter().enumerate() {
                let ok = match s {
                    CStep::Mkdir(p) => {
                        libc::mkdir(p.as_ptr(), 0o755) == 0
                            || *libc::__errno_location() == libc::EEXIST
                    }
                    CStep::Touch(p) => {
                        let fd = libc::open(
                            p.as_ptr(),
                            libc::O_RDONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                            0o644,
                        );
                        fd >= 0 && libc::close(fd) == 0
                    }
                    CStep::Mount {
                        source,
                        target,
                        fstype,
                        flags,
                        data,
                    } => {
                        let data = if data.is_empty() { null } else { data.as_ptr() };
                        libc::mount(
                            source.as_ptr(),
                            target.as_ptr(),
                            fstype.as_ptr(),
                            *flags,
                            data.cast(),
                        ) == 0
                    }
                    CStep::Bind {
                        source,
                        target,
                        flags,
                    } => {
                        let attached = match source {
                            BindSource::Path(p) => {
                                libc::mount(
                                    p.as_ptr(),
                                    target.as_ptr(),
                                    null,
                                    libc::MS_BIND,
                                    null.cast(),
                                ) == 0
                            }
                            BindSource::Tree(fd) => {
                                libc::syscall(
                                    libc::SYS_move_mount,
                                    *fd,
                                    c"".as_ptr(),
                                    libc::AT_FDCWD,
                                    target.as_ptr(),
                                    MOVE_MOUNT_F_EMPTY_PATH,
                                ) == 0
                            }
                        };
                        attached
                            && libc::mount(null, target.as_ptr(), null, *flags, null.cast()) == 0
                    }
                    CStep::Symlink { to, link } => libc::symlink(to.as_ptr(), link.as_ptr()) == 0,
                };
                if !ok {
                    return Err(STAGE_STEP + i as u32);
                }
            }
            // pivot_root(".", "."): the old root ends up stacked on the new
            // one, and is detached right away.
            if libc::chdir(self.new_root.as_ptr()) != 0
                || libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) != 0
                || libc::umount2(c".".as_ptr(), libc::MNT_DETACH) != 0
                || libc::chdir(c"/".as_ptr()) != 0
            {
                return Err(STAGE_PIVOT);
            }
            let ro = libc::MS_BIND
                | libc::MS_REMOUNT
                | libc::MS_RDONLY
                | libc::MS_NOSUID
                | libc::MS_NODEV;
            if libc::mount(null, c"/".as_ptr(), null, ro, null.cast()) != 0 {
                return Err(STAGE_ROOT_RO);
            }
        }
        Ok(())
    }

    /// Installs [`seccomp_filter`]. Async-signal-safe. Needs `no_new_privs`
    /// (or CAP_SYS_ADMIN); `launch` calls it right after setting that.
    ///
    /// # Safety
    /// Only in the forked child.
    pub unsafe fn seccomp(&self) -> Result<(), u32> {
        let prog = libc::sock_fprog {
            len: self.filter.len() as u16,
            filter: self.filter.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: prog points at a live filter for the duration of the call.
        let rc = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &prog as *const libc::sock_fprog,
            )
        };
        if rc != 0 {
            return Err(STAGE_SECCOMP);
        }
        Ok(())
    }
}

/// System calls the sandbox refuses with EPERM (milestone 9, part B). The
/// anti-cheat reads the game; it never writes to or controls it, nor
/// borrows its files: `ptrace` (attach, poke, and making the game run
/// code), `process_vm_writev`, `pidfd_getfd` (copying the game's open
/// files, e.g. Wine's handle on `/`), `process_madvise`. `process_vm_readv`
/// and reading `/proc/<pid>/mem` stay. Writes to `/proc/<pid>/mem` and
/// signals outside the sandbox are refused by the BPF LSM instead (seccomp
/// sees neither paths nor targets).
///
/// The rest is defence in depth (#30): nothing that reads a game's memory
/// and module list needs them, and each is a way to change what the
/// sandbox sees or to reach a large kernel surface. Most already fail for
/// an ordinary user, but the anti-cheat may run as root (the milestone 9
/// test does, on purpose), and root keeps its capabilities in here:
///
/// - namespaces: `setns`, `unshare` (and `clone` with a `CLONE_NEW*` flag,
///   see [`seccomp_filter`]): a new user namespace makes even an ordinary
///   user root inside it, with mounts of its own;
/// - mounts: `mount`, `umount2` (uncovering what the sandbox's mounts
///   hide), the new mount API (`open_tree`, `move_mount`, `fsopen`,
///   `fsconfig`, `fsmount`, `fspick`, `mount_setattr`: e.g. making a
///   read-only mount writable), `pivot_root` and `chroot`;
/// - the kernel keyring (`keyctl`, `add_key`, `request_key`): per user,
///   shared with the user's other programs, outside any mount namespace;
/// - `bpf`: loading programs or touching maps (fairplayd's too, as root)
///   is the operating system's job, never the anti-cheat's.
///
/// fairplayd's own mounts and `pivot_root` for the sandbox happen before
/// the filter is installed (`launch`: [`Prepared::enter`], then
/// [`Prepared::seccomp`]).
pub const DENIED_SYSCALLS: &[(&str, libc::c_long)] = &[
    ("ptrace", libc::SYS_ptrace),
    ("process_vm_writev", libc::SYS_process_vm_writev),
    ("pidfd_getfd", libc::SYS_pidfd_getfd),
    ("process_madvise", libc::SYS_process_madvise),
    ("setns", libc::SYS_setns),
    ("unshare", libc::SYS_unshare),
    ("mount", libc::SYS_mount),
    ("umount2", libc::SYS_umount2),
    ("open_tree", libc::SYS_open_tree),
    ("move_mount", libc::SYS_move_mount),
    ("fsopen", libc::SYS_fsopen),
    ("fsconfig", libc::SYS_fsconfig),
    ("fsmount", libc::SYS_fsmount),
    ("fspick", libc::SYS_fspick),
    ("mount_setattr", libc::SYS_mount_setattr),
    ("pivot_root", libc::SYS_pivot_root),
    ("chroot", libc::SYS_chroot),
    ("keyctl", libc::SYS_keyctl),
    ("add_key", libc::SYS_add_key),
    ("request_key", libc::SYS_request_key),
    ("bpf", libc::SYS_bpf),
];

/// `clone` flags that make a new namespace (`<linux/sched.h>`; libc has
/// no `CLONE_NEWTIME`). `clone`'s flags are its first argument on both
/// x86-64 and arm64, and the kernel reads only their low 32 bits.
pub const CLONE_NEW_FLAGS: u32 = libc::CLONE_NEWNS as u32
    | libc::CLONE_NEWCGROUP as u32
    | libc::CLONE_NEWUTS as u32
    | libc::CLONE_NEWIPC as u32
    | libc::CLONE_NEWUSER as u32
    | libc::CLONE_NEWPID as u32
    | libc::CLONE_NEWNET as u32
    | CLONE_NEWTIME;
const CLONE_NEWTIME: u32 = 0x80;

/// `<linux/audit.h>`: the architecture a filter was written for. A system
/// call made through another ABI (32-bit compat) kills the process.
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
/// x86-64's x32 ABI: the same numbers with this bit set.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// Classic BPF opcodes (`<linux/filter.h>`).
/// `BPF_LD | BPF_W | BPF_ABS`.
const LD_W_ABS: u16 = 0x20;
/// `BPF_JMP | BPF_JEQ | BPF_K`.
const JMP_JEQ_K: u16 = 0x15;
/// `BPF_JMP | BPF_JSET | BPF_K`.
const JMP_JSET_K: u16 = 0x45;
#[cfg(target_arch = "x86_64")]
/// `BPF_JMP | BPF_JGE | BPF_K`.
const JMP_JGE_K: u16 = 0x35;
const RET_K: u16 = 0x06;
/// `struct seccomp_data` offsets: `nr`, `arch`, then the low 32 bits of
/// the first argument (little-endian on both architectures).
const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;
const OFFSET_ARG0_LO: u32 = 16;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// The sandbox's seccomp filter: wrong architecture -> kill; a call in
/// [`DENIED_SYSCALLS`], or `clone` with a [`CLONE_NEW_FLAGS`] flag, ->
/// EPERM; `clone3` -> ENOSYS; anything else allowed.
///
/// `clone3` passes its flags in memory, which seccomp can't read, so it
/// can't be checked like `clone`. ENOSYS ("not implemented") makes glibc
/// fall back to `clone` for threads and `posix_spawn`, as it does on
/// kernels older than 5.3.
pub fn seccomp_filter() -> Vec<libc::sock_filter> {
    let eperm = libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32 & libc::SECCOMP_RET_DATA);
    let enosys = libc::SECCOMP_RET_ERRNO | (libc::ENOSYS as u32 & libc::SECCOMP_RET_DATA);
    let mut f = vec![
        stmt(LD_W_ABS, OFFSET_ARCH),
        jump(JMP_JEQ_K, AUDIT_ARCH, 1, 0),
        stmt(RET_K, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(LD_W_ABS, OFFSET_NR),
    ];
    #[cfg(target_arch = "x86_64")]
    f.extend([jump(JMP_JGE_K, X32_SYSCALL_BIT, 0, 1), stmt(RET_K, eperm)]);
    for &(_, nr) in DENIED_SYSCALLS {
        f.push(jump(JMP_JEQ_K, nr as u32, 0, 1));
        f.push(stmt(RET_K, eperm));
    }
    f.push(jump(JMP_JEQ_K, libc::SYS_clone3 as u32, 0, 1));
    f.push(stmt(RET_K, enosys));
    // clone: load its flags (last, since this replaces `nr` in the
    // accumulator), EPERM if any namespace flag is set.
    f.extend([
        jump(JMP_JEQ_K, libc::SYS_clone as u32, 0, 3),
        stmt(LD_W_ABS, OFFSET_ARG0_LO),
        jump(JMP_JSET_K, CLONE_NEW_FLAGS, 0, 1),
        stmt(RET_K, eperm),
    ]);
    f.push(stmt(RET_K, libc::SECCOMP_RET_ALLOW));
    f
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// A host with merged /usr, all of ETC and DEV, and a socket.
    struct Fake(HashMap<&'static str, Kind>);
    impl Fake {
        fn new() -> Self {
            let mut m = HashMap::from([
                ("/usr", Kind::Dir),
                ("/bin", Kind::Symlink("usr/bin".into())),
                ("/sbin", Kind::Symlink("usr/sbin".into())),
                ("/lib", Kind::Symlink("usr/lib".into())),
                ("/etc/ssl", Kind::Dir),
                ("/run/fairplayd.sock", Kind::File),
            ]);
            for f in ETC.iter().chain(DEV).filter(|f| **f != "/etc/ssl") {
                m.insert(f, Kind::File);
            }
            Fake(m)
        }
    }
    impl Host for Fake {
        fn lstat(&self, p: &Path) -> Kind {
            self.0
                .get(p.to_str().unwrap())
                .cloned()
                .unwrap_or(Kind::Missing)
        }
        fn stat(&self, p: &Path) -> Kind {
            match self.lstat(p) {
                Kind::Symlink(_) => Kind::Dir,
                k => k,
            }
        }
    }

    fn dirs<'a>(game: &'a str, own: &'a str, data: &'a str) -> Dirs<'a> {
        Dirs {
            game: (Path::new(game), 10),
            own: (Path::new(own), 11),
            data: (Path::new(data), 12),
            socket: Path::new("/run/fairplayd.sock"),
        }
    }

    fn binds(steps: &[Step]) -> Vec<(String, Source, Flags)> {
        steps
            .iter()
            .filter_map(|s| match s {
                Step::Bind {
                    source,
                    target,
                    flags,
                } => Some((target.display().to_string(), source.clone(), *flags)),
                _ => None,
            })
            .collect()
    }

    fn position(steps: &[Step], f: impl Fn(&Step) -> bool) -> usize {
        steps.iter().position(f).expect("step present")
    }

    #[test]
    fn plan_mounts_what_the_design_allows_and_nothing_else() {
        let steps = plan(
            dirs("/games/g", "/opt/vendor", "/home/u/.local/share/fairplay/v"),
            &Fake::new(),
        )
        .unwrap();
        // The new root first.
        assert_eq!(
            steps[0],
            Step::Tmpfs {
                target: "/".into(),
                mode: 0o755
            }
        );
        let b = binds(&steps);
        let targets: Vec<&str> = b.iter().map(|(t, _, _)| t.as_str()).collect();
        let mut expected = vec!["/usr", "/dev/null", "/dev/zero", "/dev/full"];
        expected.extend(["/dev/random", "/dev/urandom", "/dev/tty"]);
        expected.extend(ETC);
        expected.extend([
            "/run/fairplayd.sock",
            "/games/g",
            "/opt/vendor",
            "/home/u/.local/share/fairplay/v",
        ]);
        let mut sorted = targets.clone();
        sorted.sort();
        expected.sort();
        assert_eq!(sorted, expected);
        // Read-only: everything but the data directory and device nodes.
        for (t, src, f) in &b {
            match t.as_str() {
                "/home/u/.local/share/fairplay/v" => {
                    assert_eq!((src, *f), (&Source::Fd(12), DATA))
                }
                t if t.starts_with("/dev/") => assert_eq!(*f, DEVICE, "{t}"),
                "/games/g" => assert_eq!((src, *f), (&Source::Fd(10), RO)),
                "/opt/vendor" => assert_eq!((src, *f), (&Source::Fd(11), RO)),
                t => assert_eq!((src, *f), (&Source::Path(t.into()), RO), "{t}"),
            }
        }
        // No home directory beyond the path down to the data directory.
        assert!(!targets.iter().any(|t| *t == "/home" || *t == "/home/u"));
        // Fresh /proc, private /tmp and /dev/shm, /dev on tmpfs.
        assert!(steps.contains(&Step::Proc("/proc".into())));
        for (t, mode) in [("/tmp", 0o1777), ("/dev/shm", 0o1777), ("/dev", 0o755)] {
            assert!(
                steps.contains(&Step::Tmpfs {
                    target: t.into(),
                    mode
                }),
                "{t}"
            );
        }
        // Merged-/usr symlinks are recreated, after every mount.
        let first_link = position(&steps, |s| matches!(s, Step::Symlink { .. }));
        assert!(steps[first_link..]
            .iter()
            .all(|s| matches!(s, Step::Symlink { .. })));
        assert!(steps.contains(&Step::Symlink {
            link: "/bin".into(),
            to: "usr/bin".into()
        }));
        // Mount points exist before their mounts; files for files.
        let at = |s: Step| position(&steps, |x| *x == s);
        assert!(
            at(Step::File("/etc/passwd".into()))
                < at(Step::Bind {
                    source: Source::Path("/etc/passwd".into()),
                    target: "/etc/passwd".into(),
                    flags: RO
                })
        );
        assert!(
            at(Step::Dir("/home/u/.local".into())) < at(Step::Dir("/home/u/.local/share".into()))
        );
        // /dev's tmpfs comes before the nodes bound into it.
        assert!(
            at(Step::Tmpfs {
                target: "/dev".into(),
                mode: 0o755
            }) < at(Step::File("/dev/null".into()))
        );
    }

    #[test]
    fn mounts_never_land_under_a_later_one() {
        // A data directory under /tmp, and the vendor inside the game.
        let steps = plan(
            dirs("/tmp/g", "/tmp/g/ac", "/tmp/x/fairplay/v"),
            &Fake::new(),
        )
        .unwrap();
        let tmp = position(&steps, |s| {
            *s == Step::Tmpfs {
                target: "/tmp".into(),
                mode: 0o1777,
            }
        });
        let mounted: Vec<usize> = steps
            .iter()
            .enumerate()
            .filter(|(_, s)| matches!(s, Step::Bind { target, .. } if target.starts_with("/tmp")))
            .map(|(i, _)| i)
            .collect();
        assert!(mounted.iter().all(|&i| i > tmp));
        // The vendor's directory is already visible inside the game's.
        let b = binds(&steps);
        assert!(!b.iter().any(|(t, _, _)| t == "/tmp/g/ac"));
        // Every Dir/File comes after any mount above it.
        for (i, s) in steps.iter().enumerate() {
            let (Step::Dir(p) | Step::File(p)) = s else {
                continue;
            };
            for (j, m) in steps.iter().enumerate() {
                let t = match m {
                    Step::Bind { target, .. } | Step::Tmpfs { target, .. } => target,
                    _ => continue,
                };
                if p != t && p.starts_with(t) && t != Path::new("/") {
                    assert!(
                        j < i,
                        "{} made before {} was mounted",
                        p.display(),
                        t.display()
                    );
                }
            }
        }
    }

    #[test]
    fn user_directories_may_not_cover_system_mounts() {
        for (game, own, data) in [
            ("/", "/opt/v", "/d/v"),
            ("/etc", "/opt/v", "/d/v"),
            ("/g", "/run", "/d/v"),
            ("/g", "/opt/v", "/tmp"),
            ("/g", "/opt/v", "/dev"),
            ("/g/../etc", "/opt/v", "/d/v"),
            ("relative", "/opt/v", "/d/v"),
        ] {
            assert!(
                plan(dirs(game, own, data), &Fake::new()).is_err(),
                "{game} {own} {data}"
            );
        }
        // Under them is fine: those land on top.
        assert!(plan(dirs("/usr/games/g", "/opt/v", "/tmp/d/v"), &Fake::new()).is_ok());
    }

    #[test]
    fn missing_host_paths_are_skipped() {
        let mut host = Fake::new();
        host.0.remove("/etc/localtime");
        host.0.remove("/dev/tty");
        host.0.insert("/lib64", Kind::Dir);
        let steps = plan(dirs("/g", "/v", "/d/v"), &host).unwrap();
        let b = binds(&steps);
        assert!(!b
            .iter()
            .any(|(t, _, _)| t == "/etc/localtime" || t == "/dev/tty"));
        assert!(b.iter().any(|(t, _, _)| t == "/lib64"));
        // No socket is an error: the anti-cheat must reach fairplayd.
        host.0.remove("/run/fairplayd.sock");
        assert!(plan(dirs("/g", "/v", "/d/v"), &host).is_err());
    }

    #[test]
    fn data_directory_and_environment() {
        let fp = "ed25519:ab12";
        assert_eq!(vendor_dir_name(fp), "ed25519-ab12");
        let home = Path::new("/home/u");
        assert_eq!(
            data_dir(&[], home, fp),
            Path::new("/home/u/.local/share/fairplay/ed25519-ab12")
        );
        let env = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            data_dir(&env(&["XDG_DATA_HOME=/x/data"]), home, fp),
            Path::new("/x/data/fairplay/ed25519-ab12")
        );
        // A relative XDG_DATA_HOME is ignored, as the spec says.
        assert_eq!(
            data_dir(&env(&["XDG_DATA_HOME=data"]), home, fp),
            Path::new("/home/u/.local/share/fairplay/ed25519-ab12")
        );
        let out = sandbox_env(
            &env(&[
                "PATH=/usr/bin",
                "DISPLAY=:0",
                "HOME=/home/u",
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
                "LANG=C.UTF-8",
            ]),
            Path::new("/d/v"),
        );
        assert_eq!(
            out,
            env(&[
                "PATH=/usr/bin",
                "LANG=C.UTF-8",
                "HOME=/d/v",
                "FAIRPLAY_DATA_DIR=/d/v",
                "TMPDIR=/tmp"
            ])
        );
    }

    #[test]
    fn bind_flags_keep_host_restrictions() {
        let base = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID;
        assert_eq!(bind_flags(DEVICE, 0), base | libc::MS_NOEXEC);
        assert_eq!(bind_flags(RO, 0), base | libc::MS_RDONLY | libc::MS_NODEV);
        // A game on a noexec host mount stays noexec.
        assert_eq!(
            bind_flags(RO, libc::ST_NOEXEC),
            base | libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOEXEC
        );
        assert_eq!(
            bind_flags(DATA, libc::ST_RDONLY),
            base | libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOEXEC
        );
    }

    #[test]
    fn c_steps_live_under_the_new_root() {
        let steps = plan(dirs("/g", "/v", "/d/v"), &Fake::new()).unwrap();
        let (c, names) = steps_to_c(&steps);
        assert_eq!(c.len(), names.len());
        for s in &c {
            let t = match s {
                CStep::Mkdir(t) | CStep::Touch(t) => t,
                CStep::Mount { target, .. } | CStep::Bind { target, .. } => target,
                CStep::Symlink { link, .. } => link,
            };
            assert!(t.to_str().unwrap().starts_with(NEW_ROOT), "{t:?}");
        }
        // The data directory comes from its detached tree, never a path.
        assert!(c.iter().any(|s| matches!(s, CStep::Bind {
            source: BindSource::Tree(12),
            target,
            ..
        } if target.to_str().unwrap() == format!("{NEW_ROOT}/d/v"))));
        assert!(
            matches!(&c[0], CStep::Mount { target, .. } if target.to_str().unwrap() == NEW_ROOT)
        );
        // /proc shows only what the sandbox may look at.
        assert!(c
            .iter()
            .any(|s| matches!(s, CStep::Mount { fstype, data, .. }
            if fstype.to_str().unwrap() == "proc" && data.as_c_str() == PROC_OPTIONS)));
    }

    #[test]
    fn seccomp_filter_shape() {
        let f = seccomp_filter();
        // Architecture check first, allow last, one EPERM per denied call.
        assert_eq!((f[0].code, f[0].k), (LD_W_ABS, OFFSET_ARCH));
        assert_eq!((f[1].code, f[1].k), (JMP_JEQ_K, AUDIT_ARCH));
        assert_eq!(f[2].k, libc::SECCOMP_RET_KILL_PROCESS);
        assert_eq!(f.last().unwrap().k, libc::SECCOMP_RET_ALLOW);
        let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        for &(name, nr) in DENIED_SYSCALLS {
            let i = f
                .iter()
                .position(|x| x.code == JMP_JEQ_K && x.k == nr as u32)
                .unwrap_or_else(|| panic!("{name} not in the filter"));
            assert_eq!((f[i].jt, f[i].jf), (0, 1));
            assert_eq!((f[i + 1].code, f[i + 1].k), (RET_K, eperm), "{name}");
        }
        assert!(!f.iter().any(|x| x.code == JMP_JEQ_K
            && (x.k == libc::SYS_process_vm_readv as u32 || x.k == libc::SYS_openat as u32)));
        // clone3 -> ENOSYS; clone with a namespace flag -> EPERM, last
        // before allow (it overwrites the system call number).
        let i = f
            .iter()
            .position(|x| x.code == JMP_JEQ_K && x.k == libc::SYS_clone3 as u32)
            .unwrap();
        let enosys = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
        assert_eq!((f[i + 1].code, f[i + 1].k), (RET_K, enosys));
        let n = f.len();
        assert_eq!(
            (f[n - 5].code, f[n - 5].k, f[n - 5].jf),
            (JMP_JEQ_K, libc::SYS_clone as u32, 3)
        );
        assert_eq!((f[n - 4].code, f[n - 4].k), (LD_W_ABS, OFFSET_ARG0_LO));
        assert_eq!((f[n - 3].code, f[n - 3].k), (JMP_JSET_K, CLONE_NEW_FLAGS));
        assert_eq!((f[n - 2].code, f[n - 2].k), (RET_K, eperm));
        assert_eq!(CLONE_NEW_FLAGS & libc::SIGCHLD as u32, 0);
    }

    /// Installs the filter in a forked child (no root needed): ptrace and
    /// process_vm_writev fail with EPERM, process_vm_readv still works.
    #[test]
    fn seccomp_filter_works() {
        let sb = Prepared {
            steps: vec![],
            names: vec![],
            new_root: CString::default(),
            _dirs: vec![],
            filter: seccomp_filter(),
            info: SandboxInfo {
                data_dir: String::new(),
                read_only: vec![],
            },
            data_dir: PathBuf::new(),
            cwd: PathBuf::new(),
        };
        // SAFETY: the child only makes system calls and exits.
        match unsafe { libc::fork() } {
            0 => unsafe {
                let mut code = 0;
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || sb.seccomp().is_err()
                {
                    libc::_exit(10);
                }
                let eperm = || *libc::__errno_location() == libc::EPERM;
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != -1 || !eperm() {
                    code |= 1;
                }
                let mut buf = [0u8; 8];
                let src = [7u8; 8];
                let local = libc::iovec {
                    iov_base: buf.as_mut_ptr().cast(),
                    iov_len: 8,
                };
                let remote = libc::iovec {
                    iov_base: src.as_ptr() as *mut _,
                    iov_len: 8,
                };
                let me = libc::getpid();
                if libc::process_vm_writev(me, &local, 1, &remote, 1, 0) != -1 || !eperm() {
                    code |= 2;
                }
                if libc::process_vm_readv(me, &local, 1, &remote, 1, 0) != 8 || buf != src {
                    code |= 4;
                }
                // unshare(0) would succeed (and do nothing) without the filter.
                if libc::unshare(0) != -1 || !eperm() {
                    code |= 8;
                }
                let clone = |flags: libc::c_int| libc::syscall(libc::SYS_clone, flags, 0, 0, 0, 0);
                if clone(libc::CLONE_NEWUSER | libc::SIGCHLD) != -1 || !eperm() {
                    code |= 16;
                }
                if libc::syscall(libc::SYS_clone3, 0, 0) != -1
                    || *libc::__errno_location() != libc::ENOSYS
                {
                    code |= 32;
                }
                // A plain clone (a fork) still works.
                match clone(libc::SIGCHLD) {
                    0 => libc::_exit(0),
                    -1 => code |= 64,
                    pid => {
                        let mut st = 0;
                        if libc::waitpid(pid as libc::pid_t, &mut st, 0) != pid as libc::pid_t
                            || !libc::WIFEXITED(st)
                        {
                            code |= 64;
                        }
                    }
                }
                libc::_exit(code);
            },
            -1 => panic!("fork failed"),
            pid => {
                let mut status = 0;
                // SAFETY: waiting for our own child.
                unsafe { libc::waitpid(pid, &mut status, 0) };
                assert!(libc::WIFEXITED(status), "status {status:#x}");
                assert_eq!(
                    libc::WEXITSTATUS(status),
                    0,
                    "1 ptrace, 2 writev, 4 readv, 8 unshare, 16 clone NEWUSER, 32 clone3, 64 fork"
                );
            }
        }
    }
}
