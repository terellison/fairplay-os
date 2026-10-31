//! Checking a launch against its game manifest (milestone 9).
//!
//! `launch_protected` starts only what a signed manifest names: a `launch`
//! executable for a new session, or with `join` an `anti_cheat` reader of
//! the session's manifest. For each launch this module
//!
//! 1. reads the manifest and `<manifest>.sig` and checks the signature
//!    against the manifest's own `signer` key (no list of trusted
//!    publishers: the vendor's server judges the signer);
//! 2. finds the requested program among the manifest's entries;
//! 3. opens it, hashes it **through that open file descriptor**, and hands
//!    the descriptor back: the child execs the descriptor (`fexecve`), so
//!    the path can't be swapped for another file between check and exec;
//! 4. for a new session, also opens and hashes the manifest's
//!    `runtime_helper` readers (they go into READER_FILES), and its `proton`
//!    and `overlays` files (they go on the session's executable-mapping
//!    allowlist). Entries that are missing or don't match are skipped and
//!    logged: a manifest may list several accepted Proton builds.
//!
//! All files are opened with the caller's file-system identity (see
//! [`as_caller`]), so a launcher can't make fairplayd read or hash a file it
//! couldn't read itself.
//!
//! Remaining window: the hashed file is the one exec'd, but someone who can
//! write to it can still rewrite it **in place** between the hash and the
//! exec, or later (a runtime helper is exec'd by the game long after
//! launch). fs-verity (the kernel checks every page against a hash it
//! fixed when the file was sealed) is the later fix.

use std::{
    fs::File,
    os::unix::fs::{FileExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use fairplay_api::{
    manifest::{self, ManifestError, Role, Verified},
    ApiError, ErrorCode, ManifestInfo,
};

use crate::state::Peer;

/// A manifest whose signature verified, as a session keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionManifest {
    pub verified: Verified,
    /// The manifest's directory: relative entry paths are relative to it.
    pub base: PathBuf,
}

impl SessionManifest {
    pub fn info(&self) -> ManifestInfo {
        let m = &self.verified.manifest;
        ManifestInfo {
            name: m.name.clone(),
            sha256: self.verified.sha256.clone(),
            signer: m.signer.clone(),
            signer_fingerprint: self.verified.signer_fingerprint.clone(),
            block_virtual_input: m.block_virtual_input,
        }
    }
}

/// A file opened once, whose contents matched the manifest's hash.
#[derive(Debug)]
pub struct CheckedFile {
    pub path: PathBuf,
    pub file: File,
}

/// What one launch may do, every file already checked.
#[derive(Debug)]
pub struct Plan {
    pub manifest: Arc<SessionManifest>,
    /// The program to exec (by its descriptor).
    pub program: CheckedFile,
    /// Files whose exec makes a process a reader of the session.
    pub readers: Vec<CheckedFile>,
    /// Files the session may map executable besides its install directory.
    pub exec: Vec<CheckedFile>,
    /// Entries that didn't check out, for the log.
    pub skipped: Vec<String>,
}

fn forbidden(m: String) -> ApiError {
    ApiError::new(ErrorCode::Forbidden, m)
}

fn bad(m: String) -> ApiError {
    ApiError::new(ErrorCode::BadRequest, m)
}

/// A new session: verify the manifest at `manifest_path` and check that
/// `program` is one of its launch executables.
pub fn plan_launch(manifest_path: &str, program: &str) -> Result<Plan, ApiError> {
    if !manifest_path.starts_with('/') {
        return Err(bad("manifest must be an absolute path".into()));
    }
    let path = Path::new(manifest_path);
    let read = |p: &Path, max: u64| -> Result<Vec<u8>, ApiError> {
        let f = open_regular(p).map_err(|e| bad(format!("{}: {e}", p.display())))?;
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if len > max {
            return Err(bad(format!("{} is larger than {max} bytes", p.display())));
        }
        let mut buf = vec![0u8; len as usize];
        f.read_exact_at(&mut buf, 0)
            .map_err(|e| bad(format!("reading {}: {e}", p.display())))?;
        Ok(buf)
    };
    let bytes = read(path, manifest::MAX_MANIFEST_BYTES)?;
    let sig = read(&manifest::sig_path(path), 1024)?;
    let verified = Verified::check(&bytes, &sig).map_err(|e| match e {
        ManifestError::Invalid(_) => bad(e.to_string()),
        ManifestError::BadSignature(_) => forbidden(e.to_string()),
    })?;
    let m = Arc::new(SessionManifest {
        verified,
        base: path.parent().unwrap_or(Path::new("/")).to_owned(),
    });
    let mf = &m.verified.manifest;
    let program = select(
        &m.base,
        program,
        mf.launch.iter().map(|e| (&e.path, &e.sha256)),
        "launch executable",
        &mf.name,
    )?;
    let mut skipped = vec![];
    let mut check_all = |entries: Vec<(&String, &String)>| -> Vec<CheckedFile> {
        entries
            .into_iter()
            .filter_map(
                |(p, sha)| match check(&manifest::resolve(&m.base, p), sha) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        skipped.push(e);
                        None
                    }
                },
            )
            .collect()
    };
    let readers = check_all(
        mf.readers(Role::RuntimeHelper)
            .map(|r| (&r.path, &r.sha256))
            .collect(),
    );
    let exec = check_all(
        mf.proton
            .iter()
            .chain(&mf.overlays)
            .map(|e| (&e.path, &e.sha256))
            .collect(),
    );
    Ok(Plan {
        manifest: m,
        program,
        readers,
        exec,
        skipped,
    })
}

/// `join`: check that `program` is one of the session manifest's
/// `anti_cheat` readers. Its file becomes a reader file of the session, so
/// its exec makes it a reader.
pub fn plan_join(m: Arc<SessionManifest>, program: &str) -> Result<Plan, ApiError> {
    let mf = &m.verified.manifest;
    let program = select(
        &m.base,
        program,
        mf.readers(Role::AntiCheat).map(|r| (&r.path, &r.sha256)),
        "anti_cheat reader",
        &mf.name,
    )?;
    let reader = CheckedFile {
        path: program.path.clone(),
        file: program
            .file
            .try_clone()
            .map_err(|e| ApiError::new(ErrorCode::Internal, format!("dup: {e}")))?,
    };
    Ok(Plan {
        manifest: m,
        program,
        readers: vec![reader],
        exec: vec![],
        skipped: vec![],
    })
}

/// Opens `program` if it is one of `entries` and its contents match that
/// entry's hash. Paths are compared after resolving symlinks, so
/// `/usr/bin/python3` names the same entry as `/usr/bin/python3.12`.
fn select<'a>(
    base: &Path,
    program: &str,
    entries: impl Iterator<Item = (&'a String, &'a String)>,
    what: &str,
    name: &str,
) -> Result<CheckedFile, ApiError> {
    if !program.starts_with('/') {
        return Err(bad("program must be an absolute path".into()));
    }
    let real = std::fs::canonicalize(program).map_err(|e| bad(format!("{program}: {e}")))?;
    let hashes: Vec<&String> = entries
        .filter(|(p, _)| {
            std::fs::canonicalize(manifest::resolve(base, p))
                .ok()
                .as_ref()
                == Some(&real)
        })
        .map(|(_, sha)| sha)
        .collect();
    if hashes.is_empty() {
        return Err(forbidden(format!(
            "{program} is not a {what} in manifest {name:?}"
        )));
    }
    let file = open_regular(&real).map_err(|e| bad(format!("{}: {e}", real.display())))?;
    let mut head = [0u8; 2];
    let n = file.read_at(&mut head, 0).unwrap_or(0);
    if &head[..n] == b"#!" {
        // Its interpreter would read it again by path, after the check.
        return Err(bad(format!(
            "{program} is a script; a manifest must name a binary"
        )));
    }
    let got = hash(&file).map_err(|e| bad(format!("hashing {}: {e}", real.display())))?;
    if !hashes.iter().any(|h| h.eq_ignore_ascii_case(&got)) {
        return Err(forbidden(format!(
            "{program} does not match the sha256 in manifest {name:?}"
        )));
    }
    Ok(CheckedFile { path: real, file })
}

/// Opens and hashes one entry's file. `Err` is a line for the log.
fn check(path: &Path, sha: &str) -> Result<CheckedFile, String> {
    let file = open_regular(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let got = hash(&file).map_err(|e| format!("{}: {e}", path.display()))?;
    if !got.eq_ignore_ascii_case(sha) {
        return Err(format!("{}: sha256 mismatch", path.display()));
    }
    Ok(CheckedFile {
        path: path.to_owned(),
        file,
    })
}

fn hash(f: &File) -> std::io::Result<String> {
    // A fresh descriptor reads from offset 0.
    Ok(manifest::hex(&manifest::sha256_of(f)?))
}

/// Opens a regular file read-only, without blocking on a FIFO.
fn open_regular(path: &Path) -> std::io::Result<File> {
    let f = File::options()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok(f)
}

/// Runs `f` on a thread of its own whose file-system identity is the
/// caller's (`setfsuid`, `setfsgid`, `setgroups`, which on Linux are
/// per-thread system calls), so every open in `f` is checked against the
/// caller's permissions, not root's. The identity dies with the thread.
/// Root callers keep root's.
pub fn as_caller<T: Send + 'static>(
    peer: &Peer,
    f: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    let (uid, gid, groups) = (peer.uid, peer.gid, peer.groups.clone());
    std::thread::Builder::new()
        .name("verify".into())
        .spawn(move || {
            if uid != 0 {
                become_for_files(uid, gid, &groups)?;
            }
            f()
        })
        .map_err(|e| ApiError::new(ErrorCode::Internal, format!("spawning: {e}")))?
        .join()
        .unwrap_or_else(|_| Err(ApiError::new(ErrorCode::Internal, "verifier panicked")))
}

fn become_for_files(uid: u32, gid: u32, groups: &[u32]) -> Result<(), ApiError> {
    let fail = |what: &str| {
        ApiError::new(
            ErrorCode::Internal,
            format!("{what}: {}", std::io::Error::last_os_error()),
        )
    };
    // Raw system calls, not libc's wrappers: glibc applies setgroups to
    // every thread of the process.
    // SAFETY: plain system calls on this thread's credentials.
    unsafe {
        if libc::syscall(libc::SYS_setgroups, groups.len(), groups.as_ptr()) != 0 {
            return Err(fail("setgroups"));
        }
        libc::syscall(libc::SYS_setfsgid, gid);
        libc::syscall(libc::SYS_setfsuid, uid);
        // They report the previous id, never an error: ask again with an
        // invalid id, which changes nothing and returns the current one.
        if libc::syscall(libc::SYS_setfsgid, u32::MAX) as u32 != gid
            || libc::syscall(libc::SYS_setfsuid, u32::MAX) as u32 != uid
        {
            return Err(fail("setfsuid"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use ed25519_dalek::SigningKey;
    use fairplay_api::manifest::{encode_public, sign};

    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("fairplayd-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Self(d)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sha(bytes: &[u8]) -> String {
        manifest::hex(&manifest::sha256_of(bytes).unwrap())
    }

    /// A game dir with `game` (and `helper`, `ac`, `proton.so`) and a
    /// signed manifest naming them. Returns the manifest's path.
    fn setup(d: &Path, key: &SigningKey, edit: impl FnOnce(&mut serde_json::Value)) -> String {
        for (f, body) in [
            ("game", &b"\x7fELF game"[..]),
            ("helper", b"\x7fELF helper"),
            ("ac", b"\x7fELF ac"),
            ("proton.so", b"\x7fELF proton"),
            ("script", b"#!/bin/sh\necho hi\n"),
        ] {
            std::fs::write(d.join(f), body).unwrap();
        }
        let mut m = serde_json::json!({
            "name": "Test",
            "signer": encode_public(&key.verifying_key()),
            "launch": [
                {"path": "game", "sha256": sha(b"\x7fELF game")},
                {"path": "script", "sha256": sha(b"#!/bin/sh\necho hi\n")},
            ],
            "readers": [
                {"role": "anti_cheat", "path": d.join("ac"), "sha256": sha(b"\x7fELF ac")},
                {"role": "runtime_helper", "path": "helper", "sha256": sha(b"\x7fELF helper")},
                {"role": "runtime_helper", "path": "missing", "sha256": sha(b"")},
            ],
            "proton": [{"path": "proton.so", "sha256": sha(b"\x7fELF proton")}],
        });
        edit(&mut m);
        let bytes = serde_json::to_vec(&m).unwrap();
        let p = d.join("game.json");
        std::fs::write(&p, &bytes).unwrap();
        std::fs::write(manifest::sig_path(&p), sign(key, &bytes)).unwrap();
        p.to_str().unwrap().to_owned()
    }

    fn path(d: &Path, f: &str) -> String {
        d.join(f).to_str().unwrap().to_owned()
    }

    #[test]
    fn launch_checks_everything_it_names() {
        let t = TempDir::new("verify-ok");
        let key = SigningKey::from_bytes(&[1; 32]);
        let m = setup(&t.0, &key, |_| {});
        let plan = plan_launch(&m, &path(&t.0, "game")).unwrap();
        assert_eq!(
            plan.program.path,
            std::fs::canonicalize(t.0.join("game")).unwrap()
        );
        // The runtime helper is a reader file; the anti-cheat isn't (it
        // becomes one when it joins).
        let readers: Vec<_> = plan.readers.iter().map(|c| c.path.clone()).collect();
        assert_eq!(readers, vec![t.0.join("helper")]);
        assert_eq!(plan.exec.len(), 1);
        assert_eq!(plan.skipped.len(), 1, "{:?}", plan.skipped);
        assert!(plan.skipped[0].contains("missing"));
        let info = plan.manifest.info();
        assert_eq!(info.name, "Test");
        assert_eq!(
            info.signer_fingerprint,
            manifest::fingerprint(&key.verifying_key())
        );
        assert_eq!(info.sha256, sha(&std::fs::read(&m).unwrap()));

        // join: only the anti_cheat reader.
        let j = plan_join(plan.manifest.clone(), &path(&t.0, "ac")).unwrap();
        assert_eq!(j.readers.len(), 1);
        for other in ["game", "helper"] {
            let e = plan_join(plan.manifest.clone(), &path(&t.0, other)).unwrap_err();
            assert_eq!(e.code, ErrorCode::Forbidden, "{other}");
        }
    }

    #[test]
    fn launch_refuses_what_the_manifest_does_not_name() {
        let t = TempDir::new("verify-unnamed");
        let key = SigningKey::from_bytes(&[1; 32]);
        let m = setup(&t.0, &key, |_| {});
        std::fs::copy(t.0.join("game"), t.0.join("copy")).unwrap();
        // Same bytes, but not the named path; and a named reader isn't a
        // launch executable.
        for p in ["copy", "ac", "helper"] {
            let e = plan_launch(&m, &path(&t.0, p)).unwrap_err();
            assert_eq!(e.code, ErrorCode::Forbidden, "{p}: {e}");
        }
        // Named, but a script.
        let e = plan_launch(&m, &path(&t.0, "script")).unwrap_err();
        assert_eq!(e.code, ErrorCode::BadRequest, "{e}");
        // A symlink to a named file names it.
        std::os::unix::fs::symlink(t.0.join("game"), t.0.join("link")).unwrap();
        assert!(plan_launch(&m, &path(&t.0, "link")).is_ok());
    }

    #[test]
    fn hash_mismatch_is_refused() {
        let t = TempDir::new("verify-hash");
        let key = SigningKey::from_bytes(&[1; 32]);
        let m = setup(&t.0, &key, |_| {});
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(t.0.join("game"))
            .unwrap();
        f.write_all(b"cheat").unwrap();
        let e = plan_launch(&m, &path(&t.0, "game")).unwrap_err();
        assert_eq!(e.code, ErrorCode::Forbidden);
        assert!(e.message.contains("sha256"), "{e}");
        // A changed runtime helper is skipped, not trusted.
        std::fs::write(t.0.join("game"), b"\x7fELF game").unwrap();
        std::fs::write(t.0.join("helper"), b"\x7fELF evil").unwrap();
        let plan = plan_launch(&m, &path(&t.0, "game")).unwrap();
        assert!(plan.readers.is_empty());
        assert!(plan.skipped.iter().any(|s| s.contains("helper")));
    }

    #[test]
    fn bad_signatures_are_refused() {
        let t = TempDir::new("verify-sig");
        let key = SigningKey::from_bytes(&[1; 32]);
        let m = setup(&t.0, &key, |_| {});
        let game = path(&t.0, "game");
        // Tampered after signing.
        let text = std::fs::read_to_string(&m).unwrap().replace("Test", "Tset");
        std::fs::write(&m, text).unwrap();
        assert_eq!(
            plan_launch(&m, &game).unwrap_err().code,
            ErrorCode::Forbidden
        );
        // Signed by a key other than the one it names.
        let other = SigningKey::from_bytes(&[2; 32]);
        let m = setup(&t.0, &key, |_| {});
        let bytes = std::fs::read(&m).unwrap();
        std::fs::write(manifest::sig_path(Path::new(&m)), sign(&other, &bytes)).unwrap();
        assert_eq!(
            plan_launch(&m, &game).unwrap_err().code,
            ErrorCode::Forbidden
        );
        // No signature at all.
        std::fs::remove_file(manifest::sig_path(Path::new(&m))).unwrap();
        assert_eq!(
            plan_launch(&m, &game).unwrap_err().code,
            ErrorCode::BadRequest
        );
        // Relative manifest path.
        assert_eq!(
            plan_launch("game.json", &game).unwrap_err().code,
            ErrorCode::BadRequest
        );
    }

    #[test]
    fn as_caller_runs_on_its_own_thread() {
        let root = Peer {
            pid: 1,
            uid: 0,
            gid: 0,
            groups: vec![],
        };
        let me = std::thread::current().id();
        let other = as_caller(&root, move || Ok(std::thread::current().id() != me)).unwrap();
        assert!(other);
    }
}
