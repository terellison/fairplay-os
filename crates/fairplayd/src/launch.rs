//! Starting a program so that it is protected before it runs a single
//! instruction of its own.
//!
//! 1. [`prepare`] validates the request and builds every C string the child
//!    needs, because after `fork` in a threaded process the child may only
//!    make async-signal-safe system calls (no allocation, no locks).
//! 2. [`fork_paused`] forks. The child blocks reading a pipe.
//! 3. The caller puts the child's PID into PROTECTED ([`Paused::pid`]).
//! 4. [`Paused::release`] writes one byte; the child drops to the caller's
//!    identity (groups, then gid, then uid), enters the working directory,
//!    and execs the program through the file descriptor fairplayd hashed it
//!    from (`fexecve`, milestone 9), never by path. If the caller drops a `Paused` without releasing it,
//!    the child is killed without ever running the program.
//! 5. [`Released::wait_exec`] reports whether `execve` worked: a
//!    close-on-exec pipe reads EOF on success, or the failing step and errno.

use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

use fairplay_api::{ApiError, ErrorCode};

use crate::state::Identity;

/// Upper bound on argv and env entries each.
const MAX_ARGS: usize = 4096;

/// Everything the child needs, as C strings.
#[derive(Debug)]
pub struct Prepared {
    argv: Vec<CString>,
    envp: Vec<CString>,
    cwd: CString,
    /// Environment variables that were dropped (names only), for the log.
    pub dropped_env: Vec<String>,
}

/// Validates a `launch_protected` request.
pub fn prepare(argv: &[String], env: &[String], cwd: &str) -> Result<Prepared, ApiError> {
    let bad = |m: String| ApiError::new(ErrorCode::BadRequest, m);
    if !cwd.starts_with('/') {
        return Err(bad("cwd must be an absolute path".into()));
    }
    if argv.is_empty() {
        return Err(bad("argv must include argv[0]".into()));
    }
    if argv.len() > MAX_ARGS || env.len() > MAX_ARGS {
        return Err(bad(format!("at most {MAX_ARGS} argv and env entries")));
    }
    let c = |s: &str| CString::new(s).map_err(|_| bad(format!("NUL byte in {s:?}")));
    let mut envp = vec![];
    let mut dropped_env = vec![];
    for kv in env {
        let Some((key, _)) = kv.split_once('=') else {
            return Err(bad(format!("env entry {kv:?} is not KEY=VALUE")));
        };
        if injects_code(key) {
            dropped_env.push(key.to_owned());
            continue;
        }
        envp.push(c(kv)?);
    }
    Ok(Prepared {
        argv: argv.iter().map(|a| c(a)).collect::<Result<_, _>>()?,
        envp,
        cwd: c(cwd)?,
        dropped_env,
    })
}

/// Wine's DLL variables: `WINEDLLOVERRIDES` swaps a game's DLL for a
/// "native" one from its directory, and `WINEDLLPATH` adds directories to
/// load DLLs from. Either puts a cheat's code inside a Proton game.
const WINE_DLL_VARS: &[&str] = &["WINEDLLOVERRIDES", "WINEDLLPATH"];

/// Environment variables that load arbitrary code into the process we are
/// about to protect, dropped for the design doc's "clean launch
/// environment": the dynamic loader's (LD_PRELOAD, LD_LIBRARY_PATH,
/// LD_AUDIT, ...) and Wine's DLL variables. Children inherit the clean
/// environment.
fn injects_code(key: &str) -> bool {
    key.starts_with("LD_") || WINE_DLL_VARS.contains(&key)
}

/// A forked child waiting for [`Paused::release`].
pub struct Paused {
    pid: u32,
    /// `Some` until released; dropping it unreleased kills the child.
    release: Option<File>,
    exec_status: Option<File>,
}

pub struct Released {
    pid: u32,
    exec_status: File,
}

/// Steps the child reports failure from.
const STAGES: &[&str] = &[
    "setsid",
    "dup2",
    "setgroups",
    "setgid",
    "setuid",
    "no_new_privs",
    "chdir",
    "execve",
];

/// Forks a child that will exec `program` (an open file, checked against
/// the manifest) with `prep`'s argv and environment, running as `id`, with
/// `stdio` (or /dev/null) as fds 0-2. The child does nothing until released.
pub fn fork_paused(
    prep: &Prepared,
    program: &File,
    id: &Identity,
    stdio: Option<[OwnedFd; 3]>,
) -> Result<Paused, ApiError> {
    let internal =
        |what: &str, e: std::io::Error| ApiError::new(ErrorCode::Internal, format!("{what}: {e}"));
    let devnull;
    let stdio_fds: [RawFd; 3] = match &stdio {
        Some(fds) => [fds[0].as_raw_fd(), fds[1].as_raw_fd(), fds[2].as_raw_fd()],
        None => {
            devnull = File::options()
                .read(true)
                .write(true)
                .open("/dev/null")
                .map_err(|e| internal("/dev/null", e))?;
            [devnull.as_raw_fd(); 3]
        }
    };
    let (release_r, release_w) = pipe().map_err(|e| internal("pipe", e))?;
    let (status_r, status_w) = pipe().map_err(|e| internal("pipe", e))?;

    let mut argv: Vec<*const libc::c_char> = prep.argv.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> = prep.envp.iter().map(|a| a.as_ptr()).collect();
    envp.push(std::ptr::null());
    let groups: Vec<libc::gid_t> = id.groups.clone();

    let child = ChildArgs {
        release: release_r.as_raw_fd(),
        status: status_w.as_raw_fd(),
        stdio: stdio_fds,
        groups: &groups,
        uid: id.uid,
        gid: id.gid,
        cwd: &prep.cwd,
        program: program.as_raw_fd(),
        argv: &argv,
        envp: &envp,
    };
    // SAFETY: the child runs only child_main, which makes async-signal-safe
    // system calls on data prepared above and never returns.
    match unsafe { libc::fork() } {
        -1 => Err(internal("fork", std::io::Error::last_os_error())),
        0 => unsafe { child_main(&child) },
        pid => Ok(Paused {
            pid: pid as u32,
            release: Some(File::from(release_w)),
            exec_status: Some(File::from(status_r)),
        }),
    }
    // release_r, status_w, the stdio fds and /dev/null close here in the parent.
}

impl Paused {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Lets the child continue to `execve`. Call only once its PID is in
    /// PROTECTED.
    pub fn release(mut self) -> Result<Released, ApiError> {
        let mut w = self.release.take().expect("released once");
        if let Err(e) = w.write_all(&[1]) {
            // The child is already gone; the reaper collects it.
            return Err(ApiError::new(
                ErrorCode::LaunchFailed,
                format!("child vanished: {e}"),
            ));
        }
        Ok(Released {
            pid: self.pid,
            exec_status: self.exec_status.take().expect("taken once"),
        })
    }
}

impl Drop for Paused {
    /// Never released: make sure the program never runs. Closing the pipe
    /// alone would do (the child exits on EOF); the kill is belt and braces.
    /// The reaper collects it.
    fn drop(&mut self) {
        if self.release.is_none() {
            return;
        }
        // SAFETY: kill has no memory-safety preconditions; pid is our child.
        unsafe { libc::kill(self.pid as libc::pid_t, libc::SIGKILL) };
    }
}

impl Released {
    /// Waits until the child has exec'd (`Ok(pid)`) or failed trying.
    pub fn wait_exec(mut self) -> Result<u32, ApiError> {
        let mut buf = [0u8; 8];
        let mut got = 0;
        while got < buf.len() {
            match self.exec_status.read(&mut buf[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    return Err(ApiError::new(
                        ErrorCode::Internal,
                        format!("exec status: {e}"),
                    ))
                }
            }
        }
        if got == 0 {
            return Ok(self.pid);
        }
        let stage = u32::from_ne_bytes(buf[..4].try_into().unwrap()) as usize;
        let errno = i32::from_ne_bytes(buf[4..].try_into().unwrap());
        Err(ApiError::new(
            ErrorCode::LaunchFailed,
            format!(
                "{}: {}",
                STAGES.get(stage).unwrap_or(&"?"),
                std::io::Error::from_raw_os_error(errno)
            ),
        ))
    }
}

fn pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: fds has room for two descriptors.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: pipe2 just returned these and nothing else owns them.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

struct ChildArgs<'a> {
    release: RawFd,
    status: RawFd,
    stdio: [RawFd; 3],
    groups: &'a [libc::gid_t],
    uid: u32,
    gid: u32,
    cwd: &'a CString,
    /// Close-on-exec, like every descriptor the daemon holds: fine for a
    /// binary, which the kernel has open by then (scripts are refused).
    program: RawFd,
    argv: &'a [*const libc::c_char],
    envp: &'a [*const libc::c_char],
}

/// Runs in the forked child. Async-signal-safe calls only.
unsafe fn child_main(a: &ChildArgs) -> ! {
    unsafe {
        // Undo what the daemon set up for itself: signal mask, and Rust's
        // SIGPIPE=ignore (ignored signals survive exec).
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);

        // Wait until the parent has registered our PID. EOF means it gave up.
        let mut b = 0u8;
        loop {
            let n = libc::read(a.release, (&mut b as *mut u8).cast(), 1);
            if n == 1 {
                break;
            }
            if n < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            libc::_exit(126);
        }

        // Our own session: not in the daemon's terminal's process group.
        if libc::setsid() < 0 {
            fail(a, 0);
        }
        for (i, &fd) in a.stdio.iter().enumerate() {
            if libc::dup2(fd, i as libc::c_int) < 0 {
                fail(a, 1);
            }
        }
        // Order matters: groups and gid need privilege, so uid goes last.
        if libc::setgroups(a.groups.len(), a.groups.as_ptr()) != 0 {
            fail(a, 2);
        }
        if libc::setgid(a.gid) != 0 {
            fail(a, 3);
        }
        if libc::setuid(a.uid) != 0 {
            fail(a, 4);
        }
        // No setuid/file-capability elevation from here on: a protected
        // process (which even root can't inspect) shouldn't become privileged.
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            fail(a, 5);
        }
        // After setuid, so the kernel checks the directory as the user.
        if libc::chdir(a.cwd.as_ptr()) != 0 {
            fail(a, 6);
        }
        // Anything the daemon has open that isn't already close-on-exec.
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        );
        // The very file that was hashed: a path could point elsewhere by now.
        libc::fexecve(a.program, a.argv.as_ptr(), a.envp.as_ptr());
        fail(a, 7);
    }
}

unsafe fn fail(a: &ChildArgs, stage: u32) -> ! {
    unsafe {
        let errno = *libc::__errno_location();
        let mut msg = [0u8; 8];
        msg[..4].copy_from_slice(&stage.to_ne_bytes());
        msg[4..].copy_from_slice(&errno.to_ne_bytes());
        libc::write(a.status, msg.as_ptr().cast(), msg.len());
        libc::_exit(127);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn prepare_validates() {
        let ok = prepare(&s(&["game"]), &s(&["HOME=/h"]), "/").unwrap();
        assert_eq!(ok.argv.len(), 1);
        for (argv, env, cwd) in [
            (vec![], vec![], "/"),
            (s(&["game"]), vec![], "relative"),
            (s(&["ga\0me"]), vec![], "/"),
            (s(&["game"]), s(&["NOEQUALS"]), "/"),
        ] {
            let e = prepare(&argv, &env, cwd).unwrap_err();
            assert_eq!(e.code, ErrorCode::BadRequest, "{argv:?} {env:?} {cwd}");
        }
    }

    #[test]
    fn prepare_drops_loader_variables() {
        let p = prepare(
            &s(&["game"]),
            &s(&[
                "LD_PRELOAD=/tmp/cheat.so",
                "HOME=/h",
                "LD_LIBRARY_PATH=/x",
                "OLD_X=1",
            ]),
            "/",
        )
        .unwrap();
        let env: Vec<_> = p.envp.iter().map(|c| c.to_str().unwrap()).collect();
        assert_eq!(env, vec!["HOME=/h", "OLD_X=1"]);
        assert_eq!(p.dropped_env, vec!["LD_PRELOAD", "LD_LIBRARY_PATH"]);
    }

    #[test]
    fn prepare_drops_wine_dll_variables() {
        let p = prepare(
            &s(&["game"]),
            &s(&[
                "WINEDLLOVERRIDES=dxgi=n,b",
                "WINEPREFIX=/h/pfx",
                "WINEDLLPATH=/tmp/cheat",
                "LD_PRELOAD=/tmp/cheat.so",
                // Exact names only: these are not Wine's DLL variables.
                "WINEDLLOVERRIDES_X=1",
                "MY_WINEDLLPATH=1",
            ]),
            "/",
        )
        .unwrap();
        let env: Vec<_> = p.envp.iter().map(|c| c.to_str().unwrap()).collect();
        assert_eq!(
            env,
            vec![
                "WINEPREFIX=/h/pfx",
                "WINEDLLOVERRIDES_X=1",
                "MY_WINEDLLPATH=1"
            ]
        );
        assert_eq!(
            p.dropped_env,
            vec!["WINEDLLOVERRIDES", "WINEDLLPATH", "LD_PRELOAD"]
        );
    }

    #[test]
    fn code_injecting_variables() {
        for k in ["LD_PRELOAD", "LD_AUDIT", "WINEDLLOVERRIDES", "WINEDLLPATH"] {
            assert!(injects_code(k), "{k}");
        }
        for k in ["HOME", "WINEPREFIX", "winedlloverrides", "OLD_X", "WINEDLL"] {
            assert!(!injects_code(k), "{k}");
        }
    }

    fn me() -> Identity {
        // SAFETY: no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Identity {
            uid,
            gid,
            groups: nix::unistd::getgroups()
                .unwrap()
                .into_iter()
                .map(|g| g.as_raw())
                .collect(),
        }
    }

    fn reap(pid: u32) -> nix::sys::wait::WaitStatus {
        nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid as i32), None).unwrap()
    }

    #[test]
    fn unreleased_child_never_runs() {
        let marker =
            std::env::temp_dir().join(format!("fairplayd-unreleased-{}", std::process::id()));
        let prep = prepare(&s(&["touch", marker.to_str().unwrap()]), &[], "/").unwrap();
        let touch = File::open("/usr/bin/touch").unwrap();
        let paused = fork_paused(&prep, &touch, &me(), None).unwrap();
        let pid = paused.pid();
        drop(paused);
        assert!(!matches!(
            reap(pid),
            nix::sys::wait::WaitStatus::Exited(_, 0)
        ));
        assert!(!marker.exists(), "the program must not have run");
    }

    /// As root this launches for real; as a normal user (CI) setgroups is
    /// refused, which exercises the error pipe.
    #[test]
    fn released_child_execs_or_reports_why_not() {
        let prep = prepare(&s(&["true"]), &[], "/").unwrap();
        let program = File::open("/bin/true").unwrap();
        let paused = fork_paused(&prep, &program, &me(), None).unwrap();
        let pid = paused.pid();
        let result = paused.release().unwrap().wait_exec();
        let status = reap(pid);
        // SAFETY: no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(result.unwrap(), pid);
            assert_eq!(
                status,
                nix::sys::wait::WaitStatus::Exited(nix::unistd::Pid::from_raw(pid as i32), 0)
            );
        } else {
            let e = result.unwrap_err();
            assert_eq!(e.code, ErrorCode::LaunchFailed);
            assert!(e.message.starts_with("setgroups:"), "{}", e.message);
        }
    }

    #[test]
    fn exec_failure_is_reported() {
        // SAFETY: no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return; // can't get past setgroups as a normal user
        }
        let prep = prepare(&s(&["game"]), &[], "/").unwrap();
        // Not executable.
        let program = File::open("/etc/hostname").unwrap();
        let paused = fork_paused(&prep, &program, &me(), None).unwrap();
        let pid = paused.pid();
        let e = paused.release().unwrap().wait_exec().unwrap_err();
        reap(pid);
        assert!(e.message.starts_with("execve:"), "{}", e.message);
    }
}
