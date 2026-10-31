//! cheatsim: the attacker for milestone 3.
//!
//! Terminal 1:  cheatsim game            # prints its pid and the secret's address
//!              cheatsim game --depth 2  # same, from a grandchild (milestone 5)
//! Terminal 2:  sudo fairplayd --obj ... --protect <pid>
//! Terminal 3:  sudo cheatsim attack --pid <pid> --addr <addr>
//!
//! Without fairplayd every attack reads the secret. With it, every attack must
//! fail and fairplayd must print one DENIED line per attempt. Run the attacker
//! as root on purpose: kernel ptrace rules let root through, so a denial proves
//! the LSM did it.
//!
//! Milestone 8: `cheatsim game --dlopen <lib>` (or `--dlopen-stdin`) has the
//! game load a library after startup, as a game tricked into loading a
//! dropped cheat would, and prints LOADED or BLOCKED.
//!
//! Milestone 6: `cheatsim self-attack --pid <fairplayd>` tries, as root, to
//! get at fairplayd itself the ways `kill` and `bpftool` don't cover: read
//! its memory or steal its file descriptors, load a BPF program of its own,
//! and detach programs. Each attempt prints BLOCKED (EPERM or EACCES) or
//! WORKED.

use std::{
    fs::File,
    io::{IoSliceMut, Read, Seek, SeekFrom},
    process::ExitCode,
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nix::{
    errno::Errno,
    sys::{
        prctl, ptrace,
        signal::Signal,
        uio::{process_vm_readv, RemoteIoVec},
        wait::{waitpid, WaitStatus},
    },
    unistd::{fork, getpid, getppid, ForkResult, Pid},
};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// A stand-in game holding a secret value in memory.
    Game {
        /// Fork this many levels first; the deepest descendant holds the
        /// secret and prints its pid and address (milestone 5: a Proton game
        /// is a chain of processes). Every level dies with its parent.
        #[arg(long, default_value_t = 0)]
        depth: u32,
        /// After startup, dlopen() this library (repeatable) and print
        /// LOADED or BLOCKED: a game being tricked into loading a cheat, or
        /// loading an overlay (milestone 8).
        #[arg(long)]
        dlopen: Vec<String>,
        /// Also read library paths from stdin, one per line, and dlopen each
        /// as it arrives (so a test can drop or replace files first). A line
        /// `mprotect <path>` instead maps the file read-only and then asks
        /// for PROT_EXEC with mprotect(), printing MPROTECT-OK or
        /// MPROTECT-BLOCKED; a line `exec <path> [args...]` forks a child
        /// that execs the program, printing EXEC-OK if it exited 0, else
        /// EXEC-BLOCKED and how it ended; `spawn <path> [args...]` does the
        /// same without waiting and prints SPAWNED <pid> (milestone 9: the
        /// game starting a helper, or a second process of its own).
        #[arg(long)]
        dlopen_stdin: bool,
    },
    /// Try every read path against the target.
    Attack {
        #[arg(long)]
        pid: i32,
        /// Address of the secret, as printed by `cheatsim game` (hex).
        #[arg(long, value_parser = parse_hex)]
        addr: u64,
    },
    /// Try to get around a self-protecting fairplayd (milestone 6).
    SelfAttack {
        /// fairplayd's pid.
        #[arg(long)]
        pid: i32,
        /// Also try to open this BPF program of fairplayd's by id.
        #[arg(long)]
        prog_id: Option<u32>,
    },
}

const SECRET: u64 = 0x5EC2_E713_37C0_DE11;

type Attempt = fn(Pid, u64) -> Result<u64>;

fn parse_hex(s: &str) -> Result<u64, String> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    match Args::parse().cmd {
        Cmd::Game {
            depth,
            dlopen,
            dlopen_stdin,
        } => game(depth, &dlopen, dlopen_stdin),
        Cmd::Attack { pid, addr } => attack(Pid::from_raw(pid), addr),
        Cmd::SelfAttack { pid, prog_id } => self_attack(Pid::from_raw(pid), prog_id),
    }
}

fn game(depth: u32, dlopen: &[String], dlopen_stdin: bool) -> ExitCode {
    for level in 1..=depth {
        let parent = getpid();
        // SAFETY: single-threaded so far; the child just carries on here.
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                // Die with the parent, so killing the game stops the chain.
                if let Err(e) = prctl::set_pdeathsig(Signal::SIGTERM) {
                    eprintln!("cheatsim: PR_SET_PDEATHSIG: {e}");
                    return ExitCode::FAILURE;
                }
                // The parent may have died before the line above.
                if getppid() != parent {
                    return ExitCode::FAILURE;
                }
            }
            Ok(ForkResult::Parent { child }) => {
                eprintln!(
                    "cheatsim: level {} (pid {}) started level {level} (pid {child})",
                    level - 1,
                    std::process::id()
                );
                // Wait for it, then leave with its status.
                return match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, 0)) => ExitCode::SUCCESS,
                    _ => ExitCode::FAILURE,
                };
            }
            Err(e) => {
                eprintln!("cheatsim: fork: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    let secret = Box::new(SECRET);
    println!(
        "pid={} addr={:#x}",
        std::process::id(),
        &*secret as *const u64 as usize
    );
    for path in dlopen {
        load(path);
    }
    if dlopen_stdin {
        for line in std::io::stdin().lines() {
            let Ok(line) = line else { break };
            if let Some(path) = line.strip_prefix("mprotect ") {
                make_executable(path);
            } else if let Some(cmd) = line.strip_prefix("exec ") {
                run(cmd, true);
            } else if let Some(cmd) = line.strip_prefix("spawn ") {
                run(cmd, false);
            } else if !line.is_empty() {
                load(&line);
            }
        }
    }
    loop {
        // Keep the value live so the optimizer can't drop it.
        std::hint::black_box(&secret);
        thread::sleep(Duration::from_secs(1));
    }
}

/// dlopen()s a library the way a game loads a plugin, then prints one line:
/// `LOADED <path>` (and the result of its `cheatsim_marker()` if it has
/// one) or `BLOCKED <path>: <loader error>`. The library is never closed.
fn load(path: &str) {
    let Ok(c) = std::ffi::CString::new(path) else {
        println!("BLOCKED {path}: NUL in path");
        return;
    };
    // SAFETY: dlopen runs the library's constructors, which is the point:
    // this is the test's stand-in for injected code.
    let handle = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        // SAFETY: dlerror returns a thread-local string or NULL.
        let err = unsafe { libc::dlerror() };
        let msg = if err.is_null() {
            "unknown error".into()
        } else {
            // SAFETY: non-null dlerror results are NUL-terminated.
            unsafe { std::ffi::CStr::from_ptr(err) }.to_string_lossy()
        };
        println!("BLOCKED {path}: {msg}");
        return;
    }
    // SAFETY: handle is live; the symbol, if present, is `int (void)`.
    let sym = unsafe { libc::dlsym(handle, c"cheatsim_marker".as_ptr()) };
    if sym.is_null() {
        println!("LOADED {path}");
    } else {
        let f: extern "C" fn() -> libc::c_int = unsafe { std::mem::transmute(sym) };
        println!("LOADED {path} marker={}", f());
    }
}

/// Forks a child that execs `cmd` (a path, then arguments, split on
/// whitespace) and, if `wait`, reports how it ended: a game starting a
/// helper program, or being tricked into starting a dropped one.
fn run(cmd: &str, wait: bool) {
    let Ok(words) = cmd
        .split_whitespace()
        .map(std::ffi::CString::new)
        .collect::<Result<Vec<_>, _>>()
    else {
        return println!("EXEC-BLOCKED {cmd}: NUL in command");
    };
    let Some(c) = words.first() else {
        return println!("EXEC-BLOCKED: empty command");
    };
    let path = c.to_string_lossy().into_owned();
    let mut argv: Vec<*const libc::c_char> = words.iter().map(|w| w.as_ptr()).collect();
    argv.push(std::ptr::null());
    // Lines printed by the child must not sit in a copy of our buffer.
    use std::io::Write;
    let _ = std::io::stdout().flush();
    // SAFETY: single-threaded; the child only calls execv and _exit.
    match unsafe { fork() } {
        Ok(ForkResult::Child) => unsafe {
            libc::execv(c.as_ptr(), argv.as_ptr());
            // Exit code 100 + errno: execve itself returned an error.
            libc::_exit(100 + *libc::__errno_location());
        },
        Ok(ForkResult::Parent { child }) if !wait => println!("SPAWNED {child} {path}"),
        Ok(ForkResult::Parent { child }) => match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, 0)) => println!("EXEC-OK {path}"),
            Ok(WaitStatus::Exited(_, code)) if code > 100 => println!(
                "EXEC-BLOCKED {path}: execve failed: {}",
                std::io::Error::from_raw_os_error(code - 100)
            ),
            Ok(WaitStatus::Exited(_, code)) => println!("EXEC-BLOCKED {path}: exited {code}"),
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                println!("EXEC-BLOCKED {path}: killed by {sig:?}")
            }
            other => println!("EXEC-BLOCKED {path}: {other:?}"),
        },
        Err(e) => println!("EXEC-BLOCKED {path}: fork: {e}"),
    }
}

/// Maps the first page of `path` read-only, then mprotect()s it to
/// read+exec: the other way to get file-backed code into a process.
fn make_executable(path: &str) {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return println!("MPROTECT-BLOCKED {path}: open: {e}"),
    };
    use std::os::fd::AsRawFd;
    // SAFETY: a fresh private read-only mapping of one page; unmapped below.
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        let e = std::io::Error::last_os_error();
        return println!("MPROTECT-BLOCKED {path}: mmap: {e}");
    }
    // SAFETY: addr is the page we just mapped.
    let rc = unsafe { libc::mprotect(addr, 4096, libc::PROT_READ | libc::PROT_EXEC) };
    let e = std::io::Error::last_os_error();
    // SAFETY: same mapping, no longer used.
    unsafe { libc::munmap(addr, 4096) };
    if rc == 0 {
        println!("MPROTECT-OK {path}");
    } else {
        println!("MPROTECT-BLOCKED {path}: mprotect: {e}");
    }
}

fn attack(pid: Pid, addr: u64) -> ExitCode {
    let attempts: [(&str, Attempt); 3] = [
        ("ptrace attach + PEEKDATA", via_ptrace),
        ("process_vm_readv", via_process_vm_readv),
        ("/proc/<pid>/mem", via_proc_mem),
    ];
    let mut leaked = 0;
    for (name, f) in attempts {
        match f(pid, addr) {
            Ok(v) if v == SECRET => {
                leaked += 1;
                println!("LEAKED  {name}: read {v:#x}");
            }
            Ok(v) => println!("READ    {name}: got {v:#x}, not the secret (wrong addr?)"),
            Err(e) => println!("BLOCKED {name}: {e:#}"),
        }
    }
    println!("{leaked}/3 paths leaked the secret");
    if leaked == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn via_ptrace(pid: Pid, addr: u64) -> Result<u64> {
    ptrace::attach(pid).context("attach")?;
    waitpid(pid, None).context("waitpid")?;
    let word = ptrace::read(pid, addr as ptrace::AddressType).context("PEEKDATA");
    let _ = ptrace::detach(pid, None);
    Ok(word? as u64)
}

fn via_process_vm_readv(pid: Pid, addr: u64) -> Result<u64> {
    let mut buf = [0u8; 8];
    let remote = [RemoteIoVec {
        base: addr as usize,
        len: 8,
    }];
    let n = process_vm_readv(pid, &mut [IoSliceMut::new(&mut buf)], &remote)?;
    anyhow::ensure!(n == 8, "short read: {n} bytes");
    Ok(u64::from_ne_bytes(buf))
}

fn via_proc_mem(pid: Pid, addr: u64) -> Result<u64> {
    let mut f = File::open(format!("/proc/{pid}/mem")).context("open")?;
    f.seek(SeekFrom::Start(addr))?;
    let mut buf = [0u8; 8];
    f.read_exact(&mut buf).context("read")?;
    Ok(u64::from_ne_bytes(buf))
}

/// One attempt against fairplayd: Ok if it worked, else the errno.
type SelfAttempt = Box<dyn Fn() -> Result<(), Errno>>;

fn self_attack(pid: Pid, prog_id: Option<u32>) -> ExitCode {
    let mut attempts: Vec<(&str, SelfAttempt)> = vec![
        (
            "ptrace attach",
            Box::new(move || {
                ptrace::attach(pid)?;
                let _ = waitpid(pid, None);
                let _ = ptrace::detach(pid, None);
                Ok(())
            }),
        ),
        (
            "process_vm_readv",
            Box::new(move || {
                let mut buf = [0u8; 8];
                // Any address: the access check comes first.
                let remote = [RemoteIoVec {
                    base: 0x1000,
                    len: 8,
                }];
                process_vm_readv(pid, &mut [IoSliceMut::new(&mut buf)], &remote).map(drop)
            }),
        ),
        (
            "open /proc/<pid>/mem",
            Box::new(move || {
                File::open(format!("/proc/{pid}/mem"))
                    .map(drop)
                    .map_err(|e| Errno::from_raw(e.raw_os_error().unwrap_or(0)))
            }),
        ),
        (
            "pidfd_getfd (copy its fd 3)",
            Box::new(move || steal_fd(pid, 3)),
        ),
        (
            "bpf(BPF_PROG_LOAD) socket filter",
            Box::new(load_trivial_prog),
        ),
        (
            "bpf(BPF_LINK_DETACH)",
            // link_fd = -1: without the LSM this fails with EBADF.
            Box::new(|| bpf_cmd(BPF_LINK_DETACH, &u32::MAX.to_ne_bytes()).map(drop)),
        ),
        (
            "bpf(BPF_PROG_DETACH)",
            // Without the LSM: EBADF or EINVAL, from the zeroed attributes.
            Box::new(|| bpf_cmd(BPF_PROG_DETACH, &[]).map(drop)),
        ),
    ];
    if let Some(id) = prog_id {
        attempts.push((
            "bpf(BPF_PROG_GET_FD_BY_ID)",
            Box::new(move || {
                let fd = bpf_cmd(BPF_PROG_GET_FD_BY_ID, &id.to_ne_bytes())?;
                // SAFETY: a fresh fd we own.
                unsafe { libc::close(fd) };
                Ok(())
            }),
        ));
    }
    let mut got_past = 0;
    for (name, f) in &attempts {
        match f() {
            Ok(()) => {
                got_past += 1;
                println!("WORKED  {name}");
            }
            Err(e @ (Errno::EPERM | Errno::EACCES)) => println!("BLOCKED {name}: {e}"),
            // Refused for some other reason: not the protection.
            Err(e) => {
                got_past += 1;
                println!("FAILED  {name}: {e} (not a permission error)");
            }
        }
    }
    println!("{got_past}/{} attempts got past fairplayd", attempts.len());
    if got_past == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

const BPF_PROG_LOAD: libc::c_long = 5;
const BPF_PROG_DETACH: libc::c_long = 9;
const BPF_PROG_GET_FD_BY_ID: libc::c_long = 13;
const BPF_LINK_DETACH: libc::c_long = 34;

/// `bpf(cmd, attr, sizeof attr)` with `prefix` as the first bytes of an
/// otherwise zeroed `union bpf_attr`.
fn bpf_cmd(cmd: libc::c_long, prefix: &[u8]) -> Result<i32, Errno> {
    let mut attr = [0u8; 128];
    attr[..prefix.len()].copy_from_slice(prefix);
    // SAFETY: attr is a fully initialised buffer the size we pass.
    let rc = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr.as_ptr(), attr.len() as u32) };
    Errno::result(rc).map(|fd| fd as i32)
}

/// Loads `r0 = 0; exit` as a socket filter, about the smallest program
/// there is, and closes it again.
fn load_trivial_prog() -> Result<(), Errno> {
    // BPF_MOV64_IMM(BPF_REG_0, 0), BPF_EXIT_INSN(), as little-endian words.
    let insns: [u64; 2] = [0xb7, 0x95];
    let license = c"GPL";
    let mut attr = [0u8; 24];
    attr[0..4].copy_from_slice(&1u32.to_ne_bytes()); // BPF_PROG_TYPE_SOCKET_FILTER
    attr[4..8].copy_from_slice(&2u32.to_ne_bytes()); // insn_cnt
    attr[8..16].copy_from_slice(&(insns.as_ptr() as u64).to_ne_bytes());
    attr[16..24].copy_from_slice(&(license.as_ptr() as u64).to_ne_bytes());
    let fd = bpf_cmd(BPF_PROG_LOAD, &attr)?;
    // SAFETY: a fresh fd we own.
    unsafe { libc::close(fd) };
    Ok(())
}

/// `pidfd_getfd`: copy one of the target's file descriptors.
fn steal_fd(pid: Pid, fd: i32) -> Result<(), Errno> {
    // SAFETY: plain syscalls; the fds they return are closed here.
    unsafe {
        let pidfd = Errno::result(libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0))? as i32;
        let copy = Errno::result(libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd, 0));
        libc::close(pidfd);
        libc::close(copy? as i32);
    }
    Ok(())
}
