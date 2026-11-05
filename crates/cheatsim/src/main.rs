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
//! Issue #27: `cheatsim perf` opens a CPU-wide perf event sampling user
//! registers and stack (`pid == -1`, CPU 0), the kind that would see the
//! game's; `cheatsim perf --pid <pid>` opens one on a single process.
//! Prints OPENED or BLOCKED.
//! Milestone 7: `cheatsim clicker` makes a virtual mouse through
//! `/dev/uinput` and clicks, `cheatsim uhid` makes one through `/dev/uhid`,
//! and `cheatsim inject --device /dev/input/eventN` writes an event into an
//! existing device (see `input`).
//! Issue #21: `cheatsim forkbomb` forks until a fork fails, and says how
//! many it got and why (see `forkbomb`).

mod forkbomb;
mod input;

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
        ///
        /// Milestone 9, part B, for a mock anti-cheat started this way:
        /// `attack <pid> <addr>` runs the attacks in this very process;
        /// `forkattack <pid> <addr>` from a forked child that doesn't exec;
        /// `become <path> [args...]` execs in place (no fork); `read
        /// <path>`, `ls <dir>` and `write <path> <text>` try the file
        /// system; `poke <pid> <addr>` tries to overwrite the game's secret
        /// (`process_vm_writev`, then writing `/proc/<pid>/mem`); `signal
        /// <pid> <signum>`; `hold <path>` opens a file and keeps it open;
        /// `connect <name>` and `dgram <name>` reach an abstract Unix
        /// socket (`@name`); `syscalls` tries the namespace, mount, keyring
        /// and bpf system calls the sandbox's seccomp filter refuses, each
        /// with arguments that make it fail harmlessly if it does run, and
        /// prints `EXEC-SYSCALLS name=<errno> ...`. Each prints an EXEC-
        /// line when done. `byhandle <path>` opens a file by its file handle
        /// (`open_by_handle_at`, which needs CAP_DAC_READ_SEARCH).
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
    /// Open a perf event sampling user registers and stack: on every
    /// process on CPU 0, or with --pid on one process.
    Perf {
        #[arg(long)]
        pid: Option<i32>,
    },
    /// Make a virtual mouse through /dev/uinput and click with it (an
    /// autoclicker or triggerbot). Needs write access to /dev/uinput.
    Clicker {
        /// The device's name, as sysfs and session_status show it.
        #[arg(long, default_value = "cheatsim clicker")]
        name: String,
        #[arg(long, default_value_t = 3)]
        clicks: u32,
        /// Milliseconds between clicks.
        #[arg(long, default_value_t = 20)]
        interval_ms: u64,
        /// Seconds to keep the device after clicking.
        #[arg(long, default_value_t = 3600)]
        hold: u64,
    },
    /// Make a virtual HID mouse through /dev/uhid and move it.
    Uhid {
        #[arg(long, default_value = "cheatsim uhid mouse")]
        name: String,
        #[arg(long, default_value_t = 3)]
        moves: u32,
        /// Seconds to keep the device after moving.
        #[arg(long, default_value_t = 3600)]
        hold: u64,
        /// Before creating the device, write an event uhid rejects (marks
        /// the fd as written to).
        #[arg(long)]
        bogus_first: bool,
        /// Wait for a line on stdin before creating the device.
        #[arg(long)]
        wait_stdin: bool,
    },
    /// Write one event (a SYN_REPORT, which changes nothing) into an
    /// existing input device node.
    Inject {
        #[arg(long)]
        device: String,
    },
    /// Fork until a fork fails (issue #21: a game filling PROTECTED), from
    /// several processes at once, and keep every process alive until
    /// killed.
    Forkbomb {
        /// Processes forking at once.
        #[arg(long, default_value_t = 4)]
        workers: u32,
        /// Stop each worker after this many forks.
        #[arg(long, default_value_t = 100_000)]
        max: u32,
        /// After the first refusal, keep trying for this many seconds.
        #[arg(long, default_value_t = 0)]
        keep_trying: u64,
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
        Cmd::Perf { pid } => perf(pid),
        Cmd::Clicker {
            name,
            clicks,
            interval_ms,
            hold,
        } => input::clicker(&name, clicks, interval_ms, hold),
        Cmd::Uhid {
            name,
            moves,
            hold,
            bogus_first,
            wait_stdin,
        } => input::uhid(&name, moves, hold, bogus_first, wait_stdin),
        Cmd::Inject { device } => input::inject(&device),
        Cmd::Forkbomb {
            workers,
            max,
            keep_trying,
        } => forkbomb::forkbomb(workers, max, keep_trying),
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
            } else if let Some(rest) = line.strip_prefix("attack ") {
                in_process_attack(rest, false);
            } else if let Some(rest) = line.strip_prefix("forkattack ") {
                in_process_attack(rest, true);
            } else if let Some(cmd) = line.strip_prefix("become ") {
                exec_in_place(cmd);
            } else if let Some(path) = line.strip_prefix("read ") {
                match std::fs::read_to_string(path) {
                    Ok(t) => println!("EXEC-READ {path}: {}", t.replace('\0', " ").trim()),
                    Err(e) => println!("EXEC-ERR read {path}: {e}"),
                }
            } else if let Some(dir) = line.strip_prefix("ls ") {
                match std::fs::read_dir(dir) {
                    Ok(entries) => {
                        let mut names: Vec<String> = entries
                            .filter_map(|e| e.ok())
                            .map(|e| e.file_name().to_string_lossy().into_owned())
                            .collect();
                        names.sort();
                        println!("EXEC-LS {dir}: [{}]", names.join(" "));
                    }
                    Err(e) => println!("EXEC-ERR ls {dir}: {e}"),
                }
            } else if let Some(path) = line.strip_prefix("byhandle ") {
                match by_handle(path) {
                    Ok(()) => println!("EXEC-BYHANDLE {path}: opened"),
                    Err(e) => println!("EXEC-ERR byhandle {path}: {e}"),
                }
            } else if line == "syscalls" {
                println!("EXEC-SYSCALLS {}", try_syscalls());
            } else if let Some(rest) = line.strip_prefix("poke ") {
                poke(rest);
            } else if let Some(rest) = line.strip_prefix("signal ") {
                let mut w = rest.split_whitespace().map(str::parse::<i32>);
                match (w.next(), w.next()) {
                    (Some(Ok(pid)), Some(Ok(sig))) => {
                        // SAFETY: plain system call.
                        let r = unsafe { libc::kill(pid, sig) };
                        if r == 0 {
                            println!("EXEC-SIGNALED {pid} {sig}");
                        } else {
                            println!(
                                "EXEC-ERR signal {pid} {sig}: {}",
                                std::io::Error::last_os_error()
                            );
                        }
                    }
                    _ => println!("EXEC-ERR signal: want <pid> <signum>"),
                }
            } else if let Some(path) = line.strip_prefix("hold ") {
                match File::open(path) {
                    Ok(f) => {
                        use std::os::fd::IntoRawFd;
                        println!("EXEC-HELD {path} fd={}", f.into_raw_fd());
                    }
                    Err(e) => println!("EXEC-ERR hold {path}: {e}"),
                }
            } else if let Some(name) = line.strip_prefix("connect ") {
                use std::os::linux::net::SocketAddrExt;
                let r = std::os::unix::net::SocketAddr::from_abstract_name(name)
                    .and_then(|a| std::os::unix::net::UnixStream::connect_addr(&a));
                match r {
                    Ok(_) => println!("EXEC-CONNECTED @{name}"),
                    Err(e) => println!("EXEC-ERR connect @{name}: {e}"),
                }
            } else if let Some(name) = line.strip_prefix("dgram ") {
                use std::os::linux::net::SocketAddrExt;
                let r = std::os::unix::net::SocketAddr::from_abstract_name(name).and_then(|a| {
                    std::os::unix::net::UnixDatagram::unbound()?.send_to_addr(b"hello", &a)
                });
                match r {
                    Ok(_) => println!("EXEC-SENT @{name}"),
                    Err(e) => println!("EXEC-ERR dgram @{name}: {e}"),
                }
            } else if let Some(rest) = line.strip_prefix("write ") {
                let (path, text) = rest.split_once(' ').unwrap_or((rest, ""));
                match std::fs::write(path, text) {
                    Ok(()) => println!("EXEC-WROTE {path}"),
                    Err(e) => println!("EXEC-ERR write {path}: {e}"),
                }
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

/// `<pid> <addr>`: runs every attack from this process, or with `fork`
/// from a child that doesn't exec (milestone 9: reader status is not
/// inherited), then prints `EXEC-DONE attack`.
fn in_process_attack(args: &str, fork_first: bool) {
    let mut w = args.split_whitespace();
    let (Some(Ok(pid)), Some(Ok(addr))) =
        (w.next().map(str::parse::<i32>), w.next().map(parse_hex))
    else {
        return println!("EXEC-ERR attack: want <pid> <addr>");
    };
    use std::io::Write;
    let _ = std::io::stdout().flush();
    if !fork_first {
        attack(Pid::from_raw(pid), addr);
        return println!("EXEC-DONE attack");
    }
    // SAFETY: single-threaded; the child runs the attacks and exits.
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            println!("forked child pid={}", std::process::id());
            attack(Pid::from_raw(pid), addr);
            let _ = std::io::stdout().flush();
            unsafe { libc::_exit(0) };
        }
        Ok(ForkResult::Parent { child }) => {
            let _ = waitpid(child, None);
            println!("EXEC-DONE forkattack");
        }
        Err(e) => println!("EXEC-ERR forkattack: fork: {e}"),
    }
}

/// `<pid> <addr>`: tries to overwrite the 8-byte secret with zeros, with
/// `process_vm_writev` and by writing `/proc/<pid>/mem`, and prints
/// `EXEC-POKE` with each result.
fn poke(args: &str) {
    let mut w = args.split_whitespace();
    let (Some(Ok(pid)), Some(Ok(addr))) =
        (w.next().map(str::parse::<i32>), w.next().map(parse_hex))
    else {
        return println!("EXEC-ERR poke: want <pid> <addr>");
    };
    let zeros = [0u8; 8];
    let local = [std::io::IoSlice::new(&zeros)];
    let remote = [RemoteIoVec {
        base: addr as usize,
        len: 8,
    }];
    let pvw = match nix::sys::uio::process_vm_writev(Pid::from_raw(pid), &local, &remote) {
        Ok(n) => format!("wrote {n}"),
        Err(e) => format!("{e}"),
    };
    let mem = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut f = File::options()
            .write(true)
            .open(format!("/proc/{pid}/mem"))?;
        f.seek(SeekFrom::Start(addr))?;
        f.write_all(&zeros)
    })();
    let mem = match mem {
        Ok(()) => "wrote 8".to_string(),
        Err(e) => e.to_string(),
    };
    println!("EXEC-POKE process_vm_writev: {pvw}; /proc/{pid}/mem: {mem}");
}

/// Gets `path`'s file handle (`name_to_handle_at`) and opens the file by
/// it (`open_by_handle_at`): the inode-number route around a mount
/// namespace ("shocker"), which needs CAP_DAC_READ_SEARCH.
fn by_handle(path: &str) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let c = std::ffi::CString::new(path)?;
    // struct file_handle: handle_bytes, handle_type, then up to
    // MAX_HANDLE_SZ (128) bytes.
    let mut buf = [0u32; 2 + 32];
    buf[0] = 128;
    let mut mount_id = 0;
    // SAFETY: buf is a file_handle with room for 128 bytes.
    if unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            libc::AT_FDCWD,
            c.as_ptr(),
            buf.as_mut_ptr(),
            &mut mount_id,
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let mount = File::open(path)?;
    // SAFETY: buf holds the handle the kernel just filled in.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_open_by_handle_at,
            mount.as_raw_fd(),
            buf.as_ptr(),
            libc::O_RDONLY,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the fd the call just returned.
    unsafe { libc::close(fd as libc::c_int) };
    Ok(())
}

/// Tries each system call the anti-cheat sandbox's seccomp filter refuses
/// beyond the memory ones (#30), with arguments that make the call itself
/// fail (a missing path, a bad fd, an unknown command) if it runs, so a
/// control run outside the sandbox changes nothing, even as root. Returns
/// `name=<errno>` for each (`ok` if one somehow succeeds): EPERM means
/// refused before it ran (or, for an ordinary user, for lack of privilege:
/// the test runs it as root). clone3 should be ENOSYS in the sandbox.
fn try_syscalls() -> String {
    const NOPE: &std::ffi::CStr = c"/nonexistent-fairplay-m9b";
    let n = NOPE.as_ptr();
    let null = std::ptr::null::<libc::c_char>();
    // (name, returns an fd to close, call)
    let probes: [(&str, bool, &dyn Fn() -> libc::c_long); 27] = [
        ("setns", false, &|| unsafe {
            libc::syscall(libc::SYS_setns, -1, 0)
        }),
        // Bit 0 is no unshare flag: EINVAL before anything is done.
        ("unshare", false, &|| unsafe {
            libc::syscall(libc::SYS_unshare, 1)
        }),
        ("mount", false, &|| unsafe {
            libc::syscall(
                libc::SYS_mount,
                c"none".as_ptr(),
                n,
                c"tmpfs".as_ptr(),
                0,
                null,
            )
        }),
        ("umount2", false, &|| unsafe {
            libc::syscall(libc::SYS_umount2, n, 0)
        }),
        ("open_tree", true, &|| unsafe {
            libc::syscall(libc::SYS_open_tree, -1, n, 0)
        }),
        ("move_mount", false, &|| unsafe {
            libc::syscall(libc::SYS_move_mount, -1, n, -1, n, 0)
        }),
        ("fsopen", true, &|| unsafe {
            libc::syscall(libc::SYS_fsopen, c"fairplay-no-such-fs".as_ptr(), 0)
        }),
        ("fsconfig", false, &|| unsafe {
            libc::syscall(libc::SYS_fsconfig, -1, 0, null, null, 0)
        }),
        ("fsmount", true, &|| unsafe {
            libc::syscall(libc::SYS_fsmount, -1, 0, 0)
        }),
        ("fspick", true, &|| unsafe {
            libc::syscall(libc::SYS_fspick, -1, n, 0)
        }),
        ("mount_setattr", false, &|| unsafe {
            libc::syscall(libc::SYS_mount_setattr, -1, n, 0, null, 0)
        }),
        ("pivot_root", false, &|| unsafe {
            libc::syscall(libc::SYS_pivot_root, n, n)
        }),
        ("chroot", false, &|| unsafe {
            libc::syscall(libc::SYS_chroot, n)
        }),
        ("keyctl", false, &|| unsafe {
            libc::syscall(libc::SYS_keyctl, 9999, 0, 0, 0, 0)
        }),
        ("add_key", false, &|| unsafe {
            libc::syscall(
                libc::SYS_add_key,
                c"fairplay-no-such-type".as_ptr(),
                c"x".as_ptr(),
                null,
                0,
                0,
            )
        }),
        ("request_key", false, &|| unsafe {
            libc::syscall(
                libc::SYS_request_key,
                c"fairplay-no-such-type".as_ptr(),
                c"x".as_ptr(),
                null,
                0,
            )
        }),
        ("bpf", false, &|| unsafe {
            libc::syscall(libc::SYS_bpf, 9999, null, 0)
        }),
        // 0 entries: EINVAL.
        ("io_uring_setup", false, &|| unsafe {
            libc::syscall(libc::SYS_io_uring_setup, 0, null)
        }),
        ("io_uring_enter", false, &|| unsafe {
            libc::syscall(libc::SYS_io_uring_enter, -1, 0, 0, 0, null, 0)
        }),
        // A NULL attribute block: EFAULT.
        ("perf_event_open", true, &|| unsafe {
            libc::syscall(libc::SYS_perf_event_open, null, 0, -1, -1, 0)
        }),
        // Flags it doesn't know: EINVAL.
        ("userfaultfd", true, &|| unsafe {
            libc::syscall(libc::SYS_userfaultfd, 0x7fff_0000)
        }),
        // CLONE_NEWUSER with CLONE_FS is invalid: EINVAL, no child.
        ("clone_newuser", false, &|| unsafe {
            libc::syscall(
                libc::SYS_clone,
                libc::CLONE_NEWUSER | libc::CLONE_FS | libc::SIGCHLD,
                0,
                0,
                0,
                0,
            )
        }),
        ("clone_newns", false, &|| unsafe {
            libc::syscall(
                libc::SYS_clone,
                libc::CLONE_NEWNS | libc::CLONE_FS | libc::SIGCHLD,
                0,
                0,
                0,
                0,
            )
        }),
        ("clone_newnet", false, &|| unsafe {
            // CLONE_SIGHAND without CLONE_VM is invalid too.
            libc::syscall(
                libc::SYS_clone,
                libc::CLONE_NEWNET | libc::CLONE_SIGHAND | libc::SIGCHLD,
                0,
                0,
                0,
                0,
            )
        }),
        ("clone_newpid", false, &|| unsafe {
            libc::syscall(
                libc::SYS_clone,
                libc::CLONE_NEWPID | libc::CLONE_SIGHAND | libc::SIGCHLD,
                0,
                0,
                0,
                0,
            )
        }),
        // A NULL argument block smaller than any version: EINVAL.
        ("clone3", false, &|| unsafe {
            libc::syscall(libc::SYS_clone3, null, 0)
        }),
        ("unshare_none", false, &|| unsafe {
            libc::syscall(libc::SYS_unshare, 0)
        }),
    ];
    let mut out = Vec::new();
    for (name, fd, call) in probes {
        let r = call();
        let what = if r >= 0 {
            if fd {
                // SAFETY: an fd the call just returned.
                unsafe { libc::close(r as libc::c_int) };
            }
            "ok".to_string()
        } else {
            format!("{:?}", Errno::last())
        };
        out.push(format!("{name}={what}"));
    }
    out.join(" ")
}

/// Execs `cmd` (split on whitespace) in place of this process: the same
/// pid, a different program. Prints only if that fails.
fn exec_in_place(cmd: &str) {
    let Ok(words) = cmd
        .split_whitespace()
        .map(std::ffi::CString::new)
        .collect::<Result<Vec<_>, _>>()
    else {
        return println!("EXEC-ERR become: NUL in command");
    };
    let Some(c) = words.first() else {
        return println!("EXEC-ERR become: empty command");
    };
    let mut argv: Vec<*const libc::c_char> = words.iter().map(|w| w.as_ptr()).collect();
    argv.push(std::ptr::null());
    use std::io::Write;
    let _ = std::io::stdout().flush();
    // SAFETY: argv is NULL-terminated and outlives the call.
    unsafe { libc::execv(c.as_ptr(), argv.as_ptr()) };
    println!("EXEC-ERR become: {}", std::io::Error::last_os_error());
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

/// `perf_event_open` for a software clock event that samples user
/// registers and the user stack: on `pid`, or with `None` on everything
/// CPU 0 runs. Exit status 0 if it opened.
fn perf(pid: Option<i32>) -> ExitCode {
    // struct perf_event_attr, PERF_ATTR_SIZE_VER5 (112 bytes), zeroed.
    let mut attr = [0u8; 112];
    let put32 = |a: &mut [u8], at: usize, v: u32| a[at..at + 4].copy_from_slice(&v.to_ne_bytes());
    let put64 = |a: &mut [u8], at: usize, v: u64| a[at..at + 8].copy_from_slice(&v.to_ne_bytes());
    put32(&mut attr, 0, 1); // type: PERF_TYPE_SOFTWARE
    put32(&mut attr, 4, 112); // size
    put64(&mut attr, 8, 0); // config: PERF_COUNT_SW_CPU_CLOCK
    put64(&mut attr, 16, 10_000); // sample_period
                                  // sample_type: PERF_SAMPLE_REGS_USER | PERF_SAMPLE_STACK_USER
    put64(&mut attr, 24, (1 << 12) | (1 << 13));
    // flags: disabled, exclude_kernel, exclude_hv
    put64(&mut attr, 40, 1 | (1 << 5) | (1 << 6));
    put64(&mut attr, 80, 0xff); // sample_regs_user: a few registers
    put32(&mut attr, 88, 4096); // sample_stack_user
    let (target, cpu) = match pid {
        Some(p) => (p, -1),
        None => (-1, 0),
    };
    let what = match pid {
        Some(p) => format!("perf_event_open on pid {p}"),
        None => "CPU-wide perf_event_open (pid -1, CPU 0)".into(),
    };
    // SAFETY: attr is a fully initialised buffer of the size it declares.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            attr.as_ptr(),
            target,
            cpu,
            -1,
            8u64, // PERF_FLAG_FD_CLOEXEC
        )
    };
    match Errno::result(rc) {
        Ok(fd) => {
            // SAFETY: a fresh fd we own.
            unsafe { libc::close(fd as i32) };
            println!("OPENED  {what}");
            ExitCode::SUCCESS
        }
        Err(e @ (Errno::EPERM | Errno::EACCES)) => {
            println!("BLOCKED {what}: {e}");
            ExitCode::FAILURE
        }
        Err(e) => {
            println!("FAILED  {what}: {e} (not a permission error)");
            ExitCode::from(2)
        }
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
