//! cheatsim: the attacker for milestone 3.
//!
//! Terminal 1:  cheatsim game            # prints its pid and the secret's address
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
    sys::{
        ptrace,
        uio::{process_vm_readv, RemoteIoVec},
        wait::waitpid,
    },
    unistd::Pid,
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
        /// After startup, dlopen() this library (repeatable) and print
        /// LOADED or BLOCKED: a game being tricked into loading a cheat, or
        /// loading an overlay (milestone 8).
        #[arg(long)]
        dlopen: Vec<String>,
        /// Also read library paths from stdin, one per line, and dlopen each
        /// as it arrives (so a test can drop or replace files first). A line
        /// `mprotect <path>` instead maps the file read-only and then asks
        /// for PROT_EXEC with mprotect(), printing MPROTECT-OK or
        /// MPROTECT-BLOCKED.
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
}

const SECRET: u64 = 0x5EC2_E713_37C0_DE11;

type Attempt = fn(Pid, u64) -> Result<u64>;

fn parse_hex(s: &str) -> Result<u64, String> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    match Args::parse().cmd {
        Cmd::Game {
            dlopen,
            dlopen_stdin,
        } => game(&dlopen, dlopen_stdin),
        Cmd::Attack { pid, addr } => attack(Pid::from_raw(pid), addr),
    }
}

fn game(dlopen: &[String], dlopen_stdin: bool) -> ExitCode {
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
            match line.strip_prefix("mprotect ") {
                Some(path) => make_executable(path),
                None if !line.is_empty() => load(&line),
                None => {}
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
