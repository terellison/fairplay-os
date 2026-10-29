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
    Game,
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
        Cmd::Game => game(),
        Cmd::Attack { pid, addr } => attack(Pid::from_raw(pid), addr),
    }
}

fn game() -> ExitCode {
    let secret = Box::new(SECRET);
    println!(
        "pid={} addr={:#x}",
        std::process::id(),
        &*secret as *const u64 as usize
    );
    loop {
        // Keep the value live so the optimizer can't drop it.
        std::hint::black_box(&secret);
        thread::sleep(Duration::from_secs(1));
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
