//! fairplayd v0 (milestones 3 and 4).
//!
//! v0 is a foreground tool: load the LSM program, register the processes to
//! protect, and print every denied attempt. The socket API from the design doc
//! (launch_protected, session_status, attest, violations) builds on this in
//! milestone 4.
//!
//!     sudo fairplayd --obj fairplay.o --protect <game pid> --allow <anti-cheat pid>

use std::{path::PathBuf, thread, time::Duration};

use anyhow::{bail, Context, Result};
use aya::{
    maps::{HashMap, RingBuf},
    programs::Lsm,
    Btf, Ebpf,
};
use clap::Parser;
use fairplay_common::{Hook, Violation, MAP_PROTECTED, MAP_VIOLATIONS};

#[derive(Parser)]
#[command(about = "Protect game processes with a BPF LSM program")]
struct Args {
    /// Compiled eBPF object (crates/fairplay-ebpf/target/bpfel-unknown-none/release/fairplay)
    #[arg(long)]
    obj: PathBuf,
    /// Process to protect (the game)
    #[arg(long, required = true)]
    protect: Vec<u32>,
    /// Process allowed into the same protection domain (the vendor's anti-cheat)
    #[arg(long)]
    allow: Vec<u32>,
}

/// v0 uses a single protection domain.
const DOMAIN: u32 = 1;

fn main() -> Result<()> {
    let args = Args::parse();
    check_bpf_lsm_enabled()?;

    let mut ebpf =
        Ebpf::load_file(&args.obj).with_context(|| format!("loading {}", args.obj.display()))?;
    let btf = Btf::from_sys_fs().context("reading kernel BTF")?;
    let prog: &mut Lsm = ebpf
        .program_mut("ptrace_access_check")
        .context("program ptrace_access_check missing from object")?
        .try_into()?;
    prog.load("ptrace_access_check", &btf)?;
    prog.attach()?;

    {
        let mut protected: HashMap<_, u32, u32> =
            HashMap::try_from(ebpf.map_mut(MAP_PROTECTED).context("PROTECTED map")?)?;
        for pid in args.protect.iter().chain(&args.allow) {
            protected.insert(pid, DOMAIN, 0)?;
        }
    }
    eprintln!(
        "fairplayd: protecting {:?}, domain members {:?}. Ctrl-C to stop (protection ends with this process).",
        args.protect, args.allow
    );

    let mut ring = RingBuf::try_from(ebpf.take_map(MAP_VIOLATIONS).context("VIOLATIONS map")?)?;
    loop {
        while let Some(item) = ring.next() {
            if item.len() < std::mem::size_of::<Violation>() {
                continue;
            }
            // SAFETY: the BPF side writes exactly one Violation per entry.
            let v: Violation = unsafe { std::ptr::read_unaligned(item.as_ptr().cast()) };
            report(&v);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn report(v: &Violation) {
    let hook = match v.hook {
        x if x == Hook::PtraceAccess as u32 => "ptrace_access_check",
        x if x == Hook::UinputOpen as u32 => "file_open(/dev/uinput)",
        _ => "unknown",
    };
    let exe = std::fs::read_link(format!("/proc/{}/exe", v.caller))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<exited>".into());
    println!(
        "DENIED caller={} exe={} target={} hook={} mode={:#x}",
        v.caller, exe, v.target, hook, v.mode
    );
}

fn check_bpf_lsm_enabled() -> Result<()> {
    let lsms = std::fs::read_to_string("/sys/kernel/security/lsm")
        .context("reading /sys/kernel/security/lsm (is securityfs mounted? are you root?)")?;
    if !lsms.split(',').any(|s| s.trim() == "bpf") {
        bail!("BPF LSM is not active ({lsms}). Add 'bpf' to the lsm= boot parameter; see vm/provision-guest.sh");
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("fairplayd must run as root to load LSM programs");
    }
    Ok(())
}
