//! fairplayd (milestones 3 and 4).
//!
//! Loads the BPF LSM program, owns the PROTECTED map, and serves the design
//! doc's vendor-facing API on a Unix socket (see the `fairplay-api` crate):
//! `launch_protected`, `session_status`, `attest`, and a `violations` stream.
//! Every denied attempt is also printed as a `DENIED` line, as in milestone 3.
//!
//!     sudo fairplayd --obj fairplay.o                    # socket API only
//!     sudo fairplayd --obj fairplay.o --protect <pid>    # milestone 3 style
//!
//! The kernel enforces, fairplayd decides who is protected, and the vendor's
//! server sets policy. Protection ends when fairplayd exits (fails open).

mod host;
mod launch;
mod server;
mod state;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Context, Result};
use aya::{
    maps::{HashMap, MapData, MapError, RingBuf},
    programs::Lsm,
    Btf, Ebpf,
};
use clap::Parser;
use fairplay_api::{ProcessState, ViolationEvent, DEFAULT_LAUNCHER_GROUP, DEFAULT_SOCKET};
use fairplay_common::{Violation, MAP_PROTECTED, MAP_VIOLATIONS};
use tokio::{io::unix::AsyncFd, sync::broadcast};

use crate::state::{c_str, hook_name, Daemon, ProtectedMap, CLI_DOMAIN};

#[derive(Parser)]
#[command(about = "Protect game processes with a BPF LSM program and serve the fairplay API")]
struct Args {
    /// Compiled eBPF object (crates/fairplay-ebpf/target/bpfel-unknown-none/release/fairplay)
    #[arg(long)]
    obj: PathBuf,
    /// Unix socket to serve the API on.
    #[arg(long, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
    /// Group whose members may call launch_protected (root always may).
    #[arg(long, default_value = DEFAULT_LAUNCHER_GROUP)]
    launcher_group: String,
    /// Also protect this already-running process (milestone 3; not tracked
    /// as a session, and not removed if it exits).
    #[arg(long)]
    protect: Vec<u32>,
    /// Process allowed into the --protect processes' domain.
    #[arg(long)]
    allow: Vec<u32>,
}

/// The kernel's PROTECTED map.
pub struct BpfMap(HashMap<MapData, u32, u32>);

impl ProtectedMap for BpfMap {
    fn insert(&mut self, pid: u32, domain: u32) -> Result<()> {
        Ok(self.0.insert(pid, domain, 0)?)
    }
    fn remove(&mut self, pid: u32) -> Result<()> {
        match self.0.remove(&pid) {
            Ok(()) | Err(MapError::KeyNotFound) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

pub type Shared = Arc<Mutex<Daemon<BpfMap>>>;

/// The LSM programs in the object, as (program name, kernel LSM hook), each
/// from one module in `crates/fairplay-ebpf/src/hooks/`. All are loaded and
/// attached at startup, and stay attached until fairplayd exits.
const LSM_PROGRAMS: &[(&str, &str)] = &[
    // (program name, LSM hook), one line per hook.
    ("ptrace_access_check", "ptrace_access_check"),
];

fn main() -> Result<()> {
    let args = Args::parse();
    check_bpf_lsm_enabled()?;

    let mut ebpf =
        Ebpf::load_file(&args.obj).with_context(|| format!("loading {}", args.obj.display()))?;
    let btf = Btf::from_sys_fs().context("reading kernel BTF")?;
    for &(name, hook) in LSM_PROGRAMS {
        let prog: &mut Lsm = ebpf
            .program_mut(name)
            .with_context(|| format!("program {name} missing from object"))?
            .try_into()?;
        prog.load(hook, &btf)
            .with_context(|| format!("loading {name} on LSM hook {hook}"))?;
        prog.attach().with_context(|| format!("attaching {name}"))?;
    }

    let mut map = BpfMap(HashMap::try_from(
        ebpf.take_map(MAP_PROTECTED).context("PROTECTED map")?,
    )?);
    for &pid in args.protect.iter().chain(&args.allow) {
        map.insert(pid, CLI_DOMAIN)?;
    }
    if !args.protect.is_empty() {
        eprintln!(
            "fairplayd: protecting {:?}, domain members {:?} (from the command line)",
            args.protect, args.allow
        );
    }
    let ring = RingBuf::try_from(ebpf.take_map(MAP_VIOLATIONS).context("VIOLATIONS map")?)?;

    let launcher_gid = host::group_gid(&args.launcher_group);
    match launcher_gid {
        Some(g) => eprintln!(
            "fairplayd: launchers: root and group {} (gid {g})",
            args.launcher_group
        ),
        None => eprintln!(
            "fairplayd: group {} does not exist; only root may launch",
            args.launcher_group
        ),
    }

    let daemon: Shared = Arc::new(Mutex::new(Daemon::new(map)));
    let (events, _) = broadcast::channel::<ViolationEvent>(1024);

    // Reaping is plain blocking waitid, so it gets its own thread.
    {
        let daemon = daemon.clone();
        std::thread::Builder::new()
            .name("reaper".into())
            .spawn(move || reaper(daemon))?;
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let listener = server::bind(&args.socket)?;
        eprintln!(
            "fairplayd: listening on {}. Ctrl-C to stop (protection ends with this process).",
            args.socket.display()
        );
        let ctx = server::Ctx {
            daemon: daemon.clone(),
            events: events.clone(),
            launcher_gid,
        };
        tokio::spawn(read_violations(ring, daemon, events));
        tokio::select! {
            r = server::serve(listener, ctx) => r?,
            _ = shutdown_signal() => {}
        }
        let _ = std::fs::remove_file(&args.socket);
        eprintln!("fairplayd: stopping; protected processes still running are no longer protected");
        Ok(())
    })
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut int), Ok(mut term)) = (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) else {
        return std::future::pending().await;
    };
    tokio::select! {
        _ = int.recv() => {}
        _ = term.recv() => {}
    }
}

/// Streams the ring buffer: prints each record, files it under its session,
/// and hands it to `violations` subscribers. Woken by the kernel (epoll on
/// the ring buffer's fd), so the caller is usually still alive when we read
/// /proc/<caller>/exe.
async fn read_violations(
    ring: RingBuf<MapData>,
    daemon: Shared,
    events: broadcast::Sender<ViolationEvent>,
) -> Result<()> {
    // SAFETY: the RingBuf owns its fd and keeps it open for as long as the
    // AsyncFd (which owns the RingBuf) is registered.
    let mut ring = unsafe { AsyncFd::register(ring) }
        .map_err(|e| anyhow::anyhow!("watching the ring buffer: {e}"))?;
    loop {
        let mut guard = ring.readable_mut().await?;
        let ring = guard.get_inner_mut();
        while let Some(item) = ring.next() {
            if item.len() < std::mem::size_of::<Violation>() {
                continue;
            }
            // SAFETY: the BPF side writes exactly one Violation per entry.
            let v: Violation = unsafe { std::ptr::read_unaligned(item.as_ptr().cast()) };
            drop(item);
            let exe_path = std::fs::read_link(format!("/proc/{}/exe", v.caller))
                .ok()
                .map(|p| p.display().to_string());
            report(&v, exe_path.as_deref());
            let ev = daemon.lock().unwrap().record_violation(&v, exe_path);
            let _ = events.send(ev); // no subscribers is fine
        }
        guard.clear_ready();
    }
}

fn report(v: &Violation, exe_path: Option<&str>) {
    println!(
        "DENIED caller={} comm={} exe={} target={} hook={} mode={:#x}",
        v.caller,
        c_str(&v.comm),
        exe_path.map(str::to_owned).unwrap_or_else(|| c_str(&v.exe)),
        v.target,
        hook_name(v.hook),
        v.mode
    );
}

/// Collects exited children. For each: wait without reaping (`WNOWAIT`), so
/// the PID stays reserved; remove it from PROTECTED; then reap. Reaping
/// first would let the kernel hand the PID to a new process that would then
/// be protected by mistake.
fn reaper(daemon: Shared) {
    loop {
        // SAFETY: zeroed siginfo_t is a valid out-parameter for waitid.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::waitid(libc::P_ALL, 0, &mut info, libc::WEXITED | libc::WNOWAIT) };
        if rc != 0 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ECHILD) => std::thread::sleep(std::time::Duration::from_millis(50)),
                Some(libc::EINTR) => {}
                e => {
                    eprintln!("fairplayd: waitid failed: {e:?}");
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
            continue;
        }
        // SAFETY: waitid filled in a CLD_* record.
        let (pid, status, code) = unsafe { (info.si_pid(), info.si_status(), info.si_code) };
        let state = if code == libc::CLD_EXITED {
            ProcessState::Exited {
                code: Some(status),
                signal: None,
            }
        } else {
            ProcessState::Exited {
                code: None,
                signal: Some(status),
            }
        };
        let mut d = daemon.lock().unwrap();
        if let Some(session) = d.child_exited(pid as u32, state) {
            eprintln!("fairplayd: session {session}: pid {pid} exited ({state:?}); removed from PROTECTED");
        }
        // Now the PID may be freed.
        // SAFETY: pid is our exited child.
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        drop(d);
    }
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
