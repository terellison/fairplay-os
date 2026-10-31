//! fairplayd (milestones 3, 4, 7 and 8).
//!
//! Loads the BPF LSM program, owns the PROTECTED map, and serves the design
//! doc's vendor-facing API on a Unix socket (see the `fairplay-api` crate):
//! `launch_protected`, `session_status`, `attest`, and a `violations` stream.
//! Every denied attempt is also printed as a `DENIED` line, as in milestone 3.
//! It also keeps the executable-mapping allowlist (milestone 8): which files
//! a protected process may map as code (see `exec_allow`). And it reports
//! virtual input (milestone 7): who creates uinput and uhid devices or
//! writes into input devices, with a `REPORTED` line and a violation event
//! for each one during a session, unless the executable is on the input
//! allowlist (see `input`).
//!
//!     sudo fairplayd --obj fairplay.o                    # socket API only
//!     sudo fairplayd --obj fairplay.o --protect <pid>    # milestone 3 style
//!     sudo fairplayd --obj fairplay.o --overlay /usr/local/lib/overlay.so
//!     sudo fairplayd --obj fairplay.o --input-allow /usr/bin/input-remapper-service
//!
//! The kernel enforces, fairplayd decides who is protected, and the vendor's
//! server sets policy. Protection ends when fairplayd exits (fails open).

mod exec_allow;
mod host;
mod input;
mod launch;
mod server;
mod state;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Context, Result};
use aya::{
    maps::{Array, HashMap, MapData, MapError, RingBuf},
    programs::{BtfTracePoint, Lsm},
    Btf, Ebpf,
};
use clap::Parser;
use fairplay_api::{ProcessState, ViolationEvent, DEFAULT_LAUNCHER_GROUP, DEFAULT_SOCKET};
use fairplay_common::{
    ExecAllow, ExecKey, Violation, ANY_DOMAIN, FS_SYSTEM, MAP_EXEC_ALLOWED, MAP_EXEC_TRUSTED_FS,
    MAP_INPUT_ALLOWED, MAP_INPUT_BLOCK, MAP_PROTECTED, MAP_UNFOLLOWED, MAP_VIOLATIONS,
    VIOLATION_REPORTED,
};
use tokio::{io::unix::AsyncFd, sync::broadcast};

use crate::{
    input::InputRecord,
    state::{c_str, hook_name, unix_now, Daemon, ProtectedMap, CLI_DOMAIN},
};

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
    /// as a session). Processes it starts from now on join its domain.
    #[arg(long)]
    protect: Vec<u32>,
    /// Process allowed into the --protect processes' domain.
    #[arg(long)]
    allow: Vec<u32>,
    /// An approved overlay (absolute path of a library): every protected
    /// process may map it executable. Repeatable. Identified by inode when
    /// fairplayd starts, so replacing the file un-approves it.
    #[arg(long)]
    overlay: Vec<PathBuf>,
    /// An executable allowed to make virtual input (a remapper or
    /// accessibility tool; absolute path). Repeatable. Its devices are
    /// listed as allowlisted and never sent to vendors, and a session's
    /// block_virtual_input doesn't stop it. Identified by inode when
    /// fairplayd starts, like --overlay.
    #[arg(long)]
    input_allow: Vec<PathBuf>,
}

/// The kernel's PROTECTED map, UNFOLLOWED beside it, EXEC_ALLOWED, and
/// INPUT_BLOCK.
pub struct BpfMap {
    protected: HashMap<MapData, u32, u32>,
    unfollowed: HashMap<MapData, u32, u64>,
    exec: HashMap<MapData, ExecKey, ExecAllow>,
    input_block: Array<MapData, u32>,
}

impl ProtectedMap for BpfMap {
    fn insert(&mut self, pid: u32, domain: u32) -> Result<()> {
        Ok(self.protected.insert(pid, domain, 0)?)
    }
    fn remove(&mut self, pid: u32) -> Result<()> {
        match self.protected.remove(&pid) {
            Ok(()) | Err(MapError::KeyNotFound) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    fn allow_exec(&mut self, key: ExecKey, value: ExecAllow) -> Result<()> {
        Ok(self.exec.insert(key, value, 0)?)
    }
    fn disallow_exec(&mut self, key: ExecKey) -> Result<()> {
        match self.exec.remove(&key) {
            Ok(()) | Err(MapError::KeyNotFound) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    fn unfollowed(&self, domain: u32) -> u64 {
        self.unfollowed.get(&domain, 0).unwrap_or(0)
    }
    fn forget_domain(&mut self, domain: u32) {
        let _ = self.unfollowed.remove(&domain);
    }
    fn set_input_block(&mut self, on: bool) -> Result<()> {
        Ok(self.input_block.set(0, u32::from(on), 0)?)
    }
}

pub type Shared = Arc<Mutex<Daemon<BpfMap>>>;

/// The LSM programs in the object, as (program name, kernel LSM hook), each
/// from one module in `crates/fairplay-ebpf/src/hooks/`. All are loaded and
/// attached at startup, and stay attached until fairplayd exits.
const LSM_PROGRAMS: &[(&str, &str)] = &[
    // (program name, LSM hook), one line per hook.
    ("ptrace_access_check", "ptrace_access_check"),
    ("mmap_file", "mmap_file"),
    ("file_mprotect", "file_mprotect"),
    ("file_ioctl", "file_ioctl"),
    ("file_permission", "file_permission"),
];

/// LSM programs for hooks older kernels lack. fairplayd starts without them
/// and says what that leaves uncovered.
const OPTIONAL_LSM_PROGRAMS: &[(&str, &str, &str)] = &[
    // (program name, LSM hook, what goes unseen without it)
    (
        "file_ioctl_compat",
        "file_ioctl_compat",
        "uinput devices made by 32-bit programs (the hook is Linux 6.8+)",
    ),
];

/// Tracing programs that keep PROTECTED in step with the processes in it,
/// as (program name, tracepoint), from `crates/fairplay-ebpf/src/follow.rs`:
/// every process a protected process starts joins its domain, and each
/// leaves the map when it exits. Attached and kept like the LSM programs.
const TRACING_PROGRAMS: &[(&str, &str)] = &[
    ("follow_fork", "sched_process_fork"),
    ("unfollow_exit", "sched_process_exit"),
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
    for &(name, hook, gap) in OPTIONAL_LSM_PROGRAMS {
        let prog: &mut Lsm = ebpf
            .program_mut(name)
            .with_context(|| format!("program {name} missing from object"))?
            .try_into()?;
        let attached = prog
            .load(hook, &btf)
            .map_err(anyhow::Error::from)
            .and_then(|()| Ok(prog.attach()?));
        if let Err(e) = attached {
            eprintln!("fairplayd: warning: no {hook} hook ({e:#}); not seen: {gap}");
        }
    }

    for &(name, tracepoint) in TRACING_PROGRAMS {
        let prog: &mut BtfTracePoint = ebpf
            .program_mut(name)
            .with_context(|| format!("program {name} missing from object"))?
            .try_into()?;
        prog.load(tracepoint, &btf)
            .with_context(|| format!("loading {name} on tracepoint {tracepoint}"))?;
        prog.attach().with_context(|| format!("attaching {name}"))?;
    }

    // Executable-mapping allowlist (milestone 8). Filled before anything is
    // protected, so a protected process never sees a half-made allowlist.
    let mut trusted_fs: HashMap<MapData, u32, u32> = HashMap::try_from(
        ebpf.take_map(MAP_EXEC_TRUSTED_FS)
            .context("EXEC_TRUSTED_FS map")?,
    )?;
    let trusted = exec_allow::trusted_filesystems()?;
    for &(dev, kind) in &trusted {
        trusted_fs.insert(dev, kind, 0)?;
    }
    let system_devs: Arc<[u32]> = trusted
        .iter()
        .filter(|&&(_, kind)| kind == FS_SYSTEM)
        .map(|&(dev, _)| dev)
        .collect();
    let map = BpfMap {
        protected: HashMap::try_from(ebpf.take_map(MAP_PROTECTED).context("PROTECTED map")?)?,
        unfollowed: HashMap::try_from(ebpf.take_map(MAP_UNFOLLOWED).context("UNFOLLOWED map")?)?,
        exec: HashMap::try_from(
            ebpf.take_map(MAP_EXEC_ALLOWED)
                .context("EXEC_ALLOWED map")?,
        )?,
        input_block: Array::try_from(ebpf.take_map(MAP_INPUT_BLOCK).context("INPUT_BLOCK map")?)?,
    };
    let mut daemon = Daemon::new(map);
    let mounts = exec_allow::Mounts::read()?;

    // Virtual input allowlist (milestone 7), fixed for the daemon's life.
    let mut input_allowed: HashMap<MapData, ExecKey, ExecAllow> = HashMap::try_from(
        ebpf.take_map(MAP_INPUT_ALLOWED)
            .context("INPUT_ALLOWED map")?,
    )?;
    for path in &args.input_allow {
        let id = exec_allow::input_tool_file(path, &mounts)?;
        let (key, value) = id.entry(ANY_DOMAIN);
        input_allowed
            .insert(key, value, 0)
            .with_context(|| format!("allowing {}", path.display()))?;
    }
    eprintln!(
        "fairplayd: virtual input: reported during sessions; {} allowlisted executable(s) {:?}",
        args.input_allow.len(),
        args.input_allow
    );
    let overlays = args
        .overlay
        .iter()
        .map(|p| exec_allow::overlay_file(p, &mounts))
        .collect::<Result<Vec<_>>>()?;
    daemon
        .allow_overlays(&overlays)
        .map_err(|e| anyhow::anyhow!("approving overlays: {e}"))?;
    eprintln!(
        "fairplayd: executable mappings: {} system filesystem(s), {} approved overlay(s) {:?}",
        system_devs.len(),
        overlays.len(),
        args.overlay
    );
    for &pid in args.protect.iter().chain(&args.allow) {
        daemon.map_mut().insert(pid, CLI_DOMAIN)?;
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

    let daemon: Shared = Arc::new(Mutex::new(daemon));
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
            system_devs,
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
            if input::Mechanism::of_hook(v.hook).is_some() {
                record_input(&v, &daemon, &events);
                continue;
            }
            // Not for a protected caller (e.g. a game whose own mapping was
            // denied): reading its /proc/<pid>/exe is itself a ptrace
            // access check, which the kernel would deny and log as a
            // violation by fairplayd. The kernel's `exe` names it anyway.
            let caller_protected =
                v.caller == v.target || daemon.lock().unwrap().session_of_pid(v.caller).is_some();
            let exe_path = (!caller_protected)
                .then(|| std::fs::read_link(format!("/proc/{}/exe", v.caller)).ok())
                .flatten()
                .map(|p| p.display().to_string());
            report(&v, exe_path.as_deref());
            let ev = daemon.lock().unwrap().record_violation(&v, exe_path);
            let _ = events.send(ev); // no subscribers is fine
        }
        guard.clear_ready();
    }
}

/// A virtual input record (milestone 7): kept for `session_status`, and
/// during a session, unless the executable is allowlisted, printed as a
/// `REPORTED` (or, if a session asked for blocking, `DENIED`) line and sent
/// to every running session's subscribers.
fn record_input(v: &Violation, daemon: &Shared, events: &broadcast::Sender<ViolationEvent>) {
    // The creator isn't protected (a protected caller would be in the
    // session's own domain, and reading its exe is then denied and
    // logged); fine to look.
    let caller_protected = daemon.lock().unwrap().session_of_pid(v.caller).is_some();
    let exe_path = (!caller_protected)
        .then(|| std::fs::read_link(format!("/proc/{}/exe", v.caller)).ok())
        .flatten()
        .map(|p| p.display().to_string());
    let Some(rec) = InputRecord::from_kernel(v, exe_path.clone(), unix_now()) else {
        return;
    };
    let evs = daemon.lock().unwrap().record_input(rec);
    if evs.is_empty() {
        eprintln!(
            "fairplayd: input: {} by pid {} ({}){} not reported ({})",
            hook_name(v.hook),
            v.caller,
            exe_path.clone().unwrap_or_else(|| c_str(&v.exe)),
            Some(c_str(&v.file))
                .filter(|f| !f.is_empty())
                .map(|f| format!(" file={f}"))
                .unwrap_or_default(),
            if v.flags & fairplay_common::VIOLATION_ALLOWLISTED != 0 {
                "allowlisted"
            } else {
                "no session running"
            },
        );
        return;
    }
    report(v, exe_path.as_deref());
    for ev in evs {
        let _ = events.send(ev);
    }
}

/// One line per record: `DENIED`, or `REPORTED` for virtual input the
/// kernel let through.
fn report(v: &Violation, exe_path: Option<&str>) {
    let file = c_str(&v.file);
    println!(
        "{} caller={} comm={} exe={} target={} hook={} mode={:#x}{}",
        if v.flags & VIOLATION_REPORTED != 0 {
            "REPORTED"
        } else {
            "DENIED"
        },
        v.caller,
        c_str(&v.comm),
        exe_path.map(str::to_owned).unwrap_or_else(|| c_str(&v.exe)),
        v.target,
        hook_name(v.hook),
        v.mode,
        if file.is_empty() {
            String::new()
        } else {
            format!(" file={file}")
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_flag_repeats() {
        let a = Args::try_parse_from([
            "fairplayd",
            "--obj",
            "x.o",
            "--overlay",
            "/a.so",
            "--overlay",
            "/b.so",
        ])
        .unwrap();
        assert_eq!(a.overlay, vec![PathBuf::from("/a.so"), "/b.so".into()]);
        let a = Args::try_parse_from(["fairplayd", "--obj", "x.o"]).unwrap();
        assert!(a.overlay.is_empty());
        assert!(a.input_allow.is_empty());
    }

    #[test]
    fn input_allow_flag_repeats() {
        let a = Args::try_parse_from([
            "fairplayd",
            "--obj",
            "x.o",
            "--input-allow",
            "/usr/bin/remapper",
            "--input-allow",
            "/usr/bin/a11y",
        ])
        .unwrap();
        assert_eq!(
            a.input_allow,
            vec![PathBuf::from("/usr/bin/remapper"), "/usr/bin/a11y".into()]
        );
    }
}
