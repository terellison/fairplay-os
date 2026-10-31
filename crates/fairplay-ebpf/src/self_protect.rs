//! fairplayd protecting itself (milestone 6). On a player's PC root may be
//! the cheater, and the easiest way to cheat is to switch the protection
//! off: kill fairplayd, edit its maps, or detach its programs. While
//! fairplayd runs with `--self-protect`, its tgid is in SELF_PROTECT and
//! these hooks keep every other process, root included, away from it:
//!
//! - `task_kill`: no signals to fairplayd (SIGKILL and SIGSTOP included).
//!   Signals the kernel raises itself (SIGCHLD from its children, SIGPIPE,
//!   a terminal's Ctrl-C) don't pass through this hook and still arrive.
//! - `ptrace_access_check`: fairplayd counts as protected from everyone, so
//!   no ptrace, `/proc/<pid>/mem`, `process_vm_*` or `pidfd_getfd`.
//! - `bpf_map` / `bpf_prog`: no file descriptors to fairplayd's maps and
//!   programs (listed in SELF_OBJECTS), so no reading or writing its maps.
//! - `bpf`: no new BPF programs, no link fds by id, no detaching. A program
//!   of almost any type loaded by root can read the process it runs in with
//!   `bpf_probe_read_user`, which no LSM hook sees.
//!
//! - `task_setrlimit`, `task_setnice`, `task_setscheduler`,
//!   `task_setioprio` (issue #27): no starving or limiting it instead.
//!   `prlimit --cpu=1` would have the kernel send SIGXCPU and then SIGKILL,
//!   which `task_kill` doesn't see; SCHED_IDLE, nice 19, a one-CPU
//!   affinity or the idle I/O class would leave it too slow to answer.
//!   `task_setscheduler` also covers `sched_setaffinity`, `sched_setattr`,
//!   `/proc/<pid>/timerslack_ns` and moving it into a cpuset cgroup.
//! - `file_open` (issue #27): no opening its `/proc/<pid>/oom_score_adj`,
//!   `oom_adj` or `autogroup` for writing, so root can't make it the OOM
//!   killer's first choice (fairplayd sets its own score to -1000).
//!
//! Off (SELF_PROTECT[0] == 0) unless fairplayd was asked for it: developer
//! mode, and the shared test VM, keep normal root.

use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel};
use core::ptr::addr_of;
use fairplay_common::{self_object_key, Hook};

use crate::{
    domain::{record_violation, EPERM},
    maps::{SELF_OBJECTS, SELF_PROTECT, SELF_THREADS},
    vmlinux::task_struct,
};

/// `(caller, fairplayd)`: the current task's tgid and fairplayd's, if
/// self-protection is on and the current task is not part of fairplayd.
pub fn outsider() -> Option<(u32, u32)> {
    let guardian = guardian()?;
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    (caller != guardian).then_some((caller, guardian))
}

/// Is this map, program or link (`SELF_*` kind, kernel id) fairplayd's?
pub fn is_own(kind: u32, id: u32) -> bool {
    unsafe { SELF_OBJECTS.get(&self_object_key(kind, id)) }.is_some()
}

/// fairplayd's tgid while it protects itself.
#[inline(always)]
pub fn guardian() -> Option<u32> {
    SELF_PROTECT.get(0).copied().filter(|&g| g != 0)
}

/// Is `pid` (a tgid or a thread id) one of fairplayd's threads? `fairplayd`
/// is its tgid.
#[inline(always)]
pub fn is_fairplayd(pid: u32, fairplayd: u32) -> bool {
    pid == fairplayd || unsafe { SELF_THREADS.get(&pid) }.is_some()
}

/// The verdict for a `task_set*` hook acting on `p`: -EPERM (and one
/// violation with `hook` and `mode`) if `p` is fairplayd and the caller
/// isn't. Any thread of fairplayd counts: rlimits are per process, and the
/// others are per thread but each thread matters.
#[inline(always)]
pub fn guard_task(p: *const task_struct, hook: Hook, mode: u32) -> i32 {
    let Some((caller, fairplayd)) = outsider() else {
        return 0;
    };
    let Ok(tgid) = (unsafe { bpf_probe_read_kernel(addr_of!((*p).tgid)) }) else {
        return 0;
    };
    if tgid as u32 != fairplayd {
        return 0;
    }
    record_violation(caller, fairplayd, hook, mode);
    -EPERM
}
