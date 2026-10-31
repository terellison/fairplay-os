//! Perf events (issue #27). With `PERF_SAMPLE_REGS_USER` and
//! `PERF_SAMPLE_STACK_USER` a perf event copies the registers and user
//! stack of whatever it watches, so it reads memory like ptrace does. The
//! kernel's own check doesn't hold against root: `perf_check_permission`
//! skips `ptrace_may_access` for anyone with `CAP_PERFMON`, so
//! `ptrace_access_check` never sees root's events. Two hooks close that,
//! whenever any process is protected (not only with `--self-protect`), like
//! the ptrace rules:
//!
//! - `perf_event_open` with type `PERF_SECURITY_CPU`: an event on a whole
//!   CPU (`pid == -1`, or a cgroup event) samples every process that runs
//!   there, the game included. Denied while PERF_GUARD (set by fairplayd)
//!   is on. Recorded as [`Hook::PerfCpu`], target 0; fairplayd files it
//!   under every running session.
//! - `perf_event_alloc`: an event on one task (`event->hw.target`, set
//!   before the hook runs). Same rule as `ptrace_access_check`: on a
//!   protected process only the process itself and its domain's readers
//!   may, and while fairplayd protects itself nobody else may watch it.
//!   The rule points outward too: a protected process may not watch one
//!   outside its domain. Recorded as [`Hook::PerfTarget`]. Counters copied
//!   to a child at fork (`event->parent` set) were already allowed on the
//!   parent and pass: refusing them would fail the fork.
//!
//! `mode` in the record is `event->attr.type`, which by now is the PMU
//! the kernel picked, not always what the caller asked for: a
//! `PERF_TYPE_SOFTWARE` cpu-clock or task-clock event is moved to the
//! kernel's own `cpu_clock` / `task_clock` PMU, whose type is assigned at
//! boot (6 and 7 on 6.8; `perf_swevent_init`). The `perf_event_open`
//! hook's `attr` for a CPU-wide event is that same `event->attr`.
//!
//! Both leave alone the kernel's own counters (the hard-lockup watchdog),
//! made from kernel threads, and per-process events on unprotected
//! processes.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel},
    macros::lsm,
    programs::LsmContext,
};
use core::ptr::addr_of;
use fairplay_common::{Hook, PERF_SECURITY_CPU};

use crate::{
    domain::{denied_caller_in, record_in, record_violation, task_domain, Name, EPERM},
    maps::{PERF_GUARD, PROTECTED},
    self_protect::outsider,
    vmlinux::{perf_event, perf_event_attr, task_struct},
};

/// `PF_KTHREAD` (`<linux/sched.h>`).
const PF_KTHREAD: u32 = 0x0020_0000;

/// Is the current task a kernel thread? (Unreadable counts as not.)
#[inline(always)]
fn kthread() -> bool {
    unsafe {
        let task = bpf_get_current_task() as *const task_struct;
        bpf_probe_read_kernel(addr_of!((*task).flags))
    }
    .is_ok_and(|flags| flags & PF_KTHREAD != 0)
}

#[lsm(hook = "perf_event_open")]
pub fn perf_event_open(ctx: LsmContext) -> i32 {
    // int perf_event_open(struct perf_event_attr *attr, int type)
    // For BPF LSM, arg 2 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(2) };
    if prev != 0 {
        return prev;
    }
    let kind: u32 = unsafe { ctx.arg(1) };
    if kind != PERF_SECURITY_CPU || !PERF_GUARD.get(0).is_some_and(|&on| on != 0) || kthread() {
        return 0;
    }
    let attr: *const perf_event_attr = unsafe { ctx.arg(0) };
    let event_type = unsafe { bpf_probe_read_kernel(addr_of!((*attr).type_)) }.unwrap_or(u32::MAX);
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    record_in(caller, 0, 0, Hook::PerfCpu, event_type, 0, Name::None);
    -EPERM
}

#[lsm(hook = "perf_event_alloc")]
pub fn perf_event_alloc(ctx: LsmContext) -> i32 {
    // int perf_event_alloc(struct perf_event *event)
    // For BPF LSM, arg 1 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(1) };
    if prev != 0 {
        return prev;
    }
    match should_deny_alloc(unsafe { ctx.arg(0) }) {
        Ok(false) => 0,
        // Unreadable: deny, as the ptrace and self-protection checks do.
        _ => -EPERM,
    }
}

fn should_deny_alloc(event: *const perf_event) -> Result<bool, i64> {
    let target: *const task_struct =
        unsafe { bpf_probe_read_kernel(addr_of!((*event).hw.target))? };
    // A CPU-wide event (perf_event_open's job), or a kernel counter.
    if target.is_null() || kthread() {
        return Ok(false);
    }
    let parent: *const perf_event = unsafe { bpf_probe_read_kernel(addr_of!((*event).parent))? };
    if !parent.is_null() {
        return Ok(false); // inherited at fork
    }
    let event_type = unsafe { bpf_probe_read_kernel(addr_of!((*event).attr.type_))? };
    if let Some((caller, fairplayd)) = outsider() {
        let tgid = unsafe { bpf_probe_read_kernel(addr_of!((*target).tgid))? } as u32;
        if tgid == fairplayd {
            record_violation(caller, fairplayd, Hook::PerfTarget, event_type);
            return Ok(true);
        }
    }
    let Some((tgid, domain)) = task_domain(target)? else {
        return outbound(target, event_type);
    };
    let Some(caller) = denied_caller_in(tgid, domain) else {
        return Ok(false);
    };
    record_violation(caller, tgid, Hook::PerfTarget, event_type);
    Ok(true)
}

/// The target is not protected: deny (and record) only if the caller is,
/// as `ptrace_access_check` does. A protected process (the game, its
/// anti-cheat) may watch only processes of its own domain.
fn outbound(target: *const task_struct, event_type: u32) -> Result<bool, i64> {
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    let Some(&domain) = (unsafe { PROTECTED.get(&caller) }) else {
        return Ok(false);
    };
    let tgid = unsafe { bpf_probe_read_kernel(addr_of!((*target).tgid))? } as u32;
    if tgid == caller {
        return Ok(false);
    }
    record_in(
        caller,
        tgid,
        domain,
        Hook::PerfTarget,
        event_type,
        0,
        Name::None,
    );
    Ok(true)
}
