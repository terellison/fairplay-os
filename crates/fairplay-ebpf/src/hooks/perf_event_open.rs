//! `perf_event_open` (issue #27): no CPU-wide perf events while any process
//! is protected (PERF_GUARD, set by fairplayd).
//!
//! A perf event on one process is checked against that process with
//! `ptrace_may_access`, so `ptrace_access_check` already refuses one on a
//! protected process (and records it there). A CPU-wide event (`pid ==
//! -1`, or a cgroup event) names no process and gets no such check, yet
//! with `PERF_SAMPLE_REGS_USER` and `PERF_SAMPLE_STACK_USER` it copies the
//! registers and user stack of whatever runs on that CPU: the game too.
//! The kernel asks this hook with type `PERF_SECURITY_CPU` for exactly
//! those events, after `perf_event_paranoid` has already turned away
//! anyone without `CAP_PERFMON`. So while PERF_GUARD is set, every such
//! request from a user-space process is denied and recorded (target 0;
//! fairplayd files it under every running session). Per-process events on
//! unprotected processes are untouched, and so are the kernel's own
//! counters (the hard-lockup watchdog), made from kernel threads.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel},
    macros::lsm,
    programs::LsmContext,
};
use core::ptr::addr_of;
use fairplay_common::{Hook, PERF_SECURITY_CPU};

use crate::{
    domain::{record_in, Name, EPERM},
    maps::PERF_GUARD,
    vmlinux::{perf_event_attr, task_struct},
};

/// `PF_KTHREAD` (`<linux/sched.h>`).
const PF_KTHREAD: u32 = 0x0020_0000;

#[lsm(hook = "perf_event_open")]
pub fn perf_event_open(ctx: LsmContext) -> i32 {
    // int perf_event_open(struct perf_event_attr *attr, int type)
    // For BPF LSM, arg 2 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(2) };
    if prev != 0 {
        return prev;
    }
    match should_deny(&ctx) {
        Ok(true) => -EPERM,
        _ => 0,
    }
}

fn should_deny(ctx: &LsmContext) -> Result<bool, i64> {
    let kind: u32 = unsafe { ctx.arg(1) };
    if kind != PERF_SECURITY_CPU || !PERF_GUARD.get(0).is_some_and(|&on| on != 0) {
        return Ok(false);
    }
    let flags = unsafe {
        let task = bpf_get_current_task() as *const task_struct;
        bpf_probe_read_kernel(addr_of!((*task).flags))?
    };
    if flags & PF_KTHREAD != 0 {
        return Ok(false);
    }
    let attr: *const perf_event_attr = unsafe { ctx.arg(0) };
    let event_type = unsafe { bpf_probe_read_kernel(addr_of!((*attr).type_)) }.unwrap_or(0);
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    record_in(caller, 0, 0, Hook::PerfCpu, event_type, 0, Name::None);
    Ok(true)
}
