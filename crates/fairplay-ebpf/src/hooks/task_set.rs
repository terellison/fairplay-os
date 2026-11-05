//! `task_setrlimit`, `task_setnice`, `task_setscheduler`, `task_setioprio`
//! (milestone 6 follow-ups, issue #27): while fairplayd protects itself, no
//! other process may change its resource limits, nice value, scheduling
//! policy, priority or CPU affinity, or I/O priority. Each is a way to stop
//! it without a signal: `RLIMIT_CPU` has the kernel send SIGXCPU and
//! SIGKILL itself, which `task_kill` doesn't see, and SCHED_IDLE or a
//! single busy CPU leave it too slow to answer. fairplayd may still change
//! its own.
//!
//! These hooks run in the syscall (or `/proc` write) of the process asking,
//! so a denial is always someone asking. `setpriority(PRIO_USER, ...)` and
//! `ioprio_set` for a whole user or process group get the error for
//! fairplayd and still change the others.

use aya_ebpf::{macros::lsm, programs::LsmContext};
use fairplay_common::Hook;

use crate::self_protect::guard_task;

#[lsm(hook = "task_setrlimit")]
pub fn task_setrlimit(ctx: LsmContext) -> i32 {
    // int task_setrlimit(struct task_struct *p, unsigned int resource,
    //                    struct rlimit *new_rlim)
    // For BPF LSM, arg 3 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(3) };
    if prev != 0 {
        return prev;
    }
    let resource: u32 = unsafe { ctx.arg(1) };
    guard_task(unsafe { ctx.arg(0) }, Hook::TaskSetrlimit, resource)
}

#[lsm(hook = "task_setnice")]
pub fn task_setnice(ctx: LsmContext) -> i32 {
    // int task_setnice(struct task_struct *p, int nice)
    let prev: i32 = unsafe { ctx.arg(2) };
    if prev != 0 {
        return prev;
    }
    let nice: i32 = unsafe { ctx.arg(1) };
    guard_task(unsafe { ctx.arg(0) }, Hook::TaskSetnice, nice as u32)
}

#[lsm(hook = "task_setscheduler")]
pub fn task_setscheduler(ctx: LsmContext) -> i32 {
    // int task_setscheduler(struct task_struct *p)
    // Called for sched_setscheduler/sched_setparam/sched_setattr,
    // sched_setaffinity, /proc/<pid>/timerslack_ns, and for each task
    // moved into a cpuset cgroup.
    let prev: i32 = unsafe { ctx.arg(1) };
    if prev != 0 {
        return prev;
    }
    guard_task(unsafe { ctx.arg(0) }, Hook::TaskSetscheduler, 0)
}

#[lsm(hook = "task_setioprio")]
pub fn task_setioprio(ctx: LsmContext) -> i32 {
    // int task_setioprio(struct task_struct *p, int ioprio)
    let prev: i32 = unsafe { ctx.arg(2) };
    if prev != 0 {
        return prev;
    }
    let ioprio: i32 = unsafe { ctx.arg(1) };
    guard_task(unsafe { ctx.arg(0) }, Hook::TaskSetioprio, ioprio as u32)
}
