//! `task_alloc` runs in `copy_process` for every new task, in the parent
//! (`current`). When a protected process starts a new process (not a
//! thread), its domain must have room under the member cap (issue #21, see
//! `members`); otherwise the fork fails with `EAGAIN`, the error
//! `RLIMIT_NPROC` gives, and is recorded (rate-limited).

use aya_ebpf::{helpers::bpf_get_current_pid_tgid, macros::lsm, programs::LsmContext};

use crate::{
    maps::PROTECTED,
    members::{self, Refused},
};

const EAGAIN: i32 = 11;
const CLONE_THREAD: u64 = 0x0001_0000;

#[lsm(hook = "task_alloc")]
pub fn task_alloc(ctx: LsmContext) -> i32 {
    // int task_alloc(struct task_struct *task, unsigned long clone_flags)
    // For BPF LSM, arg 2 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(2) };
    if prev != 0 {
        return prev;
    }
    let clone_flags: u64 = unsafe { ctx.arg(1) };
    if clone_flags & CLONE_THREAD != 0 {
        return 0;
    }
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    let Some(&domain) = (unsafe { PROTECTED.get(&caller) }) else {
        return 0;
    };
    let task: u64 = unsafe { ctx.arg(0) };
    match members::reserve(caller, domain, task) {
        Ok(()) => 0,
        Err(Refused::Cap | Refused::NoRoom) => -EAGAIN,
    }
}
