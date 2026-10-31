//! `task_free` runs when a `task_struct` is freed: at the end of every
//! task's life, and when `copy_process` fails after `task_alloc`. In the
//! second case a fork that passed the member cap (issue #21) never
//! happened; give its place back (`members::abandoned`). Decides nothing.

use aya_ebpf::{macros::lsm, programs::LsmContext};

use crate::members;

#[lsm(hook = "task_free")]
pub fn task_free(ctx: LsmContext) -> i32 {
    // void task_free(struct task_struct *task)
    let task: u64 = unsafe { ctx.arg(0) };
    members::abandoned(task);
    0
}
