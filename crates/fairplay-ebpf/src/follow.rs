//! Keeps the protection domain in step with the game's process tree, in the
//! kernel, so no process the game starts is ever outside it (milestone 5).
//! Proton games are a chain of processes (proton, wine, `game.exe`, plus
//! `wineserver`), and fairplayd only launches the first.
//!
//! These are tracing programs (`tp_btf`), not LSM hooks: they decide
//! nothing, they only maintain PROTECTED. fairplayd attaches them from its
//! `TRACING_PROGRAMS` list.
//!
//! - **fork**: `sched_process_fork` fires in the parent's `kernel_clone`,
//!   after `copy_process` and before `wake_up_new_task`, so the child is in
//!   PROTECTED before it runs a single instruction. Its PID is visible in
//!   /proc a moment earlier (from the end of `copy_process`);
//!   `domain::task_domain` covers that gap by treating a not-yet-registered
//!   child of a protected process as protected. A reader's child is a
//!   protected member only: reader status is never inherited (`readers`).
//! - **exit**: `sched_process_exit` fires in `do_exit` for each exiting
//!   thread. When the last thread of a process exits, its entries go
//!   (PROTECTED, and READERS if it was a reader). That
//!   is before the process is reaped, so before its PID can be reused: an
//!   unrelated process that gets the PID later never inherits the domain.

use aya_ebpf::{
    helpers::bpf_probe_read_kernel, macros::btf_tracepoint, programs::BtfTracePointContext,
};
use core::ptr::addr_of;

use crate::{
    maps::{PROTECTED, READERS, UNFOLLOWED},
    vmlinux::{signal_struct, task_struct},
};

/// `TP_PROTO(struct task_struct *parent, struct task_struct *child)`;
/// `parent` is the task that called fork (`current`).
#[btf_tracepoint(function = "sched_process_fork")]
pub fn follow_fork(ctx: BtfTracePointContext) -> i32 {
    let parent: *const task_struct = unsafe { ctx.arg(0) };
    let child: *const task_struct = unsafe { ctx.arg(1) };
    let _ = try_follow_fork(parent, child);
    0
}

fn try_follow_fork(parent: *const task_struct, child: *const task_struct) -> Result<(), i64> {
    let (pid, tgid) = unsafe {
        (
            bpf_probe_read_kernel(addr_of!((*child).pid))?,
            bpf_probe_read_kernel(addr_of!((*child).tgid))?,
        )
    };
    // A new thread: its process is already covered by its tgid.
    if pid != tgid {
        return Ok(());
    }
    let parent_tgid = unsafe { bpf_probe_read_kernel(addr_of!((*parent).tgid))? } as u32;
    let Some(&domain) = (unsafe { PROTECTED.get(&parent_tgid) }) else {
        return Ok(());
    };
    if PROTECTED.insert(&(tgid as u32), &domain, 0).is_err() {
        note_unfollowed(domain);
    }
    Ok(())
}

/// The child runs unprotected. Don't fail open silently: count it for the
/// domain, so `session_status` can say protection is degraded. Not atomic
/// (core has no atomic add for the BPF target): two CPUs counting at once
/// can lose a count, never the nonzero that means "degraded".
fn note_unfollowed(domain: u32) {
    match UNFOLLOWED.get_ptr_mut(&domain) {
        // SAFETY: a map value pointer stays valid while the program runs.
        Some(n) => unsafe { *n = (*n).saturating_add(1) },
        None => {
            let _ = UNFOLLOWED.insert(&domain, &1, 0);
        }
    }
}

/// `TP_PROTO(struct task_struct *p, ...)`; `p` is the exiting thread.
#[btf_tracepoint(function = "sched_process_exit")]
pub fn unfollow_exit(ctx: BtfTracePointContext) -> i32 {
    let task: *const task_struct = unsafe { ctx.arg(0) };
    let _ = try_unfollow_exit(task);
    0
}

fn try_unfollow_exit(task: *const task_struct) -> Result<(), i64> {
    let tgid = unsafe { bpf_probe_read_kernel(addr_of!((*task).tgid))? } as u32;
    // Most exits on the machine are not protected processes. (Readers are
    // always in PROTECTED too.)
    if unsafe { PROTECTED.get(&tgid) }.is_none() && unsafe { READERS.get(&tgid) }.is_none() {
        return Ok(());
    }
    // do_exit decrements signal->live before this tracepoint, so it reads 0
    // once every thread of the process has started exiting. (Two threads
    // can both see 0; removing twice is harmless.)
    let live = unsafe {
        let signal: *const signal_struct = bpf_probe_read_kernel(addr_of!((*task).signal))?;
        bpf_probe_read_kernel(addr_of!((*signal).live.counter))?
    };
    if live == 0 {
        let _ = PROTECTED.remove(&tgid);
        let _ = READERS.remove(&tgid);
    }
    Ok(())
}
