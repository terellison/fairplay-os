//! `ptrace_access_check` guards every way one process reads or writes
//! another's memory: ptrace attach, process_vm_readv/writev, and
//! /proc/<pid>/mem. If the target is protected (see `task_domain`) and the
//! caller is not in the same protection domain, the access is denied and
//! logged.

use aya_ebpf::{macros::lsm, programs::LsmContext};
use fairplay_common::Hook;

use crate::{
    domain::{denied_caller_in, record_violation, task_domain, EPERM},
    vmlinux::task_struct,
};

/// The verdict is built here, not inside a `Result`: packing an `i32` into
/// `Result<i32, i64>` loses its sign for the verifier, which then can't prove
/// R0 is in [-4095, 0] and rejects the program.
#[lsm(hook = "ptrace_access_check")]
pub fn ptrace_access_check(ctx: LsmContext) -> i32 {
    // int ptrace_access_check(struct task_struct *child, unsigned int mode)
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

/// True if the caller must not touch the target's memory. Records the attempt.
fn should_deny(ctx: &LsmContext) -> Result<bool, i64> {
    let child: *const task_struct = unsafe { ctx.arg(0) };
    let mode: u32 = unsafe { ctx.arg(1) };

    let Some((target, domain)) = task_domain(child)? else {
        return Ok(false);
    };
    let Some(caller) = denied_caller_in(target, domain) else {
        return Ok(false);
    };
    record_violation(caller, target, Hook::PtraceAccess, mode);
    Ok(true)
}
