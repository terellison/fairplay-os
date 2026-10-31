//! `ptrace_access_check` guards every way one process reads or writes
//! another's memory: ptrace attach, process_vm_readv/writev, and
//! /proc/<pid>/mem (and `pidfd_getfd`). If the target is protected (see
//! `task_domain`) and the caller is neither the target itself nor one of its
//! domain's readers (milestone 9, see `readers`), the
//! access is denied and logged.
//!
//! The rule also points outward (milestone 9, part B): a protected process
//! (the game, the vendor's anti-cheat, anything they start) may access only
//! processes of its own domain. Reaching any other process, even an
//! unprotected one of the same user such as the browser, is denied and
//! filed under the caller's own session. That keeps the anti-cheat to the
//! game it was started for. Kernel checks made on their own account
//! (`PTRACE_MODE_NOAUDIT`, e.g. which `/proc/<pid>/stat` fields `ps` may
//! see) are denied quietly.
//!
//! While fairplayd protects itself (milestone 6, see `self_protect`), it is
//! protected too, from every other process: nothing may trace it or read
//! its memory or file descriptors.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::lsm,
    programs::LsmContext,
};
use core::ptr::addr_of;
use fairplay_common::{Hook, PTRACE_MODE_NOAUDIT};

use crate::{
    domain::{denied_caller_in, record_in, record_violation, task_domain, Name, EPERM},
    maps::PROTECTED,
    self_protect::outsider,
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

    if let Some((caller, fairplayd)) = outsider() {
        let tgid = unsafe { bpf_probe_read_kernel(addr_of!((*child).tgid))? } as u32;
        if tgid == fairplayd {
            // NOAUDIT is the kernel asking on its own account (`ps` reading
            // /proc/<pid>/stat), not a request to access fairplayd: deny
            // quietly, or every `ps` would print a DENIED line.
            if mode & PTRACE_MODE_NOAUDIT == 0 {
                record_violation(caller, fairplayd, Hook::PtraceAccess, mode);
            }
            return Ok(true);
        }
    }

    let Some((target, domain)) = task_domain(child)? else {
        return outbound(child, mode);
    };
    let Some(caller) = denied_caller_in(target, domain) else {
        return Ok(false);
    };
    record_violation(caller, target, Hook::PtraceAccess, mode);
    Ok(true)
}

/// The target is not protected: deny (and record) only if the caller is,
/// since a protected process may not reach outside its domain.
fn outbound(child: *const task_struct, mode: u32) -> Result<bool, i64> {
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    let Some(&domain) = (unsafe { PROTECTED.get(&caller) }) else {
        return Ok(false);
    };
    let target = unsafe { bpf_probe_read_kernel(addr_of!((*child).tgid))? } as u32;
    if target == caller {
        return Ok(false);
    }
    if mode & PTRACE_MODE_NOAUDIT == 0 {
        record_in(
            caller,
            target,
            domain,
            Hook::PtraceAccess,
            mode,
            0,
            Name::None,
        );
    }
    Ok(true)
}
