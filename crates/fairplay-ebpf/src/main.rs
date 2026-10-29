//! Kernel side of the protected-process primitive (milestone 3).
//!
//! One LSM hook, `ptrace_access_check`, guards every way one process reads or
//! writes another's memory: ptrace attach, process_vm_readv/writev, and
//! /proc/<pid>/mem. If the target is registered in PROTECTED and the caller is
//! not in the same protection domain, the access is denied and logged.
//!
//! Needs `src/vmlinux.rs` for kernel struct layouts. Generate it on the VM:
//!     aya-tool generate task_struct > src/vmlinux.rs

#![no_std]
#![no_main]

#[allow(
    non_upper_case_globals,
    non_snake_case,
    non_camel_case_types,
    dead_code
)]
mod vmlinux;

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{lsm, map},
    maps::{HashMap, RingBuf},
    programs::LsmContext,
};
use fairplay_common::{Hook, Violation};
use vmlinux::task_struct;

const EPERM: i32 = 1;

/// tgid of a protected process -> its protection-domain id.
/// Written only by fairplayd.
#[map]
static PROTECTED: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

/// Denied attempts, read by fairplayd and streamed to vendors.
#[map]
static VIOLATIONS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

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

    let target = unsafe { bpf_probe_read_kernel(&(*child).tgid)? } as u32;
    let Some(&domain) = (unsafe { PROTECTED.get(&target) }) else {
        return Ok(false); // not protected: normal kernel rules apply
    };

    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    if caller == target {
        return Ok(false);
    }
    if let Some(&caller_domain) = unsafe { PROTECTED.get(&caller) } {
        if caller_domain == domain {
            return Ok(false); // the game and its own anti-cheat
        }
    }

    if let Some(mut entry) = VIOLATIONS.reserve::<Violation>(0) {
        let comm = bpf_get_current_comm().unwrap_or([0; 16]);
        entry.write(Violation {
            caller,
            target,
            hook: Hook::PtraceAccess as u32,
            mode,
            comm,
        });
        entry.submit(0);
    }
    Ok(true)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
