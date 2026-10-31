//! `task_kill` sees every signal one process sends another (`kill`,
//! `tgkill`, `pidfd_send_signal`, `sigqueue`). While fairplayd protects
//! itself, a signal to it from any other process is denied: SIGKILL and
//! SIGSTOP too, since the LSM check comes before the kernel delivers them.
//! Signal 0 (does it exist?) is allowed. Signals the kernel raises on its
//! own (SIGCHLD, SIGPIPE, a terminal's SIGINT) skip this hook.

use aya_ebpf::{helpers::bpf_probe_read_kernel, macros::lsm, programs::LsmContext};
use core::ptr::addr_of;
use fairplay_common::Hook;

use crate::{
    domain::{record_violation, EPERM},
    self_protect::outsider,
    vmlinux::task_struct,
};

#[lsm(hook = "task_kill")]
pub fn task_kill(ctx: LsmContext) -> i32 {
    // int task_kill(struct task_struct *p, struct kernel_siginfo *info,
    //               int sig, const struct cred *cred)
    // For BPF LSM, arg 4 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(4) };
    if prev != 0 {
        return prev;
    }
    match should_deny(&ctx) {
        Ok(true) => -EPERM,
        _ => 0,
    }
}

fn should_deny(ctx: &LsmContext) -> Result<bool, i64> {
    let sig: i32 = unsafe { ctx.arg(2) };
    if sig == 0 {
        return Ok(false);
    }
    let Some((caller, fairplayd)) = outsider() else {
        return Ok(false);
    };
    let p: *const task_struct = unsafe { ctx.arg(0) };
    // Any thread of fairplayd (tgkill names a thread).
    let tgid = unsafe { bpf_probe_read_kernel(addr_of!((*p).tgid))? } as u32;
    if tgid != fairplayd {
        return Ok(false);
    }
    record_violation(caller, fairplayd, Hook::TaskKill, sig as u32);
    Ok(true)
}
