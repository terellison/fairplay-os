//! `bprm_check_security` turns away an `execve` of a file a protected
//! process may not map executable (see `exec_allow`) before the point of no
//! return, so `execve` fails with EACCES and the caller carries on. Without
//! it the kernel would only find out in `mmap_file`, while loading the new
//! program after the old one is gone, and kill the process with SIGSEGV.
//! `mmap_file` still checks every mapping, as the backstop.
//!
//! Why this hook and not `bprm_creds_for_exec`: that one runs once per
//! `execve`, on the file named by the caller. This one runs for each file
//! the binfmt handlers try, in order: for `#!` scripts first the script and
//! then its interpreter, which is the file that actually gets mapped. Both
//! run before the point of no return (`begin_new_exec`).

use aya_ebpf::{macros::lsm, programs::LsmContext};

use crate::{exec_allow::exec_verdict, vmlinux::linux_binprm};

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    // int bprm_check_security(struct linux_binprm *bprm)
    // For BPF LSM, arg 1 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(1) };
    if prev != 0 {
        return prev;
    }
    let bprm: *const linux_binprm = unsafe { ctx.arg(0) };
    exec_verdict(bprm)
}
