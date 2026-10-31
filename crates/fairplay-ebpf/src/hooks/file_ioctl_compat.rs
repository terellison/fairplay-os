//! `file_ioctl_compat` (Linux 6.8+): the same check as `file_ioctl` for
//! 32-bit callers, which reach uinput through its compat ioctl handler.

use aya_ebpf::{macros::lsm, programs::LsmContext};

use crate::{input::ioctl_verdict, vmlinux::file};

#[lsm(hook = "file_ioctl_compat")]
pub fn file_ioctl_compat(ctx: LsmContext) -> i32 {
    // int file_ioctl_compat(struct file *file, unsigned int cmd,
    //                       unsigned long arg)
    // For BPF LSM, arg 3 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(3) };
    if prev != 0 {
        return prev;
    }
    let f: *const file = unsafe { ctx.arg(0) };
    let cmd: u32 = unsafe { ctx.arg(1) };
    ioctl_verdict(f, cmd)
}
