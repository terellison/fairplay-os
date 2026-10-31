//! `file_ioctl` sees every ioctl. `UI_DEV_CREATE` on `/dev/uinput` creates a
//! virtual input device; it is reported (or, if a session asked for it,
//! denied) with its creator, see `input`. Every other ioctl costs one
//! comparison.

use aya_ebpf::{macros::lsm, programs::LsmContext};

use crate::{input::ioctl_verdict, vmlinux::file};

#[lsm(hook = "file_ioctl")]
pub fn file_ioctl(ctx: LsmContext) -> i32 {
    // int file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
    // For BPF LSM, arg 3 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(3) };
    if prev != 0 {
        return prev;
    }
    let f: *const file = unsafe { ctx.arg(0) };
    let cmd: u32 = unsafe { ctx.arg(1) };
    ioctl_verdict(f, cmd)
}
