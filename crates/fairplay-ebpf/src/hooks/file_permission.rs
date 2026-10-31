//! `file_permission` runs on every read and write (`rw_verify_area`). A
//! write to `/dev/uhid` (the first one creates a virtual HID device) or to
//! an evdev node (`/dev/input/event*`, injecting events into a device) is
//! reported, once per open file and verdict. While a session blocks virtual
//! input, non-allowlisted writes there and on `/dev/uinput` fds (input
//! through a uinput device) are denied. See `input`. A read costs one bit
//! test; any other write, reading the inode's device number.

use aya_ebpf::{macros::lsm, programs::LsmContext};

use crate::{input::write_verdict, vmlinux::file};

#[lsm(hook = "file_permission")]
pub fn file_permission(ctx: LsmContext) -> i32 {
    // int file_permission(struct file *file, int mask)
    // For BPF LSM, arg 2 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(2) };
    if prev != 0 {
        return prev;
    }
    let f: *const file = unsafe { ctx.arg(0) };
    let mask: i32 = unsafe { ctx.arg(1) };
    write_verdict(f, mask)
}
