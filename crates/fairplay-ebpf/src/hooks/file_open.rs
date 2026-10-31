//! `file_open` (milestone 9, part B): a sandboxed process (the vendor's
//! anti-cheat) may read the game's memory but never write it, so it may not
//! open any `/proc/<pid>/mem` (or `task/<tid>/mem`) for writing. Its
//! seccomp filter already refuses `process_vm_writev` and `ptrace`; this
//! is the path seccomp can't see. Reading `mem` and `maps` keeps working.

use aya_ebpf::{helpers::bpf_probe_read_kernel, macros::lsm, programs::LsmContext};
use core::ptr::addr_of;
use fairplay_common::Hook;

use crate::{
    domain::{
        file_mode, file_path, name_is, on_procfs, record_in, sandboxed, short_name, Name, EPERM,
    },
    vmlinux::{dentry, file},
};

/// `FMODE_WRITE` (`<linux/fs.h>`).
const FMODE_WRITE: u32 = 0x2;

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    // int file_open(struct file *file)
    // For BPF LSM, arg 1 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(1) };
    if prev != 0 {
        return prev;
    }
    match should_deny(unsafe { ctx.arg(0) }) {
        Ok(true) => -EPERM,
        _ => 0,
    }
}

fn should_deny(f: *const file) -> Result<bool, i64> {
    let Some((caller, domain)) = sandboxed() else {
        return Ok(false);
    };
    let mode = unsafe { bpf_probe_read_kernel(file_mode(f))? };
    if mode & FMODE_WRITE == 0 {
        return Ok(false);
    }
    let d: *const dentry = unsafe { bpf_probe_read_kernel(addr_of!((*file_path(f)).dentry))? };
    if !on_procfs(d)? || !name_is(&short_name(d)?, b"mem") {
        return Ok(false);
    }
    record_in(
        caller,
        0,
        domain,
        Hook::ProcMemWrite,
        mode,
        0,
        Name::File(f),
    );
    Ok(true)
}
