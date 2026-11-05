//! `file_open` guards two kinds of `/proc` file opened for writing:
//!
//! - Milestone 9, part B: a sandboxed process (the vendor's anti-cheat) may
//!   read the game's memory but never write it, so it may not open any
//!   `/proc/<pid>/mem` (or `task/<tid>/mem`) for writing. Its seccomp
//!   filter already refuses `process_vm_writev` and `ptrace`; this is the
//!   path seccomp can't see. Reading `mem` and `maps` keeps working.
//! - Milestone 6 follow-ups (issue #27): while fairplayd protects itself,
//!   no other process may open its `oom_score_adj`, `oom_adj` or
//!   `autogroup` for writing (under `/proc/<pid>/`, `/proc/<tid>/` for any
//!   of its threads, or `task/<tid>/`). Raising its OOM score makes it the
//!   kernel's first victim when root fills memory, and the kernel's
//!   SIGKILL never passes `task_kill`; the autogroup nice value would
//!   starve it like `renice` does, and nothing else checks it against the
//!   target. fairplayd may still write its own.
//!
//! Writes to `/proc/<pid>/timerslack_ns` already go through
//! `task_setscheduler`.
//!
//! A procfs mounted in another pid namespace names its processes by that
//! namespace's numbers, so there a different process whose pid happens to
//! equal fairplayd's is guarded too. Harmless, and only while
//! self-protection is on.

use aya_ebpf::{helpers::bpf_probe_read_kernel, macros::lsm, programs::LsmContext};
use core::ptr::addr_of;
use fairplay_common::Hook;

use crate::{
    domain::{
        file_mode, file_path, name_is, on_procfs, parent, parse_pid, record_in,
        record_violation_on_file, sandboxed, short_name, Name, EPERM,
    },
    self_protect::{is_fairplayd, outsider},
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
    let sandboxed = sandboxed();
    let outsider = outsider();
    // Most opens on the machine: neither guard applies.
    if sandboxed.is_none() && outsider.is_none() {
        return Ok(false);
    }
    let mode = unsafe { bpf_probe_read_kernel(file_mode(f))? };
    if mode & FMODE_WRITE == 0 {
        return Ok(false);
    }
    let d: *const dentry = unsafe { bpf_probe_read_kernel(addr_of!((*file_path(f)).dentry))? };
    if !on_procfs(d)? {
        return Ok(false);
    }
    let name = short_name(d)?;
    if let Some((caller, domain)) = sandboxed {
        if name_is(&name, b"mem") {
            record_in(
                caller,
                0,
                domain,
                Hook::ProcMemWrite,
                mode,
                0,
                Name::File(f),
            );
            return Ok(true);
        }
    }
    let Some((caller, fairplayd)) = outsider else {
        return Ok(false);
    };
    if !(name_is(&name, b"oom_score_adj")
        || name_is(&name, b"oom_adj")
        || name_is(&name, b"autogroup"))
    {
        return Ok(false);
    }
    // /proc/<pid>/<name> or /proc/<pid>/task/<tid>/<name>: any of them
    // naming one of fairplayd's threads.
    let dir = parent(d)?;
    let up = parent(dir)?;
    let pid = if name_is(&short_name(up)?, b"task") {
        parse_pid(&short_name(parent(up)?)?)
    } else {
        parse_pid(&short_name(dir)?)
    };
    if !pid.is_some_and(|p| is_fairplayd(p, fairplayd)) {
        return Ok(false);
    }
    record_violation_on_file(caller, fairplayd, Hook::ProcTuneWrite, mode, f);
    Ok(true)
}
