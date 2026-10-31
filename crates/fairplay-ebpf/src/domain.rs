//! Decisions and bookkeeping every hook shares: whether the current task may
//! touch a protected process, and recording a denied attempt.

use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_probe_read_kernel, gen::bpf_probe_read_kernel_str,
    },
};
use core::ptr::addr_of;
use fairplay_common::{Hook, Violation, EXE_NAME_LEN};

use crate::{
    maps::{PROTECTED, VIOLATIONS},
    vmlinux::{
        dentry, file, inode, kuid_t, mm_struct, path, qstr, super_block, task_struct,
        vm_area_struct,
    },
};

// Field accessors (task_mm, mm_exe_file, file_path, ...): see build.rs.
include!(concat!(env!("OUT_DIR"), "/fields.rs"));

pub const EPERM: i32 = 1;

/// The current task's tgid if it must be kept away from `target` (a tgid),
/// `None` if normal kernel rules apply: the target is not protected, the
/// caller is the target itself, or the caller is in the target's protection
/// domain (the game and its own anti-cheat).
pub fn denied_caller(target: u32) -> Option<u32> {
    let domain = unsafe { PROTECTED.get(&target) }?;
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    if caller == target {
        return None;
    }
    if let Some(caller_domain) = unsafe { PROTECTED.get(&caller) } {
        if caller_domain == domain {
            return None;
        }
    }
    Some(caller)
}

/// Writes a [`Violation`] for the current task to VIOLATIONS. Drops it if the
/// ring buffer is full.
pub fn record_violation(caller: u32, target: u32, hook: Hook, mode: u32) {
    record_violation_on_file(caller, target, hook, mode, core::ptr::null());
}

/// [`record_violation`] for a file hook: also names the file (`file` may be
/// null).
pub fn record_violation_on_file(
    caller: u32,
    target: u32,
    hook: Hook,
    mode: u32,
    file: *const file,
) {
    let Some(mut entry) = VIOLATIONS.reserve::<Violation>(0) else {
        return;
    };
    // Filled in place: a Violation plus two name buffers on the BPF stack
    // would crowd its 512 bytes.
    let v = entry.as_mut_ptr();
    unsafe {
        (*v).caller = caller;
        (*v).target = target;
        (*v).hook = hook as u32;
        (*v).mode = mode;
        (*v).comm = bpf_get_current_comm().unwrap_or([0; 16]);
        (*v).exe = [0; EXE_NAME_LEN];
        (*v).file = [0; EXE_NAME_LEN];
        let _ = current_exe_name(&mut (*v).exe);
        if !file.is_null() {
            let _ = file_name(file, &mut (*v).file);
        }
    }
    entry.submit(0);
}

/// The file name of the current task's executable
/// (`current->mm->exe_file->f_path.dentry->d_name`), read here because a
/// short-lived caller is usually gone by the time user space could look at
/// `/proc/<pid>/exe`. Leaves `out` zeroed on failure (e.g. kernel threads).
fn current_exe_name(out: &mut [u8; EXE_NAME_LEN]) -> Result<(), i64> {
    unsafe {
        let task = bpf_get_current_task() as *const task_struct;
        let mm: *const mm_struct = bpf_probe_read_kernel(task_mm(task))?;
        if mm.is_null() {
            return Ok(());
        }
        let exe: *const file = bpf_probe_read_kernel(mm_exe_file(mm))?;
        if exe.is_null() {
            return Ok(());
        }
        file_name(exe, out)
    }
}

/// `file->f_path.dentry->d_name`, NUL-terminated, cut to fit `out`.
fn file_name(f: *const file, out: &mut [u8; EXE_NAME_LEN]) -> Result<(), i64> {
    unsafe {
        let dentry: *const dentry = bpf_probe_read_kernel(addr_of!((*file_path(f)).dentry))?;
        let name: *const u8 = bpf_probe_read_kernel(addr_of!((*dentry_name(dentry)).name))?;
        // Room for the NUL, so the result is always terminated.
        bpf_probe_read_kernel_str(
            out.as_mut_ptr() as *mut c_void,
            (EXE_NAME_LEN - 1) as u32,
            name as *const c_void,
        );
    }
    Ok(())
}
