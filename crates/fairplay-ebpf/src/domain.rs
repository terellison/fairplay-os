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
    vmlinux::{dentry, file, mm_struct, path, qstr, task_struct},
};

// task_mm, mm_exe_file, file_path, dentry_name: see build.rs.
include!(concat!(env!("OUT_DIR"), "/fields.rs"));

pub const EPERM: i32 = 1;

/// The current task's tgid if it must be kept away from `target` (a tgid),
/// `None` if normal kernel rules apply: the target is not protected, the
/// caller is the target itself, or the caller is in the target's protection
/// domain (the game and its own anti-cheat).
#[allow(dead_code)] // for hooks that only have the target's tgid
pub fn denied_caller(target: u32) -> Option<u32> {
    let domain = *unsafe { PROTECTED.get(&target) }?;
    denied_caller_in(target, domain)
}

/// [`denied_caller`] for a target already known to be in `domain` (see
/// [`task_domain`]).
pub fn denied_caller_in(target: u32, domain: u32) -> Option<u32> {
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    if caller == target {
        return None;
    }
    if let Some(&caller_domain) = unsafe { PROTECTED.get(&caller) } {
        if caller_domain == domain {
            return None;
        }
    }
    Some(caller)
}

/// `task`'s tgid and protection domain, if it is protected: its own
/// PROTECTED entry or, failing that, its parent's. A child of a protected
/// process is visible in /proc (with a copy of the parent's memory) a moment
/// before `follow` registers it; this covers that gap. It also keeps direct
/// children protected if PROTECTED was too full to register them.
pub fn task_domain(task: *const task_struct) -> Result<Option<(u32, u32)>, i64> {
    let tgid = unsafe { bpf_probe_read_kernel(addr_of!((*task).tgid))? } as u32;
    if let Some(&domain) = unsafe { PROTECTED.get(&tgid) } {
        return Ok(Some((tgid, domain)));
    }
    let parent_tgid = unsafe {
        let parent: *const task_struct = bpf_probe_read_kernel(addr_of!((*task).real_parent))?;
        bpf_probe_read_kernel(addr_of!((*parent).tgid))?
    } as u32;
    Ok(unsafe { PROTECTED.get(&parent_tgid) }.map(|&domain| (tgid, domain)))
}

/// Writes a [`Violation`] for the current task to VIOLATIONS. Drops it if the
/// ring buffer is full.
pub fn record_violation(caller: u32, target: u32, hook: Hook, mode: u32) {
    if let Some(mut entry) = VIOLATIONS.reserve::<Violation>(0) {
        let comm = bpf_get_current_comm().unwrap_or([0; 16]);
        let mut exe = [0u8; EXE_NAME_LEN];
        let _ = current_exe_name(&mut exe);
        // Lets fairplayd file an attempt on any process the game started
        // under the game's session. 0 if the target is no longer in the map.
        let domain = unsafe { PROTECTED.get(&target) }.copied().unwrap_or(0);
        entry.write(Violation {
            caller,
            target,
            domain,
            hook: hook as u32,
            mode,
            comm,
            exe,
        });
        entry.submit(0);
    }
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
        let dentry: *const dentry = bpf_probe_read_kernel(addr_of!((*file_path(exe)).dentry))?;
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
