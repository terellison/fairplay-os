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
    maps::{PROTECTED, READERS, SANDBOXED, VIOLATIONS},
    vmlinux::{
        bpf_map, bpf_prog, bpf_prog_aux, dentry, file, inode, kuid_t, linux_binprm, mm_struct,
        path, qstr, super_block, task_struct, vm_area_struct,
    },
};

// Field accessors (task_mm, mm_exe_file, file_path, ...): see build.rs.
include!(concat!(env!("OUT_DIR"), "/fields.rs"));

pub const EPERM: i32 = 1;
pub const EACCES: i32 = 13;

/// The current task's tgid if it must be kept away from `target` (a tgid),
/// `None` if normal kernel rules apply: the target is not protected, the
/// caller is the target itself, or the caller is one of the target domain's
/// readers (the vendor's anti-cheat, `wineserver`).
#[allow(dead_code)] // for hooks that only have the target's tgid
pub fn denied_caller(target: u32) -> Option<u32> {
    let domain = *unsafe { PROTECTED.get(&target) }?;
    denied_caller_in(target, domain)
}

/// `(caller, domain)` if the current task is sandboxed (milestone 9, part
/// B: the vendor's anti-cheat or something it started).
#[inline(always)]
pub fn sandboxed() -> Option<(u32, u32)> {
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    let domain = *unsafe { SANDBOXED.get(&caller) }?;
    Some((caller, domain))
}

/// Is `tgid` a sandboxed process of `domain`?
#[inline(always)]
pub fn sandboxed_in(tgid: u32, domain: u32) -> bool {
    unsafe { SANDBOXED.get(&tgid) }.is_some_and(|&d| d == domain)
}

/// [`denied_caller`] for a target already known to be in `domain` (see
/// [`task_domain`]). Being a protected member of the same domain is not
/// enough (milestone 9): the game's own processes can't read each other,
/// so a wrapper the player launched can't read the game it started.
pub fn denied_caller_in(target: u32, domain: u32) -> Option<u32> {
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    if caller == target {
        return None;
    }
    if let Some(&reader_domain) = unsafe { READERS.get(&caller) } {
        if reader_domain == domain {
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
    record(caller, target, hook, mode, 0, Name::None);
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
    record(caller, target, hook, mode, 0, Name::File(file));
}

/// What goes in [`Violation::file`].
pub enum Name {
    None,
    /// This file's name (may be null).
    File(*const file),
    /// A NUL-terminated kernel string (may be null).
    Str(*const u8),
}

/// The general form of [`record_violation`]: any `flags` (`VIOLATION_*`)
/// and any [`Name`].
#[inline(always)]
pub fn record(caller: u32, target: u32, hook: Hook, mode: u32, flags: u32, name: Name) {
    // Lets fairplayd file an attempt on any process the game started
    // under the game's session. 0 if the target is no longer in the map.
    let domain = unsafe { PROTECTED.get(&target) }.copied().unwrap_or(0);
    record_in(caller, target, domain, hook, mode, flags, name);
}

/// [`record`] filed under `domain`, which need not be the target's: a
/// protected caller reaching outside its domain (milestone 9) is filed
/// under its own.
#[inline(always)]
pub fn record_in(
    caller: u32,
    target: u32,
    domain: u32,
    hook: Hook,
    mode: u32,
    flags: u32,
    name: Name,
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
        (*v).domain = domain;
        (*v).hook = hook as u32;
        (*v).mode = mode;
        (*v).flags = flags;
        (*v).comm = bpf_get_current_comm().unwrap_or([0; 16]);
        (*v).exe = [0; EXE_NAME_LEN];
        (*v).file = [0; EXE_NAME_LEN];
        let _ = current_exe_name(&mut (*v).exe);
        match name {
            Name::File(f) if !f.is_null() => {
                let _ = file_name(f, &mut (*v).file);
            }
            Name::Str(s) if !s.is_null() => kernel_str(s, &mut (*v).file),
            _ => {}
        }
    }
    entry.submit(0);
}

/// The current task's executable (`current->mm->exe_file`), or null for
/// kernel threads.
pub fn current_exe() -> Result<*const file, i64> {
    unsafe {
        let task = bpf_get_current_task() as *const task_struct;
        let mm: *const mm_struct = bpf_probe_read_kernel(task_mm(task))?;
        if mm.is_null() {
            return Ok(core::ptr::null());
        }
        let exe: *mut file = bpf_probe_read_kernel(mm_exe_file(mm))?;
        Ok(exe)
    }
}

/// The file name of the current task's executable
/// (`current->mm->exe_file->f_path.dentry->d_name`), read here because a
/// short-lived caller is usually gone by the time user space could look at
/// `/proc/<pid>/exe`. Leaves `out` zeroed on failure (e.g. kernel threads).
fn current_exe_name(out: &mut [u8; EXE_NAME_LEN]) -> Result<(), i64> {
    let exe = current_exe()?;
    if exe.is_null() {
        return Ok(());
    }
    file_name(exe, out)
}

/// `file->f_path.dentry->d_name`, NUL-terminated, cut to fit `out`.
fn file_name(f: *const file, out: &mut [u8; EXE_NAME_LEN]) -> Result<(), i64> {
    unsafe {
        let dentry: *const dentry = bpf_probe_read_kernel(addr_of!((*file_path(f)).dentry))?;
        let name: *const u8 = bpf_probe_read_kernel(addr_of!((*dentry_name(dentry)).name))?;
        kernel_str(name, out);
    }
    Ok(())
}

/// Copies a NUL-terminated kernel string into `out`, cut to fit and always
/// terminated.
fn kernel_str(s: *const u8, out: &mut [u8; EXE_NAME_LEN]) {
    unsafe {
        bpf_probe_read_kernel_str(
            out.as_mut_ptr() as *mut c_void,
            (EXE_NAME_LEN - 1) as u32,
            s as *const c_void,
        );
    }
}

/// The first 15 bytes of a dentry's name, NUL-padded (enough to compare
/// against `/proc` entry names and to parse a pid).
#[inline(always)]
pub fn short_name(d: *const dentry) -> Result<[u8; 16], i64> {
    let mut out = [0u8; 16];
    unsafe {
        let name: *const u8 = bpf_probe_read_kernel(addr_of!((*dentry_name(d)).name))?;
        bpf_probe_read_kernel_str(out.as_mut_ptr() as *mut c_void, 15, name as *const c_void);
    }
    Ok(out)
}

/// Is `d` on a procfs (`PROC_SUPER_MAGIC`)?
#[inline(always)]
pub fn on_procfs(d: *const dentry) -> Result<bool, i64> {
    const PROC_SUPER_MAGIC: u64 = 0x9fa0;
    unsafe {
        let sb: *const super_block = bpf_probe_read_kernel(dentry_sb(d))?;
        let magic = bpf_probe_read_kernel(sb_magic(sb))? as u64;
        Ok(magic == PROC_SUPER_MAGIC)
    }
}

/// `name` (NUL-padded) equals `want` exactly.
#[inline(always)]
pub fn name_is(name: &[u8; 16], want: &[u8]) -> bool {
    let n = want.len();
    n < 16 && name[n] == 0 && name[..n] == *want
}

/// `d->d_parent`.
#[inline(always)]
pub fn parent(d: *const dentry) -> Result<*const dentry, i64> {
    unsafe { bpf_probe_read_kernel(dentry_parent(d)) }.map(|p| p as *const dentry)
}

/// A decimal pid, or `None` if the name isn't one.
pub fn parse_pid(name: &[u8; 16]) -> Option<u32> {
    let mut pid: u32 = 0;
    let mut i = 0;
    while i < 10 {
        let c = name[i];
        if c == 0 {
            break;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        pid = pid.checked_mul(10)?.checked_add((c - b'0') as u32)?;
        i += 1;
    }
    (i > 0 && name[i] == 0).then_some(pid)
}
