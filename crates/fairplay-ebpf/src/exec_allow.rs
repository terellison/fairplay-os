//! The executable-mapping allowlist (milestone 8), shared by the
//! `mmap_file` and `file_mprotect` hooks, and by `bprm_check_security`,
//! which applies it to `execve` before the point of no return.
//!
//! A protected process may map a file executable only if the file is
//! - on a system filesystem (EXEC_TRUSTED_FS = FS_SYSTEM), owned by root and
//!   not writable by group or others: the loader, libc, GPU user-space libs;
//! - on the kernel's internal shmem mount (FS_ANON): memfd and shared
//!   anonymous memory, treated like the anonymous memory JITs use;
//! - in EXEC_ALLOWED for the process's domain (the game's install directory,
//!   walked by fairplayd at launch) or for every domain (approved overlays).
//!
//! Files are identified by (superblock device, inode number), never by path:
//! a file created or replaced after launch has a new inode and isn't allowed.
//! Anonymous memory (no file) is never checked here.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::map,
    maps::HashMap,
};
use core::ptr::addr_of;
use fairplay_common::{
    ExecAllow, ExecKey, Hook, ANY_DOMAIN, EXEC_ALLOWED_CAPACITY, EXEC_CHECK_GENERATION, FS_ANON,
    FS_SYSTEM,
};

use crate::{
    domain::{
        bprm_buf, bprm_file, file_inode, inode_generation, inode_ino, inode_mode, inode_sb,
        inode_uid, record_violation_on_file, sb_dev, EACCES, EPERM,
    },
    maps::PROTECTED,
    vmlinux::{file, inode, linux_binprm, super_block},
};

/// Files a domain may map executable. Written only by fairplayd.
#[map]
pub static EXEC_ALLOWED: HashMap<ExecKey, ExecAllow> =
    HashMap::with_max_entries(EXEC_ALLOWED_CAPACITY, 0);

/// Kernel `s_dev` -> FS_SYSTEM or FS_ANON. Written only by fairplayd, at
/// startup.
#[map]
pub static EXEC_TRUSTED_FS: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

/// Group- or other-writable bits.
const S_IWGRP_IWOTH: u16 = 0o022;

/// The verdict for the current task mapping `file` executable (`prot` is
/// logged): 0 or -EPERM. Returns 0 at once if the current task isn't
/// protected, so unprotected processes pay one map lookup.
#[inline(always)]
pub fn exec_mapping_verdict(file: *const file, hook: Hook, prot: u32) -> i32 {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let Some(&domain) = (unsafe { PROTECTED.get(&tgid) }) else {
        return 0;
    };
    if file.is_null() {
        return 0;
    }
    // A protected process whose file we can't even read fails closed.
    if allowed(file, domain).unwrap_or(false) {
        return 0;
    }
    record_violation_on_file(tgid, tgid, hook, prot, file);
    -EPERM
}

/// The verdict for the current task exec'ing the file in `bprm`: 0 or
/// -EACCES. Only ELF files are checked: those are what the ELF loader maps
/// executable. A `#!` script (or a `binfmt_misc` format) isn't mapped; the
/// kernel comes back here with its interpreter, which is. Anything this
/// misses is still caught by `mmap_file`, just less cleanly.
#[inline(always)]
pub fn exec_verdict(bprm: *const linux_binprm) -> i32 {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let Some(&domain) = (unsafe { PROTECTED.get(&tgid) }) else {
        return 0;
    };
    // `bprm` comes from the kernel; if a read fails anyway, fail closed
    // like `exec_mapping_verdict`.
    let read = unsafe {
        bpf_probe_read_kernel(bprm_file(bprm)).and_then(|f| {
            bpf_probe_read_kernel(bprm_buf(bprm) as *const [u8; 4]).map(|magic| (f, magic))
        })
    };
    let f: *const file = match read {
        Ok((_, magic)) if magic != ELF_MAGIC => return 0,
        Ok((f, _)) if !f.is_null() && allowed(f, domain).unwrap_or(false) => return 0,
        Ok((f, _)) => f,
        Err(_) => core::ptr::null(),
    };
    record_violation_on_file(tgid, tgid, Hook::BprmCheck, 0, f);
    -EACCES
}

/// The first four bytes of every ELF file.
const ELF_MAGIC: [u8; 4] = *b"\x7fELF";

fn allowed(file: *const file, domain: u32) -> Result<bool, i64> {
    unsafe {
        let inode: *const inode = bpf_probe_read_kernel(file_inode(file))?;
        if inode.is_null() {
            return Ok(false);
        }
        let sb: *const super_block = bpf_probe_read_kernel(inode_sb(inode))?;
        let dev: u32 = bpf_probe_read_kernel(sb_dev(sb))?;
        match EXEC_TRUSTED_FS.get(&dev) {
            Some(&FS_ANON) => return Ok(true),
            Some(&FS_SYSTEM) => {
                let uid: u32 = bpf_probe_read_kernel(addr_of!((*inode_uid(inode)).val))?;
                let mode: u16 = bpf_probe_read_kernel(inode_mode(inode))?;
                if uid == 0 && mode & S_IWGRP_IWOTH == 0 {
                    return Ok(true);
                }
            }
            _ => {}
        }
        let (ino, generation) = inode_id(inode)?;
        Ok([domain, ANY_DOMAIN]
            .into_iter()
            .any(|d| listed(&EXEC_ALLOWED, d, dev, ino, generation)))
    }
}

/// `file`'s identity as the allowlist maps key it: (superblock device,
/// inode number, inode generation). Shared with the input allowlist.
#[inline(always)]
pub fn file_id(file: *const file) -> Result<(u32, u64, u32), i64> {
    unsafe {
        let inode: *const inode = bpf_probe_read_kernel(file_inode(file))?;
        if inode.is_null() {
            return Err(0);
        }
        let sb: *const super_block = bpf_probe_read_kernel(inode_sb(inode))?;
        let dev: u32 = bpf_probe_read_kernel(sb_dev(sb))?;
        let (ino, generation) = inode_id(inode)?;
        Ok((dev, ino, generation))
    }
}

#[inline(always)]
unsafe fn inode_id(inode: *const inode) -> Result<(u64, u32), i64> {
    unsafe {
        Ok((
            bpf_probe_read_kernel(inode_ino(inode))?,
            bpf_probe_read_kernel(inode_generation(inode))?,
        ))
    }
}

/// Whether `map` (EXEC_ALLOWED or INPUT_ALLOWED) has this file for
/// `domain`, with a matching generation if the entry recorded one.
#[inline(always)]
pub fn listed(
    map: &HashMap<ExecKey, ExecAllow>,
    domain: u32,
    dev: u32,
    ino: u64,
    generation: u32,
) -> bool {
    let key = ExecKey { domain, dev, ino };
    match unsafe { map.get(&key) } {
        Some(v) => v.flags & EXEC_CHECK_GENERATION == 0 || v.generation == generation,
        None => false,
    }
}
