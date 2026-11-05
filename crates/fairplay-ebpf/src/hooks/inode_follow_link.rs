//! `inode_follow_link` (milestone 9, part B): no way out of the sandbox
//! through `/proc` magic links. `/proc/<pid>/root`, `cwd` and `exe`, and
//! `fd/N` and `map_files/*` (also under `task/<tid>/`), resolve straight to
//! the process's own view of the file system or its open files, whatever
//! mount namespace the follower is in. Wine keeps a directory fd for its
//! Z: drive, which is `/`. So a sandboxed process may follow these links
//! only for itself and the other processes of its sandbox; for anything
//! else (the game included) it is denied and recorded. Reading the link
//! (`readlink`: just the path as text) and `fdinfo` still work.
//!
//! The hook runs for every symlink the kernel follows; for anyone not
//! sandboxed it costs one map lookup.

use aya_ebpf::{helpers::bpf_probe_read_kernel, macros::lsm, programs::LsmContext};
use core::ptr::addr_of;
use fairplay_common::Hook;

use crate::{
    domain::{
        dentry_name, name_is, on_procfs, parent, parse_pid, record_in, sandboxed, sandboxed_in,
        short_name, Name, EPERM,
    },
    vmlinux::dentry,
};

#[lsm(hook = "inode_follow_link")]
pub fn inode_follow_link(ctx: LsmContext) -> i32 {
    // int inode_follow_link(struct dentry *dentry, struct inode *inode, bool rcu)
    // For BPF LSM, arg 3 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(3) };
    if prev != 0 {
        return prev;
    }
    match should_deny(unsafe { ctx.arg(0) }) {
        Ok(true) => -EPERM,
        _ => 0,
    }
}

fn should_deny(link: *const dentry) -> Result<bool, i64> {
    let Some((caller, domain)) = sandboxed() else {
        return Ok(false);
    };
    if !on_procfs(link)? {
        return Ok(false);
    }
    let name = short_name(link)?;
    let dir = parent(link)?;
    // The /proc/<pid> (or task/<tid>) directory the link belongs to.
    let piddir = if name_is(&name, b"root") || name_is(&name, b"cwd") || name_is(&name, b"exe") {
        dir
    } else {
        let dname = short_name(dir)?;
        if !name_is(&dname, b"fd") && !name_is(&dname, b"map_files") {
            return Ok(false);
        }
        parent(dir)?
    };
    // /proc/<pid>/task/<tid>/...: judge by <pid>.
    let up = parent(piddir)?;
    let piddir = if name_is(&short_name(up)?, b"task") {
        parent(up)?
    } else {
        piddir
    };
    let target = parse_pid(&short_name(piddir)?);
    if let Some(pid) = target {
        if pid == caller || sandboxed_in(pid, domain) {
            return Ok(false);
        }
    }
    // Not a pid we can name (a renamed or odd /proc layout): deny anyway.
    let link_name: *const u8 =
        unsafe { bpf_probe_read_kernel(addr_of!((*dentry_name(link)).name))? };
    record_in(
        caller,
        target.unwrap_or(0),
        domain,
        Hook::ProcLink,
        0,
        0,
        Name::Str(link_name),
    );
    Ok(true)
}
