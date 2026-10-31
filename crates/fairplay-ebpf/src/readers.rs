//! Readers (milestone 9): the only processes besides a protected process
//! itself that may read its memory.
//!
//! A protected process becomes a reader of its domain when it execs a file
//! in READER_FILES for that domain: the files the game's manifest names as
//! readers (`anti_cheat`, `runtime_helper` such as Proton's `wineserver`),
//! identified by inode like the executable-mapping allowlist, and put there
//! by fairplayd after checking their hashes. Exec of any other file ends
//! reader status: a reader that execs `/bin/sh` is a plain protected member.
//! Reader status is never inherited on fork (`follow` only adds PROTECTED
//! entries), so being started *by* a reader is not enough either.
//!
//! `sched_process_exec` fires in `exec_binprm` after the new program is
//! loaded and before it returns to user space, so no instruction of the new
//! program runs with the old program's reader status, or without its own.

use aya_ebpf::{
    helpers::bpf_probe_read_kernel, macros::btf_tracepoint, macros::map, maps::HashMap,
    programs::BtfTracePointContext,
};
use core::ptr::addr_of;
use fairplay_common::{ExecAllow, ExecKey, READER_FILES_CAPACITY};

use crate::{
    domain::bprm_file,
    exec_allow::FileIdentity,
    maps::{PROTECTED, READERS},
    vmlinux::{file, linux_binprm, task_struct},
};

/// Files whose exec makes a protected process a reader of the domain in
/// the key. Written only by fairplayd.
#[map]
pub static READER_FILES: HashMap<ExecKey, ExecAllow> =
    HashMap::with_max_entries(READER_FILES_CAPACITY, 0);

/// `TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)`;
/// `p` is the task that exec'd (`current`).
#[btf_tracepoint(function = "sched_process_exec")]
pub fn reader_exec(ctx: BtfTracePointContext) -> i32 {
    let task: *const task_struct = unsafe { ctx.arg(0) };
    let bprm: *const linux_binprm = unsafe { ctx.arg(2) };
    let _ = try_reader_exec(task, bprm);
    0
}

fn try_reader_exec(task: *const task_struct, bprm: *const linux_binprm) -> Result<(), i64> {
    // After exec the task is its process's leader, so pid == tgid.
    let tgid = unsafe { bpf_probe_read_kernel(addr_of!((*task).tgid))? } as u32;
    // Most execs on the machine are not protected processes.
    let Some(&domain) = (unsafe { PROTECTED.get(&tgid) }) else {
        return Ok(());
    };
    // `bprm->file` is what was actually loaded: for a script, its
    // interpreter.
    let f: *const file = unsafe { bpf_probe_read_kernel(bprm_file(bprm))? };
    let reader = !f.is_null()
        && matches!(FileIdentity::of(f), Ok(Some(id)) if id.listed(&READER_FILES, domain));
    if reader {
        // Fails only if READERS is full: then it stays a plain member,
        // which fails closed (it can't read the game).
        let _ = READERS.insert(&tgid, &domain, 0);
    } else {
        let _ = READERS.remove(&tgid);
    }
    Ok(())
}
