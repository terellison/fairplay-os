//! `mmap_file` sees every `mmap` with a file behind it, including the ones
//! the kernel makes for `execve` (the program and its ELF interpreter) and
//! the ones `ld.so` makes for `dlopen`. A protected process asking for
//! `PROT_EXEC` on a file outside its allowlist is denied (see
//! `exec_allow`). Anonymous mappings (`file` is NULL) are left alone.

use aya_ebpf::{macros::lsm, programs::LsmContext};
use fairplay_common::{Hook, PROT_EXEC};

use crate::{exec_allow::exec_mapping_verdict, vmlinux::file};

#[lsm(hook = "mmap_file")]
pub fn mmap_file(ctx: LsmContext) -> i32 {
    // int mmap_file(struct file *file, unsigned long reqprot,
    //               unsigned long prot, unsigned long flags)
    // For BPF LSM, arg 4 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(4) };
    if prev != 0 {
        return prev;
    }
    // `prot`, not `reqprot`: what will actually be mapped, after
    // READ_IMPLIES_EXEC.
    let prot: u64 = unsafe { ctx.arg(2) };
    if prot & PROT_EXEC == 0 {
        return 0;
    }
    let f: *const file = unsafe { ctx.arg(0) };
    exec_mapping_verdict(f, Hook::MmapFile, prot as u32)
}
