//! `file_mprotect` closes the other door: map a file read-only (allowed),
//! then `mprotect` it executable. Same allowlist as `mmap_file`, applied to
//! the file behind the mapping. Anonymous mappings (no `vm_file`), which
//! JITs make executable all the time, are left alone.

use aya_ebpf::{helpers::bpf_probe_read_kernel, macros::lsm, programs::LsmContext};
use fairplay_common::{Hook, PROT_EXEC};

use crate::{
    domain::vma_file,
    exec_allow::exec_mapping_verdict,
    vmlinux::{file, vm_area_struct},
};

#[lsm(hook = "file_mprotect")]
pub fn file_mprotect(ctx: LsmContext) -> i32 {
    // int file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
    //                   unsigned long prot)
    // For BPF LSM, arg 3 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(3) };
    if prev != 0 {
        return prev;
    }
    let prot: u64 = unsafe { ctx.arg(2) };
    if prot & PROT_EXEC == 0 {
        return 0;
    }
    let vma: *const vm_area_struct = unsafe { ctx.arg(0) };
    // `vma` comes from the kernel and is valid; if the read failed anyway,
    // a dangling sentinel (non-null, so file-backed) makes the allowlist
    // check fail closed for protected processes.
    let f: *mut file = unsafe { bpf_probe_read_kernel(vma_file(vma)) }
        .unwrap_or(core::ptr::NonNull::dangling().as_ptr());
    exec_mapping_verdict(f, Hook::FileMprotect, prot as u32)
}
