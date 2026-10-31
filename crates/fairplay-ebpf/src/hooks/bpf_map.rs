//! `bpf_map` runs whenever the kernel hands out a file descriptor for a BPF
//! map: `BPF_MAP_GET_FD_BY_ID` (what `bpftool map dump id N` uses) and
//! `BPF_OBJ_GET` on a pinned map. Every read or write of a map goes through
//! such an fd. While fairplayd protects itself, no other process gets one
//! for fairplayd's maps (PROTECTED, the allowlist, SELF_PROTECT itself...).

use aya_ebpf::{helpers::bpf_probe_read_kernel, macros::lsm, programs::LsmContext};
use fairplay_common::{Hook, SELF_MAP};

use crate::{
    domain::{map_id, record_violation, EPERM},
    self_protect::{is_own, outsider},
    vmlinux::bpf_map as kernel_bpf_map,
};

#[lsm(hook = "bpf_map")]
pub fn bpf_map(ctx: LsmContext) -> i32 {
    // int bpf_map(struct bpf_map *map, fmode_t fmode)
    // For BPF LSM, arg 2 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(2) };
    if prev != 0 {
        return prev;
    }
    match should_deny(&ctx) {
        Ok(true) => -EPERM,
        _ => 0,
    }
}

fn should_deny(ctx: &LsmContext) -> Result<bool, i64> {
    let Some((caller, fairplayd)) = outsider() else {
        return Ok(false);
    };
    let map: *const kernel_bpf_map = unsafe { ctx.arg(0) };
    let id = unsafe { bpf_probe_read_kernel(map_id(map))? };
    if !is_own(SELF_MAP, id) {
        return Ok(false);
    }
    let fmode: u32 = unsafe { ctx.arg(1) };
    record_violation(caller, fairplayd, Hook::BpfMap, fmode);
    Ok(true)
}
