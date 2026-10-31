//! `bpf_prog` runs whenever the kernel hands out a file descriptor for a
//! BPF program (`BPF_PROG_GET_FD_BY_ID`, `BPF_OBJ_GET`). While fairplayd
//! protects itself, no other process gets one for fairplayd's programs.

use aya_ebpf::{helpers::bpf_probe_read_kernel, macros::lsm, programs::LsmContext};
use fairplay_common::{Hook, SELF_PROG};

use crate::{
    domain::{prog_aux, prog_aux_id, record_violation, EPERM},
    self_protect::{is_own, outsider},
    vmlinux::{bpf_prog as kernel_bpf_prog, bpf_prog_aux},
};

#[lsm(hook = "bpf_prog")]
pub fn bpf_prog(ctx: LsmContext) -> i32 {
    // int bpf_prog(struct bpf_prog *prog)
    // For BPF LSM, arg 1 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(1) };
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
    let prog: *const kernel_bpf_prog = unsafe { ctx.arg(0) };
    let id = unsafe {
        let aux: *const bpf_prog_aux = bpf_probe_read_kernel(prog_aux(prog))?;
        bpf_probe_read_kernel(prog_aux_id(aux))?
    };
    if !is_own(SELF_PROG, id) {
        return Ok(false);
    }
    record_violation(caller, fairplayd, Hook::BpfProg, 0);
    Ok(true)
}
