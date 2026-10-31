//! `bpf` runs at the start of every `bpf(2)` call, before the kernel looks
//! at the command's arguments. While fairplayd protects itself, these
//! commands are fairplayd's alone:
//!
//! - `BPF_PROG_LOAD`, for every program type. A tracing program can read
//!   the memory of whatever process it runs in with `bpf_probe_read_user`,
//!   bypassing `ptrace_access_check`. Most other types (socket filters,
//!   cgroup programs) get the same helper when loaded with `CAP_PERFMON`,
//!   which root has, and some of those run in the game's context too, when
//!   it sends or connects. A competing LSM program could also deny what
//!   fairplayd needs.
//! - `BPF_LINK_GET_FD_BY_ID`, `BPF_LINK_DETACH`, `BPF_PROG_DETACH`: the
//!   ways to detach an attached program.
//!
//! Opening fairplayd's maps and programs is handled by `bpf_map` and
//! `bpf_prog`, which see the object itself.

use aya_ebpf::{macros::lsm, programs::LsmContext};
use fairplay_common::{
    Hook, BPF_LINK_DETACH, BPF_LINK_GET_FD_BY_ID, BPF_PROG_DETACH, BPF_PROG_LOAD,
};

use crate::{
    domain::{record_violation, EPERM},
    self_protect::outsider,
};

#[lsm(hook = "bpf")]
pub fn bpf(ctx: LsmContext) -> i32 {
    // int bpf(int cmd, union bpf_attr *attr, unsigned int size)
    // For BPF LSM, arg 3 is the verdict from earlier LSMs in the stack.
    // Newer kernels (around 6.15) add `bool kernel` after `size`, which
    // moves the verdict to arg 4: check BTF (`bpf_lsm_bpf`) when moving to
    // another kernel.
    let prev: i32 = unsafe { ctx.arg(3) };
    if prev != 0 {
        return prev;
    }
    let cmd: u32 = unsafe { ctx.arg(0) };
    if !matches!(
        cmd,
        BPF_PROG_LOAD | BPF_PROG_DETACH | BPF_LINK_GET_FD_BY_ID | BPF_LINK_DETACH
    ) {
        return 0;
    }
    let Some((caller, fairplayd)) = outsider() else {
        return 0;
    };
    record_violation(caller, fairplayd, Hook::Bpf, cmd);
    -EPERM
}
