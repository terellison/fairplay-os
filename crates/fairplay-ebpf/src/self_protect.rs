//! fairplayd protecting itself (milestone 6). On a player's PC root may be
//! the cheater, and the easiest way to cheat is to switch the protection
//! off: kill fairplayd, edit its maps, or detach its programs. While
//! fairplayd runs with `--self-protect`, its tgid is in SELF_PROTECT and
//! these hooks keep every other process, root included, away from it:
//!
//! - `task_kill`: no signals to fairplayd (SIGKILL and SIGSTOP included).
//!   Signals the kernel raises itself (SIGCHLD from its children, SIGPIPE,
//!   a terminal's Ctrl-C) don't pass through this hook and still arrive.
//! - `ptrace_access_check`: fairplayd counts as protected from everyone, so
//!   no ptrace, `/proc/<pid>/mem`, `process_vm_*` or `pidfd_getfd`.
//! - `bpf_map` / `bpf_prog`: no file descriptors to fairplayd's maps and
//!   programs (listed in SELF_OBJECTS), so no reading or writing its maps.
//! - `bpf`: no new BPF programs, no link fds by id, no detaching. A program
//!   of almost any type loaded by root can read the process it runs in with
//!   `bpf_probe_read_user`, which no LSM hook sees.
//!
//! Off (SELF_PROTECT[0] == 0) unless fairplayd was asked for it: developer
//! mode, and the shared test VM, keep normal root.

use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use fairplay_common::self_object_key;

use crate::maps::{SELF_OBJECTS, SELF_PROTECT};

/// `(caller, fairplayd)`: the current task's tgid and fairplayd's, if
/// self-protection is on and the current task is not part of fairplayd.
pub fn outsider() -> Option<(u32, u32)> {
    let guardian = *SELF_PROTECT.get(0)?;
    if guardian == 0 {
        return None;
    }
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    (caller != guardian).then_some((caller, guardian))
}

/// Is this map, program or link (`SELF_*` kind, kernel id) fairplayd's?
pub fn is_own(kind: u32, id: u32) -> bool {
    unsafe { SELF_OBJECTS.get(&self_object_key(kind, id)) }.is_some()
}
