//! The per-domain member cap (issue #21). PROTECTED is shared by every
//! session; without a cap, one game that forks without end (a fork bomb, or
//! a bug) fills it, and every other session's new processes, and new
//! launches, run unprotected or fail.
//!
//! MEMBERS counts, per domain, the processes the kernel forked into it
//! that are still alive. `task_alloc` refuses a protected process's fork
//! with `EAGAIN` once its domain is at MEMBER_CAP, as `RLIMIT_NPROC` does.
//! The count can't drift:
//!
//! - **Reserve at `task_alloc`.** The check and the increment are one
//!   atomic add (`live` before the add is compared with the cap), so forks
//!   racing on several CPUs can't all slip under it. A refused fork gives
//!   its reservation back at once. A fork that passed is in PENDING, keyed
//!   by its new `task_struct`.
//! - **Settle at `sched_process_fork`** (`follow`): the child's PENDING
//!   entry becomes its COUNTED entry. If it can't be (the map is full),
//!   the reservation is given back.
//! - **Give back at `task_free`** if the fork failed after `task_alloc`
//!   (`copy_process` calls `security_task_free` on every failure path after
//!   `security_task_alloc`, including another LSM refusing). A PENDING
//!   entry still there means the child never reached `sched_process_fork`.
//! - **Give back at exit** (`follow`): whichever thread's delete of the
//!   COUNTED entry succeeds gives it back, so once. A process that was
//!   never counted (fairplayd's own launches, or a child of a process that
//!   joined PROTECTED between its parent's `task_alloc` and the fork
//!   tracepoint) has no COUNTED entry and gives nothing back.
//!
//! So `live` is always the domain's COUNTED entries plus its PENDING ones.
//! fairplayd creates a domain's MEMBERS entry before the domain has a
//! process and drops it when it forgets the session. A fork in a domain
//! with no entry is refused.

use aya_ebpf::helpers::bpf_ktime_get_ns;
use core::intrinsics::{atomic_xadd, AtomicOrdering};
use fairplay_common::{Hook, Members, FORK_DENIED_RECORDS_PER_SEC};

use crate::{
    domain::{record_in, Name},
    maps::{COUNTED, MEMBERS, MEMBER_CAP, PENDING},
};

/// Adds `n` (wrapping: `u64::MAX` subtracts one) and returns the value
/// before. A BPF atomic add (`BPF_ATOMIC | BPF_ADD | BPF_FETCH`).
#[inline(always)]
fn fetch_add(p: *mut u64, n: u64) -> u64 {
    // SAFETY: `p` points into a map value, valid while the program runs.
    unsafe { atomic_xadd::<u64, u64, { AtomicOrdering::SeqCst }>(p, n) }
}

/// Why a fork was refused.
pub enum Refused {
    /// The domain is at its cap; recorded.
    Cap,
    /// No MEMBERS entry for the domain, or PENDING is full.
    NoRoom,
}

/// Reserves a place in `domain` for the new process `task` (a
/// `task_struct` address), forked by `caller`.
pub fn reserve(caller: u32, domain: u32, task: u64) -> Result<(), Refused> {
    let Some(m) = MEMBERS.get_ptr_mut(&domain) else {
        return Err(Refused::NoRoom);
    };
    let cap = MEMBER_CAP.get(0).copied().unwrap_or(0) as u64;
    // SAFETY: map value pointer, valid while the program runs.
    let live = unsafe { core::ptr::addr_of_mut!((*m).live) };
    let before = fetch_add(live, 1);
    if cap != 0 && before >= cap {
        fetch_add(live, u64::MAX);
        refused_at_cap(caller, domain, m);
        return Err(Refused::Cap);
    }
    if PENDING.insert(&task, &domain, 0).is_err() {
        fetch_add(live, u64::MAX);
        return Err(Refused::NoRoom);
    }
    Ok(())
}

/// Gives one place in `domain` back.
fn release(domain: u32) {
    if let Some(m) = MEMBERS.get_ptr_mut(&domain) {
        // SAFETY: map value pointer, valid while the program runs.
        fetch_add(unsafe { core::ptr::addr_of_mut!((*m).live) }, u64::MAX);
    }
}

/// `sched_process_fork`: the fork of `task` (now process `tgid`) finished.
/// Returns its domain if it was reserved, after making it COUNTED (or
/// giving the place back if COUNTED is full).
pub fn settle(task: u64, tgid: u32) -> Option<u32> {
    let domain = *unsafe { PENDING.get(&task) }?;
    let _ = PENDING.remove(&task);
    if COUNTED.insert(&tgid, &domain, 0).is_err() {
        release(domain);
    }
    Some(domain)
}

/// Process `tgid` is no member to count: it exited (its last thread), or
/// it didn't make it into PROTECTED after [`settle`]. If it was counted,
/// give its place back; of threads racing here, only the one whose delete
/// succeeds does.
pub fn uncount(tgid: u32) {
    if let Some(&domain) = unsafe { COUNTED.get(&tgid) } {
        if COUNTED.remove(&tgid).is_ok() {
            release(domain);
        }
    }
}

/// `task_free`: if `task`'s fork never reached `sched_process_fork`, give
/// its place back.
pub fn abandoned(task: u64) {
    let Some(&domain) = (unsafe { PENDING.get(&task) }) else {
        return;
    };
    // Only one deleter succeeds, so only one gives the place back.
    if PENDING.remove(&task).is_ok() {
        release(domain);
    }
}

/// Counts the refusal and, within the rate limit, records it. Each record
/// carries the refusals since the previous one in `mode`, so none goes
/// unreported for good, but a fork bomb can't flood the ring buffer.
fn refused_at_cap(caller: u32, domain: u32, m: *mut Members) {
    // SAFETY: map value pointer, valid while the program runs. The window
    // fields are best effort: two CPUs at once may both record, or lose
    // an `unreported` count; `denied` is exact.
    unsafe {
        fetch_add(core::ptr::addr_of_mut!((*m).denied), 1);
        let now = bpf_ktime_get_ns();
        if now.wrapping_sub((*m).window_start) >= 1_000_000_000 {
            (*m).window_start = now;
            (*m).window_records = 0;
        }
        let pending = (*m).unreported.saturating_add(1);
        if (*m).window_records >= FORK_DENIED_RECORDS_PER_SEC {
            (*m).unreported = pending;
            return;
        }
        (*m).window_records += 1;
        (*m).unreported = 0;
        record_in(caller, 0, domain, Hook::TaskAlloc, pending, 0, Name::None);
    }
}
