//! Types shared by the kernel-side BPF program and `fairplayd`.
//! Everything here is `#[repr(C)]` plain data so both sides agree on layout.

#![no_std]

/// Name of the map from protected tgid to protection-domain id.
pub const MAP_PROTECTED: &str = "PROTECTED";
/// Name of the ring buffer of denied attempts.
pub const MAP_VIOLATIONS: &str = "VIOLATIONS";

/// Which LSM hook denied the attempt.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    /// `ptrace_access_check`: covers ptrace attach, `process_vm_readv`/`writev`,
    /// and `/proc/<pid>/mem`.
    PtraceAccess = 1,
    /// `file_open` on `/dev/uinput` during a protected session (milestone 5).
    UinputOpen = 2,
}

/// One denied attempt, written by the BPF program into the ring buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Violation {
    /// tgid of the process that tried.
    pub caller: u32,
    /// tgid of the protected process it targeted (0 for non-process targets).
    pub target: u32,
    /// A [`Hook`] value.
    pub hook: u32,
    /// The ptrace access mode bits the caller asked for.
    pub mode: u32,
    /// The caller's comm, NUL-padded. Captured in the kernel because the
    /// caller has often exited by the time user space reads the event.
    pub comm: [u8; 16],
}

#[cfg(feature = "user")]
mod user {
    // SAFETY: Violation is repr(C), Copy, and contains only integers.
    unsafe impl aya::Pod for super::Violation {}
}
