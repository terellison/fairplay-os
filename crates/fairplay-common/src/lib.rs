//! Types shared by the kernel-side BPF program and `fairplayd`.
//! Everything here is `#[repr(C)]` plain data so both sides agree on layout.

#![no_std]

/// Name of the map from protected tgid to protection-domain id.
pub const MAP_PROTECTED: &str = "PROTECTED";
/// Name of the ring buffer of denied attempts.
pub const MAP_VIOLATIONS: &str = "VIOLATIONS";
/// Name of the map of files a protected process may map executable
/// ([`ExecKey`] -> [`ExecAllow`]), milestone 8.
pub const MAP_EXEC_ALLOWED: &str = "EXEC_ALLOWED";
/// Name of the map of filesystems with a blanket executable-mapping rule
/// (kernel `s_dev` -> one of the `FS_*` kinds), milestone 8.
pub const MAP_EXEC_TRUSTED_FS: &str = "EXEC_TRUSTED_FS";
/// Name of the map from protection domain to the number of processes started
/// in it that could not be protected (PROTECTED was full).
pub const MAP_UNFOLLOWED: &str = "UNFOLLOWED";
/// Name of the map of executables allowed to make virtual input
/// (remappers, accessibility tools): [`ExecKey`] with [`ANY_DOMAIN`] ->
/// [`ExecAllow`], milestone 7.
pub const MAP_INPUT_ALLOWED: &str = "INPUT_ALLOWED";
/// Name of the one-entry array (index 0, a `u32`) that is nonzero while
/// some running session asked for `block_virtual_input`, milestone 7.
pub const MAP_INPUT_BLOCK: &str = "INPUT_BLOCK";

/// Which LSM hook denied (or, for the input hooks, saw) the attempt.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    /// `ptrace_access_check`: covers ptrace attach, `process_vm_readv`/`writev`,
    /// and `/proc/<pid>/mem`.
    PtraceAccess = 1,
    /// `mmap_file`: a protected process mapping a file executable that is
    /// not on its allowlist (milestone 8).
    MmapFile = 3,
    /// `file_mprotect`: a protected process making a file-backed mapping
    /// executable after the fact, same allowlist (milestone 8).
    FileMprotect = 4,
    // Milestone 7, virtual input. These are machine-wide: the kernel records
    // every one, with [`VIOLATION_REPORTED`] unless a session asked for
    // blocking, and fairplayd decides which sessions hear about it.
    // (Value 2 was a placeholder for this milestone and is unused.)
    /// `file_ioctl` / `file_ioctl_compat`: `UI_DEV_CREATE` on `/dev/uinput`,
    /// which creates a virtual input device.
    UinputCreate = 16,
    /// `file_permission`: the first write on an open `/dev/uhid`, which is
    /// the one that creates the virtual HID device (`UHID_CREATE2`).
    UhidCreate = 17,
    /// `file_permission`: the first write on an open `/dev/input/event*`
    /// node, which injects events into an existing device.
    EvdevWrite = 18,
}

/// [`Violation::flags`]: the kernel let it happen and only reports it
/// (milestone 7's default for virtual input). Without it, it was denied.
pub const VIOLATION_REPORTED: u32 = 1;
/// [`Violation::flags`]: the caller's executable is on the input allowlist
/// (`INPUT_ALLOWED`). Always allowed and never sent to vendors; recorded so
/// fairplayd can say who made each virtual device.
pub const VIOLATION_ALLOWLISTED: u32 = 2;

/// One denied attempt, written by the BPF program into the ring buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Violation {
    /// tgid of the process that tried.
    pub caller: u32,
    /// tgid of the protected process it targeted (0 for non-process targets).
    pub target: u32,
    /// The target's protection domain, or 0 if it was no longer in the map.
    pub domain: u32,
    /// A [`Hook`] value.
    pub hook: u32,
    /// The ptrace access mode bits the caller asked for, or for
    /// [`Hook::MmapFile`] and [`Hook::FileMprotect`] the `PROT_*` bits, or
    /// for the input hooks the device node's kernel `dev_t`
    /// (`major << 20 | minor`).
    pub mode: u32,
    /// [`VIOLATION_REPORTED`], [`VIOLATION_ALLOWLISTED`]; 0 for a denial.
    pub flags: u32,
    /// The caller's comm, NUL-padded. Captured in the kernel because the
    /// caller has often exited by the time user space reads the event.
    pub comm: [u8; 16],
    /// File name (no directory) of the caller's executable, NUL-padded and
    /// cut at [`EXE_NAME_LEN`] - 1 bytes. Empty for kernel threads. Also
    /// captured in the kernel; user space adds the full path if the caller
    /// is still alive.
    pub exe: [u8; EXE_NAME_LEN],
    /// For file hooks ([`Hook::MmapFile`], [`Hook::FileMprotect`]): file
    /// name (no directory) of the file it tried to map, same format as
    /// `exe`. For [`Hook::UinputCreate`]: the name the caller gave the new
    /// device (sysfs `name`). For [`Hook::UhidCreate`] and
    /// [`Hook::EvdevWrite`]: the device node's file name (`uhid`,
    /// `event3`). Empty for process targets.
    pub file: [u8; EXE_NAME_LEN],
}

/// Bytes reserved for [`Violation::exe`].
pub const EXE_NAME_LEN: usize = 64;

/// `PROT_EXEC` from `<sys/mman.h>`.
pub const PROT_EXEC: u64 = 4;

/// [`MAP_EXEC_ALLOWED`] domain for files every protected process may map
/// (approved overlays). Real domains start at 1.
pub const ANY_DOMAIN: u32 = 0;

/// Entries [`MAP_EXEC_ALLOWED`] holds. Files the system rule covers (see
/// [`FS_SYSTEM`]) need none, so this only has to fit games' own code and
/// overlays. fairplayd refuses a launch that would not fit.
pub const EXEC_ALLOWED_CAPACITY: u32 = 32 * 1024;

/// A file that one protection domain may map executable, identified the way
/// the kernel sees it: `inode->i_sb->s_dev` and `inode->i_ino`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExecKey {
    /// Protection domain, or [`ANY_DOMAIN`].
    pub domain: u32,
    /// Kernel-encoded device of the file's superblock
    /// (`MKDEV(major, minor)` = `major << 20 | minor`), the numbers
    /// `/proc/self/mountinfo` prints. Not always `stat`'s `st_dev`: btrfs
    /// reports a per-subvolume device there.
    pub dev: u32,
    pub ino: u64,
}

/// Value of an [`ExecKey`] entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecAllow {
    /// `inode->i_generation` when the file was allowed. Checked only with
    /// [`EXEC_CHECK_GENERATION`], so that a reused inode number (a new file
    /// on another btrfs subvolume of the same filesystem, or after the
    /// allowed file was deleted) isn't taken for the allowed file.
    pub generation: u32,
    pub flags: u32,
}

/// [`ExecAllow::flags`]: `generation` is known and must match.
pub const EXEC_CHECK_GENERATION: u32 = 1;

/// [`MAP_EXEC_TRUSTED_FS`] kind: a system filesystem (the one holding
/// `/usr`, `/lib`, ...). Files on it that root owns and that group and
/// others can't write may be mapped executable by any protected process:
/// the loader, libc, Mesa, GPU drivers' user-space libraries.
pub const FS_SYSTEM: u32 = 1;
/// [`MAP_EXEC_TRUSTED_FS`] kind: the kernel's internal shmem mount (memfd,
/// shared anonymous memory, SysV shared memory). Treated like anonymous
/// memory: another process can only write into it through the paths
/// `ptrace_access_check` already guards, or if the game hands it the fd.
pub const FS_ANON: u32 = 2;

#[cfg(feature = "user")]
mod user {
    // SAFETY: these are repr(C), Copy, contain only integers and have no
    // padding (ExecKey is 4 + 4 + 8 bytes; Violation is 6 u32s and three
    // byte arrays).
    unsafe impl aya::Pod for super::Violation {}
    unsafe impl aya::Pod for super::ExecKey {}
    unsafe impl aya::Pod for super::ExecAllow {}
}
