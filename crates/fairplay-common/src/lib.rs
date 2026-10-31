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
/// Name of the map from a reader's tgid to the protection domain it may
/// read (milestone 9). Readers are in [`MAP_PROTECTED`] too.
pub const MAP_READERS: &str = "READERS";
/// Name of the map of files that make a protected process a reader when it
/// execs them ([`ExecKey`] -> [`ExecAllow`]), milestone 9.
pub const MAP_READER_FILES: &str = "READER_FILES";
/// Name of the map from a sandboxed process's tgid (the vendor's
/// anti-cheat and everything it starts) to its protection domain
/// (milestone 9, part B). Sandboxed processes are in [`MAP_PROTECTED`] too.
pub const MAP_SANDBOXED: &str = "SANDBOXED";
/// Entries [`MAP_READER_FILES`] holds: a few per session (the anti-cheat,
/// `wineserver`).
pub const READER_FILES_CAPACITY: u32 = 1024;
/// Name of the map from protection domain to the number of processes started
/// in it that could not be protected (PROTECTED was full).
pub const MAP_UNFOLLOWED: &str = "UNFOLLOWED";
/// Name of the one-entry array holding fairplayd's own tgid while it
/// protects itself, 0 otherwise (milestone 6).
pub const MAP_SELF_PROTECT: &str = "SELF_PROTECT";
/// Name of the set of fairplayd's thread ids other than its main thread
/// (tid -> 1), while it protects itself: `/proc/<tid>/` is the same
/// process as `/proc/<fairplayd>/` (milestone 6, issue #27).
pub const MAP_SELF_THREADS: &str = "SELF_THREADS";
/// Name of the set of fairplayd's own BPF objects ([`self_object_key`] ->
/// 1) that no other process may open while it protects itself.
pub const MAP_SELF_OBJECTS: &str = "SELF_OBJECTS";

/// [`self_object_key`] kind: a BPF map.
pub const SELF_MAP: u32 = 1;
/// [`self_object_key`] kind: a BPF program.
pub const SELF_PROG: u32 = 2;
/// [`self_object_key`] kind: a BPF link (an attached program).
pub const SELF_LINK: u32 = 3;

/// Key in [`MAP_SELF_OBJECTS`]: the object's kind (`SELF_*`) and its
/// kernel id, the one `bpftool` shows.
pub const fn self_object_key(kind: u32, id: u32) -> u64 {
    (kind as u64) << 32 | id as u64
}

/// `bpf(2)` commands (`enum bpf_cmd` in `<linux/bpf.h>`) that only
/// fairplayd may use while it protects itself.
pub const BPF_PROG_LOAD: u32 = 5;
pub const BPF_PROG_DETACH: u32 = 9;
pub const BPF_LINK_GET_FD_BY_ID: u32 = 30;
pub const BPF_LINK_DETACH: u32 = 34;

/// `PTRACE_MODE_ATTACH` (`<linux/ptrace.h>`): the caller wants to act on
/// the process (ptrace attach, `process_vm_*`, `/proc/<pid>/mem`), not just
/// look (`PTRACE_MODE_READ`: `/proc/<pid>/environ`, `maps`, hidepid).
pub const PTRACE_MODE_ATTACH: u32 = 0x02;
/// `PTRACE_MODE_NOAUDIT` (`<linux/ptrace.h>`, kernel-internal): the kernel
/// is only checking, e.g. to decide which `/proc/<pid>/stat` fields `ps`
/// may see, not acting on a request to access the process.
pub const PTRACE_MODE_NOAUDIT: u32 = 0x04;
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
    // Milestone 6, fairplayd protecting itself. Numbered apart so that other
    // milestones' hooks can take the next small numbers. The target is
    // fairplayd's own pid. Tracing or reading fairplayd's memory is
    // `PtraceAccess` with fairplayd as the target.
    /// `task_kill`: a signal to fairplayd from another process.
    TaskKill = 16,
    /// `bpf_map`: another process opening one of fairplayd's maps (by id,
    /// or from a pin).
    BpfMap = 17,
    /// `bpf_prog`: another process opening one of fairplayd's programs.
    BpfProg = 18,
    /// `bpf`: another process using a `bpf(2)` command reserved for
    /// fairplayd (loading a program, detaching, opening a link by id).
    Bpf = 19,
    // Milestone 7, virtual input, numbered after milestone 6. These are
    // machine-wide: the kernel records every one, with
    // [`VIOLATION_REPORTED`] unless a session asked for blocking, and
    // fairplayd decides which sessions hear about it. The target is 0.
    // (Value 2 was a placeholder for this milestone and is unused.)
    /// `file_ioctl` / `file_ioctl_compat`: `UI_DEV_CREATE` on `/dev/uinput`,
    /// which creates a virtual input device.
    UinputCreate = 20,
    /// `file_permission`: the first write on an open `/dev/uhid`, which is
    /// the one that creates the virtual HID device (`UHID_CREATE2`).
    UhidCreate = 21,
    /// `file_permission`: the first write on an open `/dev/input/event*`
    /// node, which injects events into an existing device.
    EvdevWrite = 22,
    /// `file_permission`: a write on a `/dev/uinput` fd (input through a
    /// uinput device) while a session blocks virtual input. Recorded only
    /// when denied, once per fd.
    UinputWrite = 23,
    // Milestone 9, part B: what a sandboxed process (the vendor's
    // anti-cheat, see `MAP_SANDBOXED`) may not do. Filed under its own
    // domain. Its signals to processes outside its sandbox are `TaskKill`.
    /// `file_open`: opening a `/proc/<pid>/mem` file for writing. Target 0;
    /// `mode` is the file's `FMODE_*` bits.
    ProcMemWrite = 24,
    /// `inode_follow_link`: following a `/proc/<pid>/` magic link (`root`,
    /// `cwd`, `exe`, `fd/N`, `map_files/*`) of a process outside its
    /// sandbox. Target is that pid; `file` the link's name.
    ProcLink = 25,
    /// `socket_connect` / `socket_sendmsg`: an abstract Unix socket
    /// address (X11's `@/tmp/.X11-unix/X0`). Target 0; `file` the name.
    UnixAbstract = 26,
    // Milestone 6 follow-ups (issue #27): starving or limiting fairplayd
    // instead of killing it. Target is fairplayd's pid.
    /// `task_setrlimit`: changing one of fairplayd's resource limits
    /// (`prlimit`; `RLIMIT_CPU` would have the kernel kill it). `mode` is
    /// the `RLIMIT_*` number.
    TaskSetrlimit = 30,
    /// `task_setnice`: renicing fairplayd. `mode` is the nice value asked
    /// for, as a two's-complement `u32`.
    TaskSetnice = 31,
    /// `task_setscheduler`: changing fairplayd's scheduling policy or
    /// priority (`sched_setscheduler`, `sched_setattr`), its CPU affinity
    /// (`sched_setaffinity`), its timer slack, or moving it into a cpuset
    /// cgroup. `mode` is 0.
    TaskSetscheduler = 32,
    /// `task_setioprio`: changing fairplayd's I/O priority. `mode` is the
    /// `ioprio` value (class << 13 | level).
    TaskSetioprio = 33,
    /// `file_open`: opening one of fairplayd's `/proc/<pid>/` tuning
    /// files (`oom_score_adj`, `oom_adj`, `autogroup`) for writing. `mode`
    /// is the file's `FMODE_*` bits, `file` its name.
    ProcTuneWrite = 34,
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
    /// tgid of the protected process it targeted (0 for non-process
    /// targets). For a protected caller reaching outside its domain
    /// (milestone 9), the unprotected process it tried to reach.
    pub target: u32,
    /// The target's protection domain, or 0 if it was no longer in the map.
    /// For a protected caller reaching outside its domain, the caller's.
    pub domain: u32,
    /// A [`Hook`] value.
    pub hook: u32,
    /// The ptrace access mode bits the caller asked for, or for
    /// [`Hook::MmapFile`] and [`Hook::FileMprotect`] the `PROT_*` bits. For
    /// [`Hook::TaskKill`] the signal, for [`Hook::BpfMap`] the `FMODE_*`
    /// bits asked for, and for [`Hook::Bpf`] the `bpf(2)` command. For
    /// hooks 30-34, see each [`Hook`] variant. For the
    /// input hooks, the device node's kernel `dev_t` (`major << 20 | minor`).
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
    /// device (sysfs `name`). For [`Hook::UhidCreate`],
    /// [`Hook::EvdevWrite`] and [`Hook::UinputWrite`]: the device node's
    /// file name (`uhid`, `event3`, `uinput`). Empty for process targets.
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

/// A file that one protection domain may map executable (or, in
/// [`MAP_READER_FILES`], whose exec makes a reader), identified the way the
/// kernel sees it: `inode->i_sb->s_dev` and `inode->i_ino`.
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
