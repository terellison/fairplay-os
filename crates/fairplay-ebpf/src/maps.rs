//! Maps shared by every hook. Their names are `fairplay_common::MAP_*`, which
//! is how fairplayd finds them in the object.

use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, RingBuf},
};

/// tgid of a protected process -> its protection-domain id.
/// fairplayd adds the processes it launches; `follow` adds every process
/// they start and removes each one when it exits.
#[map]
pub static PROTECTED: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

/// tgid of a reader -> the protection domain whose members it may read
/// (milestone 9). Every reader is in PROTECTED too, with the same domain.
/// A process becomes a reader only by exec'ing a file in READER_FILES (see
/// `readers`), or from fairplayd's command line (`--allow`). Not inherited
/// on fork; dropped on exec of anything else and at exit.
#[map]
pub static READERS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

/// tgid of a sandboxed process -> its protection domain (milestone 9,
/// part B): the vendor's anti-cheat, put here by fairplayd before it runs,
/// and every process it starts (`follow`). Every one is in PROTECTED too.
/// The sandbox hooks (ptrace, `file_open`, `inode_follow_link`,
/// `socket_connect`/`socket_sendmsg`, `task_kill`) key on it.
#[map]
pub static SANDBOXED: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

/// Denied attempts, read by fairplayd and streamed to vendors.
#[map]
pub static VIOLATIONS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// Protection-domain id -> how many processes started in that domain could
/// not be added to PROTECTED (it was full), and so run unprotected. fairplayd
/// reports a nonzero count as "protection degraded".
#[map]
pub static UNFOLLOWED: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

/// Index 0: fairplayd's tgid while it protects itself (milestone 6), 0 when
/// it doesn't. Set by fairplayd after everything is loaded and attached.
#[map]
pub static SELF_PROTECT: Array<u32> = Array::with_max_entries(1, 0);

/// fairplayd's own maps, programs and links
/// (`fairplay_common::self_object_key` -> 1), which no other process may
/// open while self-protection is on.
#[map]
pub static SELF_OBJECTS: HashMap<u64, u32> = HashMap::with_max_entries(256, 0);
