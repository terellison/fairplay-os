//! Maps shared by every hook. Their names are `fairplay_common::MAP_*`, which
//! is how fairplayd finds them in the object.

use aya_ebpf::{
    macros::map,
    maps::{HashMap, RingBuf},
};

/// tgid of a protected process -> its protection-domain id.
/// fairplayd adds the processes it launches; `follow` adds every process
/// they start and removes each one when it exits.
#[map]
pub static PROTECTED: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

/// Denied attempts, read by fairplayd and streamed to vendors.
#[map]
pub static VIOLATIONS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// Protection-domain id -> how many processes started in that domain could
/// not be added to PROTECTED (it was full), and so run unprotected. fairplayd
/// reports a nonzero count as "protection degraded".
#[map]
pub static UNFOLLOWED: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);
