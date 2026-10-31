//! Maps shared by every hook. Their names are `fairplay_common::MAP_*`, which
//! is how fairplayd finds them in the object.

use aya_ebpf::{
    macros::map,
    maps::{HashMap, RingBuf},
};

/// tgid of a protected process -> its protection-domain id.
/// Written only by fairplayd.
#[map]
pub static PROTECTED: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

/// Denied attempts, read by fairplayd and streamed to vendors.
#[map]
pub static VIOLATIONS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);
