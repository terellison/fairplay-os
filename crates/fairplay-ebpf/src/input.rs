//! Virtual input (milestone 7), shared by the `file_ioctl`,
//! `file_ioctl_compat` and `file_permission` hooks.
//!
//! Three ways for a program to fake input, each recorded with the process
//! and executable that did it:
//! - `/dev/uinput`: `ioctl(UI_DEV_CREATE)` creates a virtual input device;
//! - `/dev/uhid`: the first write on an open fd (`UHID_CREATE2`) creates a
//!   virtual HID device, which the HID core turns into an input device;
//! - `/dev/input/event*`: a write injects events into an existing device.
//!
//! Everything is reported, never denied, unless a running session asked for
//! blocking (INPUT_BLOCK). Executables on INPUT_ALLOWED (remappers,
//! accessibility tools) are never denied and fairplayd doesn't send them to
//! vendors; they are still recorded so it can say who made each device.
//!
//! Devices are recognized by the inode's device number (`i_rdev`), not by
//! path: a node made elsewhere with `mknod` is the same device.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::map,
    maps::{Array, HashMap, LruHashMap},
};
use fairplay_common::{
    ExecAllow, ExecKey, Hook, ANY_DOMAIN, VIOLATION_ALLOWLISTED, VIOLATION_REPORTED,
};

use crate::{
    domain::{current_exe, file_inode, file_private, inode_mode, inode_rdev, record, Name, EPERM},
    exec_allow::{file_id, listed},
    vmlinux::{file, inode},
};

/// Executables that may make virtual input, with [`ANY_DOMAIN`]. Written
/// only by fairplayd, at startup (`--input-allow`).
#[map]
pub static INPUT_ALLOWED: HashMap<ExecKey, ExecAllow> = HashMap::with_max_entries(256, 0);

/// Index 0: nonzero while a running session asked for
/// `block_virtual_input`. Written only by fairplayd.
#[map]
pub static INPUT_BLOCK: Array<u32> = Array::with_max_entries(1, 0);

/// Open files (`file`, `file->private_data`) whose first write was already
/// recorded, so a uhid or evdev fd is reported once, not once per event.
/// The driver's per-open state pointer makes a recycled `struct file`
/// address look new. LRU: a forgotten entry only means one more report.
#[map]
static INPUT_SEEN: LruHashMap<[u64; 2], u8> = LruHashMap::with_max_entries(4096, 0);

/// `MKDEV(major, minor)` as the kernel stores it in `i_rdev`.
const fn mkdev(major: u32, minor: u32) -> u32 {
    (major << 20) | minor
}
/// `/dev/uinput`: misc device, `UINPUT_MINOR`.
const UINPUT_DEV: u32 = mkdev(10, 223);
/// `/dev/uhid`: misc device, `UHID_MINOR`.
const UHID_DEV: u32 = mkdev(10, 239);
/// Input subsystem major (`INPUT_MAJOR`). evdev nodes are minors 64-95 and,
/// once those run out, dynamic minors from 256 (`INPUT_FIRST_DYNAMIC_DEV`).
/// Minors below 64 are joystick and mouse (`mousedev`) nodes, whose writes
/// don't inject events.
const INPUT_MAJOR: u32 = 13;
const EVDEV_MINOR_BASE: u32 = 64;
const MINOR_MASK: u32 = (1 << 20) - 1;

/// `UI_DEV_CREATE`: `_IO('U', 1)`, the same number for 32-bit callers.
pub const UI_DEV_CREATE: u32 = 0x5501;
/// `MAY_WRITE` from `<linux/fs.h>`.
pub const MAY_WRITE: i32 = 2;

const S_IFMT: u16 = 0o170000;
const S_IFCHR: u16 = 0o020000;

/// The character device behind `f`, as `i_rdev`; 0 for anything else
/// (regular files, pipes, sockets all have no rdev).
#[inline(always)]
fn char_dev(f: *const file) -> u32 {
    unsafe {
        let Ok(inode) = bpf_probe_read_kernel::<*mut inode>(file_inode(f)) else {
            return 0;
        };
        if inode.is_null() {
            return 0;
        }
        let rdev: u32 = bpf_probe_read_kernel(inode_rdev(inode)).unwrap_or(0);
        if rdev == 0 {
            return 0;
        }
        match bpf_probe_read_kernel(inode_mode(inode)) {
            Ok(mode) if mode & S_IFMT == S_IFCHR => rdev,
            _ => 0,
        }
    }
}

/// `file_ioctl` and `file_ioctl_compat`: `UI_DEV_CREATE` on `/dev/uinput`.
/// Any other ioctl costs one comparison.
#[inline(always)]
pub fn ioctl_verdict(f: *const file, cmd: u32) -> i32 {
    if cmd != UI_DEV_CREATE || f.is_null() || char_dev(f) != UINPUT_DEV {
        return 0;
    }
    // The device's name, as its creator set it (sysfs `name`):
    // file->private_data is uinput's `struct uinput_device`, whose first
    // member is `struct input_dev *dev`, whose first member is
    // `const char *name`. Neither struct is in vmlinux BTF reachable from
    // task_struct, but both have started this way since Linux 2.6. If the
    // device isn't set up yet, the ioctl fails anyway and there's no name.
    let name = unsafe {
        bpf_probe_read_kernel::<*mut aya_ebpf::cty::c_void>(file_private(f))
            .and_then(|udev| bpf_probe_read_kernel(udev as *const *const u8))
            .and_then(|dev| {
                if dev.is_null() {
                    Ok(core::ptr::null())
                } else {
                    bpf_probe_read_kernel(dev as *const *const u8)
                }
            })
            .unwrap_or(core::ptr::null())
    };
    verdict(Hook::UinputCreate, UINPUT_DEV, Name::Str(name))
}

/// `file_permission`: writes to `/dev/uhid` and to evdev nodes. Reads, and
/// writes to anything that isn't a character device, cost the mask test
/// and two reads of the inode.
#[inline(always)]
pub fn write_verdict(f: *const file, mask: i32) -> i32 {
    if mask & MAY_WRITE == 0 || f.is_null() {
        return 0;
    }
    let rdev = char_dev(f);
    if rdev == 0 {
        return 0;
    }
    let minor = rdev & MINOR_MASK;
    let hook = if rdev == UHID_DEV {
        Hook::UhidCreate
    } else if rdev >> 20 == INPUT_MAJOR && minor >= EVDEV_MINOR_BASE {
        Hook::EvdevWrite
    } else {
        return 0;
    };
    let private =
        unsafe { bpf_probe_read_kernel(file_private(f)) }.unwrap_or(core::ptr::null_mut()) as u64;
    let key = [f as u64, private];
    let (flags, ret) = decide();
    // Record the first write on this fd, and the first denied one (blocking
    // may have started after the fd's first write went through).
    let seen = unsafe { INPUT_SEEN.get(&key) }.copied().unwrap_or(0);
    let state = if ret != 0 { SEEN_DENIED } else { SEEN_ALLOWED };
    if seen == 0 || (state == SEEN_DENIED && seen != SEEN_DENIED) {
        record(current_tgid(), 0, hook, rdev, flags, Name::File(f));
        let _ = INPUT_SEEN.insert(&key, &state, 0);
    }
    ret
}

/// INPUT_SEEN values.
const SEEN_ALLOWED: u8 = 1;
const SEEN_DENIED: u8 = 2;

#[inline(always)]
fn verdict(hook: Hook, rdev: u32, name: Name) -> i32 {
    let (flags, ret) = decide();
    record(current_tgid(), 0, hook, rdev, flags, name);
    ret
}

#[inline(always)]
fn current_tgid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

/// (`Violation::flags`, verdict) for the current task. Allowlisted: allow.
/// Otherwise deny if a running session asked for blocking, else allow and
/// report.
#[inline(always)]
fn decide() -> (u32, i32) {
    if allowlisted() {
        (VIOLATION_REPORTED | VIOLATION_ALLOWLISTED, 0)
    } else if INPUT_BLOCK.get(0).is_some_and(|&b| b != 0) {
        (0, -EPERM)
    } else {
        (VIOLATION_REPORTED, 0)
    }
}

/// Is the current task's executable on INPUT_ALLOWED?
#[inline(always)]
fn allowlisted() -> bool {
    let Ok(exe) = current_exe() else {
        return false;
    };
    if exe.is_null() {
        return false;
    }
    match file_id(exe) {
        Ok((dev, ino, generation)) => listed(&INPUT_ALLOWED, ANY_DOMAIN, dev, ino, generation),
        Err(_) => false,
    }
}
