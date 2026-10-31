//! Virtual input (milestone 7): who made each virtual input device.
//!
//! The kernel program records every uinput device creation, every first
//! write on an open `/dev/uhid` (which creates a uhid device) and every
//! first write on an open evdev node, with the process and executable that
//! did it and whether that executable is on the input allowlist
//! (`--input-allow`). fairplayd keeps the recent records in an
//! [`InputLog`], so it can answer for devices made before a session started
//! (Steam Input's virtual pads, say).
//!
//! `session_status` lists the devices sysfs shows and [`correlate`]s each
//! with the records:
//! - a uinput device by the name its creator gave it, which the kernel
//!   captured at `UI_DEV_CREATE`;
//! - a uhid device with the processes that opened `/dev/uhid` and are still
//!   alive (a uhid device lives exactly as long as its fd). The kernel can't
//!   see the new device's name at that point: the HID core makes the input
//!   device later, from a worker thread.
//!
//! When several live processes fit, the newest is named, the device is
//! marked `ambiguous`, and it counts as allowlisted only if all of them
//! are. Whatever sysfs shows, the violation stream has the exact process
//! for each creation: it comes straight from the kernel record.

use std::{
    collections::{BTreeSet, VecDeque},
    fs,
    path::Path,
};

use fairplay_api::{InputCreator, InputKind, VirtualInputDevice};
use fairplay_common::{Hook, Violation, EXE_NAME_LEN, VIOLATION_ALLOWLISTED, VIOLATION_REPORTED};

use crate::state::c_str;

/// Records kept. Creations are rare (a remapper makes a handful of devices
/// at start), so this covers days of normal use; the oldest go first.
pub const LOG_CAPACITY: usize = 256;

/// How a process made or faked input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    Uinput,
    Uhid,
    Evdev,
    /// Input through an existing uinput device, refused while a session
    /// blocks virtual input.
    UinputWrite,
}

impl Mechanism {
    pub fn of_hook(hook: u32) -> Option<Self> {
        match hook {
            x if x == Hook::UinputCreate as u32 => Some(Self::Uinput),
            x if x == Hook::UhidCreate as u32 => Some(Self::Uhid),
            x if x == Hook::EvdevWrite as u32 => Some(Self::Evdev),
            x if x == Hook::UinputWrite as u32 => Some(Self::UinputWrite),
            _ => None,
        }
    }
}

/// One kernel record of virtual input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRecord {
    pub mechanism: Mechanism,
    pub pid: u32,
    pub comm: String,
    pub exe: String,
    pub exe_path: Option<String>,
    /// uinput: the device's name; otherwise the node (`uhid`, `event3`,
    /// `uinput`).
    pub name: String,
    /// Device node, kernel `dev_t`.
    pub rdev: u32,
    pub allowlisted: bool,
    /// The kernel refused it (a session asked for blocking).
    pub denied: bool,
    /// Seconds since the Unix epoch, when fairplayd read it.
    pub at: u64,
}

impl InputRecord {
    /// `None` if `v` isn't from an input hook.
    pub fn from_kernel(v: &Violation, exe_path: Option<String>, at: u64) -> Option<Self> {
        Some(Self {
            mechanism: Mechanism::of_hook(v.hook)?,
            pid: v.caller,
            comm: c_str(&v.comm),
            exe: c_str(&v.exe),
            exe_path,
            name: c_str(&v.file),
            rdev: v.mode,
            allowlisted: v.flags & VIOLATION_ALLOWLISTED != 0,
            denied: v.flags & VIOLATION_REPORTED == 0,
            at,
        })
    }

    /// Should vendors hear about it? Everything but allowlisted tools.
    pub fn reportable(&self) -> bool {
        !self.allowlisted
    }

    fn creator(&self) -> InputCreator {
        InputCreator {
            pid: self.pid,
            comm: self.comm.clone(),
            exe: self.exe.clone(),
            exe_path: self.exe_path.clone(),
            created_at: self.at,
        }
    }
}

/// The most recent [`InputRecord`]s, oldest first.
#[derive(Debug, Default)]
pub struct InputLog(VecDeque<InputRecord>);

impl InputLog {
    pub fn push(&mut self, r: InputRecord) {
        if self.0.len() == LOG_CAPACITY {
            self.0.pop_front();
        }
        self.0.push_back(r);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// A virtual input device as sysfs shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysDevice {
    /// `input7`
    pub device: String,
    pub name: String,
    pub kind: InputKind,
}

/// Virtual input devices on this machine, from `/sys/class/input`.
pub fn scan() -> Vec<SysDevice> {
    scan_in(Path::new("/sys/class/input"))
}

/// Each `input*` entry of `class_dir` is a link into the device tree. A
/// uinput device has no parent: it sits right under
/// `devices/virtual/input/`. A uhid device hangs off the uhid misc device:
/// `devices/virtual/misc/uhid/<hid id>/input/`. Anything else is real
/// hardware (or a kernel driver's own device) and isn't listed.
pub fn scan_in(class_dir: &Path) -> Vec<SysDevice> {
    let Ok(entries) = fs::read_dir(class_dir) else {
        return vec![];
    };
    let mut out: Vec<SysDevice> = entries
        .flatten()
        .filter_map(|e| {
            let device = e.file_name().to_string_lossy().into_owned();
            if !device.starts_with("input") {
                return None;
            }
            let real = fs::canonicalize(e.path()).ok()?;
            let kind = kind_of(&real.to_string_lossy())?;
            let name = fs::read_to_string(real.join("name"))
                .map(|n| n.trim_end_matches('\n').to_owned())
                .unwrap_or_default();
            Some(SysDevice { device, name, kind })
        })
        .collect();
    out.sort_by_key(|d| {
        let n: u64 = d.device["input".len()..].parse().unwrap_or(u64::MAX);
        n
    });
    out
}

fn kind_of(sys_path: &str) -> Option<InputKind> {
    if sys_path.contains("/devices/virtual/misc/uhid/") {
        Some(InputKind::Uhid)
    } else if sys_path.contains("/devices/virtual/input/") {
        Some(InputKind::Uinput)
    } else {
        None
    }
}

/// Does a name the kernel captured (cut to [`EXE_NAME_LEN`] - 1 bytes) name
/// this device?
fn name_matches(captured: &str, sysfs: &str) -> bool {
    captured == sysfs
        || (captured.len() >= EXE_NAME_LEN - 1 - 3
            && sysfs.starts_with(captured.trim_end_matches('\u{fffd}')))
}

/// Pairs each device with the record of its creation (see the module docs).
/// `alive(pid)`: is that process still running?
pub fn correlate(
    devices: Vec<SysDevice>,
    log: &InputLog,
    alive: impl Fn(u32) -> bool,
) -> Vec<VirtualInputDevice> {
    devices
        .into_iter()
        .map(|d| {
            let candidates: Vec<&InputRecord> = log
                .0
                .iter()
                .filter(|r| !r.denied)
                .filter(|r| match d.kind {
                    InputKind::Uinput => {
                        r.mechanism == Mechanism::Uinput && name_matches(&r.name, &d.name)
                    }
                    InputKind::Uhid => r.mechanism == Mechanism::Uhid,
                })
                .collect();
            let live: Vec<&InputRecord> = candidates
                .iter()
                .copied()
                .filter(|r| alive(r.pid))
                .collect();
            // A uhid device dies with its fd, so its creator is alive; a
            // uinput fd can outlive its creator in a child, so fall back.
            let considered = if live.is_empty() && d.kind == InputKind::Uinput {
                candidates
            } else {
                live
            };
            let creators: BTreeSet<u32> = considered.iter().map(|r| r.pid).collect();
            VirtualInputDevice {
                created_by: considered.last().map(|r| r.creator()),
                allowlisted: !considered.is_empty() && considered.iter().all(|r| r.allowlisted),
                ambiguous: creators.len() > 1,
                device: d.device,
                name: d.name,
                kind: d.kind,
            }
        })
        .collect()
}

/// Is `pid` a running process?
pub fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(m: Mechanism, pid: u32, exe: &str, name: &str, allowlisted: bool) -> InputRecord {
        InputRecord {
            mechanism: m,
            pid,
            comm: exe.into(),
            exe: exe.into(),
            exe_path: None,
            name: name.into(),
            rdev: 0,
            allowlisted,
            denied: false,
            at: pid as u64,
        }
    }

    fn dev(n: u32, name: &str, kind: InputKind) -> SysDevice {
        SysDevice {
            device: format!("input{n}"),
            name: name.into(),
            kind,
        }
    }

    fn log(recs: impl IntoIterator<Item = InputRecord>) -> InputLog {
        let mut l = InputLog::default();
        recs.into_iter().for_each(|r| l.push(r));
        l
    }

    #[test]
    fn uinput_devices_match_by_name() {
        let l = log([
            rec(
                Mechanism::Uinput,
                10,
                "steam",
                "Steam Virtual Gamepad",
                true,
            ),
            rec(Mechanism::Uinput, 20, "cheatsim", "clicker", false),
            rec(Mechanism::Evdev, 30, "cheatsim", "event0", false),
            rec(Mechanism::UinputWrite, 40, "cheatsim", "clicker", false),
        ]);
        let out = correlate(
            vec![
                dev(3, "Steam Virtual Gamepad", InputKind::Uinput),
                dev(4, "clicker", InputKind::Uinput),
                dev(5, "made before fairplayd", InputKind::Uinput),
            ],
            &l,
            |_| true,
        );
        let by: Vec<_> = out
            .iter()
            .map(|d| {
                (
                    d.device.as_str(),
                    d.created_by.as_ref().map(|c| c.exe.as_str()),
                    d.allowlisted,
                    d.ambiguous,
                )
            })
            .collect();
        assert_eq!(
            by,
            [
                ("input3", Some("steam"), true, false),
                ("input4", Some("cheatsim"), false, false),
                ("input5", None, false, false),
            ]
        );
    }

    #[test]
    fn a_copied_name_makes_it_ambiguous_and_not_allowlisted() {
        // A cheat names its device like the remapper's to hide behind it.
        let l = log([
            rec(Mechanism::Uinput, 10, "remapper", "pad", true),
            rec(Mechanism::Uinput, 20, "cheat", "pad", false),
        ]);
        let out = correlate(
            vec![
                dev(1, "pad", InputKind::Uinput),
                dev(2, "pad", InputKind::Uinput),
            ],
            &l,
            |_| true,
        );
        for d in &out {
            assert!(d.ambiguous);
            assert!(!d.allowlisted, "{d:?}");
            assert_eq!(d.created_by.as_ref().unwrap().exe, "cheat", "newest");
        }
        // Once the cheat has exited, only the remapper fits.
        let out = correlate(vec![dev(1, "pad", InputKind::Uinput)], &l, |p| p == 10);
        assert!(out[0].allowlisted && !out[0].ambiguous);
        assert_eq!(out[0].created_by.as_ref().unwrap().pid, 10);
    }

    #[test]
    fn dead_creators_still_count_for_uinput_but_not_uhid() {
        let l = log([
            rec(Mechanism::Uinput, 10, "tool", "pad", false),
            rec(Mechanism::Uhid, 11, "hidtool", "uhid", false),
        ]);
        let out = correlate(
            vec![
                dev(1, "pad", InputKind::Uinput),
                dev(2, "HID 1234", InputKind::Uhid),
            ],
            &l,
            |_| false,
        );
        assert_eq!(out[0].created_by.as_ref().unwrap().pid, 10);
        assert_eq!(out[1].created_by, None);
    }

    #[test]
    fn uhid_devices_match_live_uhid_users() {
        let l = log([
            rec(Mechanism::Uhid, 10, "old", "uhid", false),
            rec(Mechanism::Uhid, 20, "access", "uhid", true),
        ]);
        // Only pid 20 is alive: it made the device.
        let out = correlate(vec![dev(9, "Mouse", InputKind::Uhid)], &l, |p| p == 20);
        assert_eq!(out[0].created_by.as_ref().unwrap().exe, "access");
        assert!(out[0].allowlisted && !out[0].ambiguous);
        // Both alive: can't tell which.
        let out = correlate(vec![dev(9, "Mouse", InputKind::Uhid)], &l, |_| true);
        assert!(out[0].ambiguous && !out[0].allowlisted);
    }

    #[test]
    fn denied_attempts_made_nothing() {
        let mut r = rec(Mechanism::Uinput, 10, "cheat", "pad", false);
        r.denied = true;
        let out = correlate(vec![dev(1, "pad", InputKind::Uinput)], &log([r]), |_| true);
        assert_eq!(out[0].created_by, None);
    }

    #[test]
    fn long_names_match_their_kernel_prefix() {
        let long = "x".repeat(79);
        let cut = &long[..EXE_NAME_LEN - 1];
        assert!(name_matches(cut, &long));
        assert!(!name_matches("x", &long));
        assert!(name_matches("pad", "pad"));
        assert!(!name_matches("pad", "pad2"));
    }

    #[test]
    fn records_from_the_kernel() {
        let mut v = Violation {
            caller: 5,
            target: 0,
            domain: 0,
            hook: Hook::UinputCreate as u32,
            mode: (10 << 20) | 223,
            flags: VIOLATION_REPORTED,
            comm: [0; 16],
            exe: [0; EXE_NAME_LEN],
            file: [0; EXE_NAME_LEN],
        };
        v.file[..7].copy_from_slice(b"clicker");
        let r = InputRecord::from_kernel(&v, None, 1).unwrap();
        assert_eq!(r.mechanism, Mechanism::Uinput);
        assert_eq!(r.name, "clicker");
        assert!(!r.denied && !r.allowlisted && r.reportable());
        v.flags = 0;
        assert!(InputRecord::from_kernel(&v, None, 1).unwrap().denied);
        v.flags = VIOLATION_REPORTED | VIOLATION_ALLOWLISTED;
        assert!(!InputRecord::from_kernel(&v, None, 1).unwrap().reportable());
        v.hook = Hook::UinputWrite as u32;
        assert_eq!(
            InputRecord::from_kernel(&v, None, 1).unwrap().mechanism,
            Mechanism::UinputWrite
        );
        v.hook = Hook::PtraceAccess as u32;
        assert!(InputRecord::from_kernel(&v, None, 1).is_none());
    }

    #[test]
    fn the_log_forgets_the_oldest() {
        let mut l = InputLog::default();
        for pid in 0..LOG_CAPACITY as u32 + 5 {
            l.push(rec(Mechanism::Uinput, pid, "t", "pad", false));
        }
        assert_eq!(l.len(), LOG_CAPACITY);
        assert_eq!(l.0.front().unwrap().pid, 5);
    }

    #[test]
    fn sysfs_scan_keeps_virtual_devices_only() {
        let t = std::env::temp_dir().join(format!("fairplayd-vinput-{}", std::process::id()));
        let _ = fs::remove_dir_all(&t);
        let mk = |rel: &str, name: Option<&str>| {
            let d = t.join(rel);
            fs::create_dir_all(&d).unwrap();
            if let Some(n) = name {
                fs::write(d.join("name"), format!("{n}\n")).unwrap();
            }
            d
        };
        let class = t.join("class/input");
        fs::create_dir_all(&class).unwrap();
        let link = |name: &str, target: &Path| {
            std::os::unix::fs::symlink(target, class.join(name)).unwrap();
        };
        link(
            "input12",
            &mk("devices/virtual/input/input12", Some("clicker")),
        );
        link("input3", &mk("devices/virtual/input/input3", None));
        link(
            "input9",
            &mk(
                "devices/virtual/misc/uhid/0003:1234:5678.0001/input/input9",
                Some("HID mouse"),
            ),
        );
        link(
            "input0",
            &mk("devices/platform/kbd/input/input0", Some("Keyboard")),
        );
        link("event3", &mk("devices/virtual/input/input12/event3", None));
        assert_eq!(
            scan_in(&class),
            vec![
                SysDevice {
                    device: "input3".into(),
                    name: "".into(),
                    kind: InputKind::Uinput
                },
                SysDevice {
                    device: "input9".into(),
                    name: "HID mouse".into(),
                    kind: InputKind::Uhid
                },
                SysDevice {
                    device: "input12".into(),
                    name: "clicker".into(),
                    kind: InputKind::Uinput
                },
            ]
        );
        fs::remove_dir_all(&t).unwrap();
        assert!(scan_in(&class).is_empty());
    }
}
