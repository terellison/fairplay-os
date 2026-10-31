//! fairplayd protecting itself from root (milestone 6). Off unless asked
//! for with `--self-protect` or `--self-protect-for <seconds>`.
//!
//! Turning it on means telling the kernel side two things: which BPF
//! objects are fairplayd's (SELF_OBJECTS: every map, program and link it
//! holds a file descriptor for), then fairplayd's own tgid (SELF_PROTECT),
//! which arms the hooks in `crates/fairplay-ebpf/src/self_protect.rs`. From
//! then on no other process may signal it, trace it, open its maps or
//! programs, load a BPF program or detach one.
//!
//! There is deliberately no socket call to turn it off. The only ways out
//! are a timer fairplayd sets for itself (`--self-protect-for`, for tests)
//! and a reboot; in player mode attestation sees the reboot.

use std::fmt::Write as _;

use anyhow::{Context, Result};
use aya::{
    maps::{Array, HashMap, MapData, MapInfo},
    Ebpf,
};
use fairplay_common::{
    self_object_key, MAP_SELF_OBJECTS, MAP_SELF_PROTECT, SELF_LINK, SELF_MAP, SELF_PROG,
};

/// A BPF object fairplayd holds: (`SELF_*` kind, kernel id).
pub type Object = (u32, u32);

/// The armed SELF_PROTECT map. Dropping it doesn't turn protection off;
/// [`SelfProtect::disable`] does, and so does fairplayd exiting (its
/// programs detach with it).
pub struct SelfProtect {
    guardian: Array<MapData, u32>,
}

impl SelfProtect {
    /// Lists fairplayd's BPF objects for the kernel and arms the hooks.
    /// Call once everything is loaded and attached and every map has been
    /// taken from `ebpf`: objects made later would be unprotected.
    pub fn enable(ebpf: &mut Ebpf) -> Result<Self> {
        let mut guardian: Array<MapData, u32> = Array::try_from(
            ebpf.take_map(MAP_SELF_PROTECT)
                .context("SELF_PROTECT map")?,
        )?;
        let mut objects: HashMap<MapData, u64, u32> = HashMap::try_from(
            ebpf.take_map(MAP_SELF_OBJECTS)
                .context("SELF_OBJECTS map")?,
        )?;
        // After taking both maps: their fds count too.
        let held = own_objects()?;
        for &(kind, id) in &held {
            objects
                .insert(self_object_key(kind, id), 1, 0)
                .with_context(|| format!("listing BPF object {kind}:{id}"))?;
        }
        let pid = std::process::id();
        guardian.set(0, pid, 0)?;
        eprintln!(
            "fairplayd: self-protection on for pid {pid}: {}",
            describe(&held)
        );
        // `objects` is dropped here; the kernel keeps the map, since
        // the programs that read it hold a reference.
        Ok(Self { guardian })
    }

    /// Disarms the hooks: root is ordinary root again.
    pub fn disable(&mut self) -> Result<()> {
        self.guardian.set(0, 0, 0)?;
        eprintln!("fairplayd: self-protection off");
        Ok(())
    }
}

/// Every BPF map, program and link this process has a file descriptor
/// for, from /proc/self/fdinfo.
fn own_objects() -> Result<Vec<Object>> {
    let mut all = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fdinfo").context("reading /proc/self/fdinfo")? {
        let entry = entry?;
        // An fd closed since read_dir started is fine to skip.
        if let Ok(info) = std::fs::read_to_string(entry.path()) {
            all.extend(parse_fdinfo(&info));
        }
    }
    all.sort_unstable();
    all.dedup();
    Ok(all)
}

/// The BPF objects one fdinfo file names. A map fd has `map_id:`, a
/// program fd `prog_id:`, a link fd `link_id:` and its program's
/// `prog_id:`.
pub fn parse_fdinfo(info: &str) -> Vec<Object> {
    info.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            let kind = match key.trim() {
                "map_id" => SELF_MAP,
                "prog_id" => SELF_PROG,
                "link_id" => SELF_LINK,
                _ => return None,
            };
            Some((kind, value.trim().parse().ok()?))
        })
        .collect()
}

/// `maps PROTECTED=12 VIOLATIONS=13 ..., programs 40 41 ..., links 7 8 ...`,
/// the ids a test (or a person with bpftool) needs.
fn describe(objects: &[Object]) -> String {
    let mut out = String::from("maps");
    for &(_, id) in objects.iter().filter(|o| o.0 == SELF_MAP) {
        let name = MapInfo::from_id(id)
            .ok()
            .and_then(|m| m.name_as_str().map(str::to_owned))
            .unwrap_or_else(|| "?".into());
        let _ = write!(out, " {name}={id}");
    }
    for (kind, label) in [(SELF_PROG, "programs"), (SELF_LINK, "links")] {
        let _ = write!(out, ", {label}");
        for &(_, id) in objects.iter().filter(|o| o.0 == kind) {
            let _ = write!(out, " {id}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fdinfo_of_each_kind() {
        let map = "pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1057\nmap_type:\t1\n\
                   key_size:\t4\nvalue_size:\t4\nmax_entries:\t1024\nmap_flags:\t0x0\n\
                   map_extra:\t0x0\nmemlock:\t82240\nmap_id:\t31\nfrozen:\t0\n";
        assert_eq!(parse_fdinfo(map), vec![(SELF_MAP, 31)]);
        let prog = "pos:\t0\nflags:\t02000002\nprog_type:\t29\nprog_jited:\t1\n\
                    prog_tag:\t0123456789abcdef\nmemlock:\t4096\nprog_id:\t77\n";
        assert_eq!(parse_fdinfo(prog), vec![(SELF_PROG, 77)]);
        let link = "pos:\t0\nflags:\t02000000\nlink_type:\ttracing\nlink_id:\t9\n\
                    prog_tag:\t0123456789abcdef\nprog_id:\t77\nattach_type:\t27\n";
        assert_eq!(parse_fdinfo(link), vec![(SELF_LINK, 9), (SELF_PROG, 77)]);
        assert!(parse_fdinfo("pos:\t0\nflags:\t02\nmnt_id:\t1\nino:\t5\n").is_empty());
    }

    #[test]
    fn description_names_maps() {
        // No such map ids: names fall back to "?".
        let d = describe(&[(SELF_MAP, u32::MAX), (SELF_PROG, 4), (SELF_LINK, 2)]);
        assert_eq!(d, format!("maps ?={}, programs 4, links 2", u32::MAX));
    }
}
