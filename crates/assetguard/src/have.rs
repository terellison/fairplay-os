//! The server's have list: which revision of each depot file this client has.

use std::collections::BTreeMap;

use crate::ztag;

/// depot path -> have revision.
pub type HaveList = BTreeMap<String, u32>;

/// Parse `p4 -ztag have` output.
pub fn read(ztag_output: &str) -> HaveList {
    ztag::parse(ztag_output)
        .into_iter()
        .filter_map(|r| Some((r.get("depotFile")?.clone(), r.get("haveRev")?.parse().ok()?)))
        .collect()
}

/// One `//depot/path#rev` per line, the format `p4 -x` reads.
pub fn serialize(list: &HaveList) -> String {
    list.iter().map(|(f, rev)| format!("{f}#{rev}\n")).collect()
}

/// `p4 flush` arguments that turn the `now` have list back into `before`.
pub fn restore_specs(before: &HaveList, now: &HaveList) -> Vec<String> {
    let changed = before
        .iter()
        .filter(|(f, rev)| now.get(*f) != Some(rev))
        .map(|(f, rev)| format!("{f}#{rev}"));
    // Files the failed sync added: the client had none of them.
    let added = now
        .keys()
        .filter(|f| !before.contains_key(*f))
        .map(|f| format!("{f}#none"));
    changed.chain(added).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_have_output() {
        let out = "\
... depotFile //depot/Art/hero.uasset
... clientFile //player/Art/hero.uasset
... path /work/ws/Art/hero.uasset
... haveRev 1
... syncTime 1793244287

... depotFile //depot/main.cpp
... clientFile //player/main.cpp
... path /work/ws/main.cpp
... haveRev 3
";
        let h = read(out);
        assert_eq!(h["//depot/Art/hero.uasset"], 1);
        assert_eq!(h["//depot/main.cpp"], 3);
        assert_eq!(
            serialize(&h),
            "//depot/Art/hero.uasset#1\n//depot/main.cpp#3\n"
        );
    }

    #[test]
    fn restore_resets_changed_and_removes_added() {
        let before: HaveList = [("//a".into(), 1), ("//b".into(), 2), ("//gone".into(), 1)].into();
        let now: HaveList = [("//a".into(), 1), ("//b".into(), 3), ("//new".into(), 1)].into();
        let mut specs = restore_specs(&before, &now);
        specs.sort();
        assert_eq!(specs, ["//b#2", "//gone#1", "//new#none"]);
    }

    #[test]
    fn empty_client_has_nothing() {
        assert!(read("").is_empty());
    }
}
