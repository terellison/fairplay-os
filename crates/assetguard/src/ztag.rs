//! Parser for `p4 -ztag` output: `... key value` lines, records separated by
//! blank lines.

use std::collections::HashMap;

pub type Record = HashMap<String, String>;

pub fn parse(output: &str) -> Vec<Record> {
    let mut records = Vec::new();
    let mut cur = Record::new();
    for line in output.lines() {
        let Some(rest) = line.strip_prefix("... ") else {
            if line.trim().is_empty() && !cur.is_empty() {
                records.push(std::mem::take(&mut cur));
            }
            continue;
        };
        let (key, value) = rest.split_once(' ').unwrap_or((rest, ""));
        // A repeated key on a new file means a new record even without a blank line.
        if key == "depotFile" && cur.contains_key("depotFile") {
            records.push(std::mem::take(&mut cur));
        }
        cur.insert(key.to_string(), value.to_string());
    }
    if !cur.is_empty() {
        records.push(cur);
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_two_records() {
        let out = "\
... depotFile //game/Content/hero.uasset
... clientFile /work/ws/Content/hero.uasset
... haveRev 4
... headType binary+l
... fileSize 1048576
... digest 9E107D9D372BB6826BD81D3542A419D6

... depotFile //game/Source/Main.cpp
... clientFile /work/ws/Source/Main.cpp
... haveRev 12
... headType text
... fileSize 2048
... digest E4D909C290D0FB1CA068FFADDF22CBD0
";
        let r = parse(out);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0]["headType"], "binary+l");
        assert_eq!(r[1]["clientFile"], "/work/ws/Source/Main.cpp");
    }

    #[test]
    fn splits_on_repeated_depot_file_without_blank_line() {
        let out = "... depotFile //a\n... haveRev 1\n... depotFile //b\n... haveRev 2\n";
        assert_eq!(parse(out).len(), 2);
    }
}
