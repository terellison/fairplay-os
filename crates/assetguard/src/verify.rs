//! Checks synced files against the digests Perforce has for the have revision.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

use md5::{Digest, Md5};

use crate::ztag::Record;

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    /// Size or MD5 differs from the depot.
    Mismatch {
        expected: String,
        actual: String,
    },
    Missing,
    /// Digest can't be compared on the client (keyword expansion, utf16).
    Skipped(&'static str),
}

#[derive(Debug)]
pub struct FileResult {
    pub depot_file: String,
    pub client_file: PathBuf,
    pub outcome: Outcome,
}

pub fn check(record: &Record) -> Option<FileResult> {
    let depot_file = record.get("depotFile")?.clone();
    let client_file = PathBuf::from(record.get("clientFile")?);
    let outcome = check_one(record, &client_file);
    Some(FileResult {
        depot_file,
        client_file,
        outcome,
    })
}

fn check_one(record: &Record, path: &PathBuf) -> Outcome {
    let ty = record.get("headType").map(String::as_str).unwrap_or("");
    // +k files have $Id$-style keywords expanded on the client, so the server
    // digest (of unexpanded text) never matches. utf16 is stored transcoded.
    if ty.contains("+k") || ty.starts_with("k") {
        return Outcome::Skipped("keyword-expanded type");
    }
    if ty.starts_with("utf16") {
        return Outcome::Skipped("utf16 type");
    }
    let Some(expected) = record.get("digest") else {
        return Outcome::Skipped("no digest from server (run fstat with -Ol)");
    };

    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Outcome::Missing,
        Err(e) => {
            return Outcome::Mismatch {
                expected: expected.clone(),
                actual: format!("unreadable: {e}"),
            }
        }
    };
    if let (Some(size), Ok(meta)) = (record.get("fileSize"), file.metadata()) {
        if size.parse::<u64>().ok() != Some(meta.len()) {
            return Outcome::Mismatch {
                expected: format!("size {size}"),
                actual: format!("size {}", meta.len()),
            };
        }
    }
    match md5_hex(file) {
        Ok(actual) if actual.eq_ignore_ascii_case(expected) => Outcome::Ok,
        Ok(actual) => Outcome::Mismatch {
            expected: expected.clone(),
            actual,
        },
        Err(e) => Outcome::Mismatch {
            expected: expected.clone(),
            actual: format!("read error: {e}"),
        },
    }
}

fn md5_hex(file: File) -> std::io::Result<String> {
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut hasher = Md5::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(path: &std::path::Path, ty: &str, size: usize, digest: &str) -> Record {
        [
            ("depotFile", "//depot/f".to_string()),
            ("clientFile", path.display().to_string()),
            ("headType", ty.to_string()),
            ("fileSize", size.to_string()),
            ("digest", digest.to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }

    #[test]
    fn detects_truncation_and_accepts_good_file() {
        let dir = std::env::temp_dir().join(format!("assetguard-verify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("hero.uasset");
        // MD5("hello") = 5D41402ABC4B2A76B9719D911017C592
        std::fs::write(&p, b"hello").unwrap();
        let good = record(&p, "binary", 5, "5D41402ABC4B2A76B9719D911017C592");
        assert_eq!(check(&good).unwrap().outcome, Outcome::Ok);

        std::fs::write(&p, b"hel").unwrap();
        assert!(matches!(
            check(&good).unwrap().outcome,
            Outcome::Mismatch { .. }
        ));

        let kw = record(&p, "text+k", 3, "00");
        assert!(matches!(check(&kw).unwrap().outcome, Outcome::Skipped(_)));
    }
}
