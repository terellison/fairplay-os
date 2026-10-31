//! Replaying the binary IMA log into a SHA-256 PCR.
//!
//! Each entry in `binary_runtime_measurements` (little-endian on the
//! platforms we target) is:
//!
//! ```text
//! u32 pcr | [u8; 20] sha1 template digest | u32 name_len | name
//!         | u32 data_len | template data
//! ```
//!
//! For every template except the legacy `ima` one, the kernel extends each
//! PCR bank with that bank's hash of the template data as it appears in the
//! log (each field as `u32 len || bytes`). A violation is logged with an
//! all-zero digest and extends all-ones instead.

use sha2::{Digest, Sha256};

fn take<'a>(buf: &mut &'a [u8], n: usize, what: &str) -> Result<&'a [u8], String> {
    if buf.len() < n {
        return Err(format!("truncated {what}"));
    }
    let (head, tail) = buf.split_at(n);
    *buf = tail;
    Ok(head)
}

fn le32(buf: &mut &[u8], what: &str) -> Result<u32, String> {
    Ok(u32::from_le_bytes(take(buf, 4, what)?.try_into().unwrap()))
}

/// Replay every entry for `pcr` into a fresh SHA-256 PCR.
pub fn replay_sha256(mut log: &[u8], pcr: u8) -> Result<[u8; 32], String> {
    let mut value = [0u8; 32];
    let mut index = 0usize;
    while !log.is_empty() {
        let at = |m: String| format!("entry {index}: {m}");
        let entry_pcr = le32(&mut log, "pcr index").map_err(at)?;
        let sha1 = take(&mut log, 20, "template digest").map_err(at)?;
        let name_len = le32(&mut log, "name length").map_err(at)? as usize;
        if name_len > 255 {
            return Err(at("template name too long".into()));
        }
        let name = take(&mut log, name_len, "template name").map_err(at)?;
        if name == b"ima" {
            return Err(at("legacy 'ima' template is not supported".into()));
        }
        let data_len = le32(&mut log, "template data length").map_err(at)? as usize;
        let data = take(&mut log, data_len, "template data").map_err(at)?;
        if entry_pcr == u32::from(pcr) {
            let ext = if sha1.iter().all(|&b| b == 0) {
                [0xffu8; 32]
            } else {
                sha256_extend_value(data)
            };
            value = Sha256::new()
                .chain_update(value)
                .chain_update(ext)
                .finalize()
                .into();
        }
        index += 1;
    }
    Ok(value)
}

/// What an entry with this template data extends into the SHA-256 bank.
pub fn sha256_extend_value(template_data: &[u8]) -> [u8; 32] {
    Sha256::digest(template_data).into()
}

/// Build one `ima-ng` log entry for a file with this SHA-256 digest. Returns
/// (entry bytes, template data). The SHA-1 template digest field is filled
/// with a non-zero placeholder: the SHA-256 replay doesn't use it.
pub fn ima_ng_entry(pcr: u32, file_sha256: &[u8; 32], path: &str) -> (Vec<u8>, Vec<u8>) {
    let mut d_ng = b"sha256:\0".to_vec();
    d_ng.extend_from_slice(file_sha256);
    let mut n_ng = path.as_bytes().to_vec();
    n_ng.push(0);
    let mut data = Vec::new();
    for field in [&d_ng, &n_ng] {
        data.extend_from_slice(&(field.len() as u32).to_le_bytes());
        data.extend_from_slice(field);
    }
    let mut entry = pcr.to_le_bytes().to_vec();
    entry.extend_from_slice(&[0x11; 20]);
    entry.extend_from_slice(&6u32.to_le_bytes());
    entry.extend_from_slice(b"ima-ng");
    entry.extend_from_slice(&(data.len() as u32).to_le_bytes());
    entry.extend_from_slice(&data);
    (entry, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extend(pcr: [u8; 32], v: [u8; 32]) -> [u8; 32] {
        Sha256::new()
            .chain_update(pcr)
            .chain_update(v)
            .finalize()
            .into()
    }

    #[test]
    fn empty_log_is_zero_pcr() {
        assert_eq!(replay_sha256(&[], 10).unwrap(), [0; 32]);
    }

    #[test]
    fn replays_entries_for_the_pcr_only() {
        let (a, da) = ima_ng_entry(10, &[1; 32], "/usr/bin/fairplayd");
        let (b, _) = ima_ng_entry(11, &[2; 32], "/elsewhere");
        let (c, dc) = ima_ng_entry(10, &[3; 32], "/usr/lib/x.so");
        let log = [a, b, c].concat();
        let want = extend(
            extend([0; 32], sha256_extend_value(&da)),
            sha256_extend_value(&dc),
        );
        assert_eq!(replay_sha256(&log, 10).unwrap(), want);
    }

    #[test]
    fn violation_extends_all_ones() {
        let (mut e, _) = ima_ng_entry(10, &[1; 32], "/x");
        e[4..24].fill(0);
        assert_eq!(replay_sha256(&e, 10).unwrap(), extend([0; 32], [0xff; 32]));
    }

    #[test]
    fn truncated_log_is_an_error() {
        let (e, _) = ima_ng_entry(10, &[1; 32], "/x");
        let err = replay_sha256(&e[..e.len() - 1], 10).unwrap_err();
        assert!(err.contains("entry 0"), "{err}");
    }
}
