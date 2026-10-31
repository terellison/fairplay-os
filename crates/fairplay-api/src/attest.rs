//! How `attest` evidence travels on the socket (milestone 10).
//!
//! fairplayd answers `attest` with [`Reply::Evidence`](crate::Reply), whose
//! payload is a [`WireEvidence`]: the [`fairplay_attest::Evidence`] the TPM
//! produced, in JSON, with a version number. The game hands it to its
//! server unchanged; the server decodes it with [`WireEvidence::decode`] and
//! checks it with [`fairplay_attest::verify`].
//!
//! ```text
//! {"version":1,"nonce":"00ff","quote":"<base64>","signature":"<base64>",
//!  "pcrs":{"0":"<hex>",...,"13":"<hex>"},"ima_log":"<base64>","ak_public":"<base64>"}
//! ```
//!
//! Binary blobs are standard base64 (with padding), the nonce and PCR values
//! are lowercase hex, and `pcrs` is the SHA-256 bank keyed by PCR index.
//! `ima_log` is left out when fairplayd couldn't read the log. Nothing here
//! is trusted on its own: the quote's signature covers the nonce and PCR
//! values, and the IMA log is checked by replaying it.
//!
//! Versioning: a decoder accepts only the [`EVIDENCE_VERSION`] it knows and
//! says so otherwise. Fields it doesn't know are ignored, so they can only
//! carry information that changes nothing about verification; anything
//! else needs a new version.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use fairplay_attest::{AkPublic, Evidence, PcrValue};
use serde::{Deserialize, Serialize};

/// The evidence encoding this crate writes and reads.
pub const EVIDENCE_VERSION: u32 = 1;

/// TPM attestation evidence as it appears in an `attest` reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireEvidence {
    /// [`EVIDENCE_VERSION`] for evidence this crate wrote.
    pub version: u32,
    /// The caller's nonce, hex, as the quote's qualifying data.
    pub nonce: String,
    /// Marshalled TPMS_ATTEST, base64.
    pub quote: String,
    /// Marshalled TPMT_SIGNATURE over `quote`, base64.
    pub signature: String,
    /// SHA-256 PCR values, hex, keyed by index.
    pub pcrs: BTreeMap<u8, String>,
    /// The binary IMA log, base64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ima_log: Option<String>,
    /// The attestation key as the client reports it (SEC1 uncompressed
    /// P-256 point), base64. The verifier checks against the AK it
    /// enrolled, not this.
    pub ak_public: String,
}

/// Why evidence on the wire couldn't be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Written by a newer (or older) encoder than this one.
    UnsupportedVersion(u32),
    /// A field isn't what its encoding says it should be.
    Field {
        field: &'static str,
        problem: String,
    },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::UnsupportedVersion(v) => write!(
                f,
                "evidence version {v} is not supported (this decoder reads version {EVIDENCE_VERSION})"
            ),
            DecodeError::Field { field, problem } => write!(f, "evidence {field}: {problem}"),
        }
    }
}

impl std::error::Error for DecodeError {}

fn bad(field: &'static str, problem: impl Into<String>) -> DecodeError {
    DecodeError::Field {
        field,
        problem: problem.into(),
    }
}

/// Lowercase hex.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex in either case; `None` if it isn't.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

impl WireEvidence {
    /// Encode evidence for the socket.
    pub fn encode(ev: &Evidence) -> Self {
        WireEvidence {
            version: EVIDENCE_VERSION,
            nonce: to_hex(&ev.nonce),
            quote: B64.encode(&ev.quote),
            signature: B64.encode(&ev.signature),
            pcrs: ev.pcrs.iter().map(|(&n, v)| (n, to_hex(v))).collect(),
            ima_log: ev.ima_log.as_ref().map(|l| B64.encode(l)),
            ak_public: B64.encode(&ev.ak_public.0),
        }
    }

    /// Decode evidence for [`fairplay_attest::verify`]. Checks the
    /// encoding only; whether the evidence is any good is `verify`'s job.
    pub fn decode(&self) -> Result<Evidence, DecodeError> {
        if self.version != EVIDENCE_VERSION {
            return Err(DecodeError::UnsupportedVersion(self.version));
        }
        let b64 = |field, s: &str| B64.decode(s).map_err(|e| bad(field, e.to_string()));
        let nonce = from_hex(&self.nonce).ok_or_else(|| bad("nonce", "not hex"))?;
        let mut pcrs = BTreeMap::new();
        for (&n, v) in &self.pcrs {
            // PCR indices on a TPM 2.0 PC client platform: 0-23.
            if n > 23 {
                return Err(bad("pcrs", format!("no PCR {n}")));
            }
            let value: PcrValue = from_hex(v)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| bad("pcrs", format!("PCR {n} is not 32 bytes of hex")))?;
            pcrs.insert(n, value);
        }
        Ok(Evidence {
            nonce,
            quote: b64("quote", &self.quote)?,
            signature: b64("signature", &self.signature)?,
            pcrs,
            ima_log: self
                .ima_log
                .as_deref()
                .map(|l| b64("ima_log", l))
                .transpose()?,
            ak_public: AkPublic(b64("ak_public", &self.ak_public)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode, Reply, Response};

    fn sample(ima_log: Option<Vec<u8>>) -> Evidence {
        Evidence {
            nonce: vec![0x00, 0xff, 0x10],
            quote: b"\xffTCG\x80\x18quote bytes".to_vec(),
            signature: vec![0, 0x18, 0, 0x0b, 1, 2, 3],
            pcrs: [(0u8, [0u8; 32]), (10, [0xab; 32]), (13, [0x5c; 32])]
                .into_iter()
                .collect(),
            ima_log,
            ak_public: AkPublic([4u8].into_iter().chain([7u8; 64]).collect()),
        }
    }

    type Edit = fn(&mut WireEvidence);

    fn same(a: &Evidence, b: &Evidence) {
        assert_eq!(a.nonce, b.nonce);
        assert_eq!(a.quote, b.quote);
        assert_eq!(a.signature, b.signature);
        assert_eq!(a.pcrs, b.pcrs);
        assert_eq!(a.ima_log, b.ima_log);
        assert_eq!(a.ak_public, b.ak_public);
    }

    #[test]
    fn round_trips_through_a_reply_line() {
        for ev in [sample(None), sample(Some(vec![1, 2, 3, 0, 255]))] {
            let line = encode(&Response::Ok(Reply::Evidence(Box::new(
                WireEvidence::encode(&ev),
            ))));
            let Response::Ok(Reply::Evidence(wire)) = serde_json::from_slice(&line).unwrap() else {
                panic!("not evidence")
            };
            same(&wire.decode().unwrap(), &ev);
        }
    }

    #[test]
    fn wire_format_is_stable() {
        let text = String::from_utf8(encode(&WireEvidence::encode(&sample(None)))).unwrap();
        assert!(
            text.starts_with("{\"version\":1,\"nonce\":\"00ff10\","),
            "{text}"
        );
        assert!(
            text.contains(&format!("\"13\":\"{}\"", "5c".repeat(32))),
            "{text}"
        );
        assert!(text.contains("\"signature\":\"ABgACwECAw==\""), "{text}");
        assert!(!text.contains("ima_log"), "{text}");

        // Unknown fields are ignored; uppercase hex is accepted.
        let json = text.trim_end().replacen('{', "{\"comment\":\"x\",", 1);
        let json = json.replace("00ff10", "00FF10");
        let wire: WireEvidence = serde_json::from_str(&json).unwrap();
        same(&wire.decode().unwrap(), &sample(None));
    }

    #[test]
    fn rejects_other_versions_and_bad_fields() {
        let good = WireEvidence::encode(&sample(Some(vec![9])));
        let mut w = good.clone();
        w.version = 2;
        assert_eq!(w.decode().unwrap_err(), DecodeError::UnsupportedVersion(2));
        assert!(w.decode().unwrap_err().to_string().contains("version 2"));

        let cases: [(&str, Edit); 7] = [
            ("nonce", |w| w.nonce = "0g".into()),
            ("nonce", |w| w.nonce = "abc".into()),
            ("quote", |w| w.quote = "not base64!".into()),
            ("ima_log", |w| w.ima_log = Some("***".into())),
            ("pcrs", |w| {
                w.pcrs.insert(24, "00".repeat(32));
            }),
            ("pcrs", |w| {
                w.pcrs.insert(1, "00".repeat(31));
            }),
            ("ak_public", |w| w.ak_public = "@".into()),
        ];
        for (field, edit) in cases {
            let mut w = good.clone();
            edit(&mut w);
            match w.decode() {
                Err(DecodeError::Field { field: f, .. }) => assert_eq!(f, field),
                other => panic!("{field}: {other:?}"),
            }
        }

        // A version-1 decoder never silently reads a missing required field.
        let mut v = serde_json::to_value(&good).unwrap();
        v.as_object_mut().unwrap().remove("quote");
        assert!(serde_json::from_value::<WireEvidence>(v).is_err());
    }

    #[test]
    fn hex() {
        assert_eq!(to_hex(&[0, 0xab, 0xff]), "00abff");
        assert_eq!(from_hex("00abFF"), Some(vec![0, 0xab, 0xff]));
        assert_eq!(from_hex(""), Some(vec![]));
        for bad in ["0", "zz", "+1", "0 "] {
            assert_eq!(from_hex(bad), None, "{bad:?}");
        }
    }
}
