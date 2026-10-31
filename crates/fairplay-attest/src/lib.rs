//! Attestation (milestone 10).
//!
//! The client answers a server nonce with a TPM quote over the boot PCRs plus
//! the IMA event log ([`collect`]). The verifier, which runs on the vendor's
//! server, checks the quote signature against the attestation key (AK) it
//! trusts, checks the nonce, checks the reported PCR values against the
//! quoted digest, and replays the IMA log into PCR 10 ([`verify`]). The OS
//! reports facts; the server sets policy.
//!
//! `collect` needs the `tpm` feature (libtss2). `verify` is pure Rust so a
//! server can run it without a TPM stack.
//!
//! Not done yet: trusting the AK (EK certificate chain and enrollment),
//! measuring the player/developer mode, per-vendor keys or ECDAA for privacy,
//! and the wire encoding of [`Evidence`] for the socket API.

use std::collections::BTreeMap;

mod ima;
#[cfg(feature = "tpm")]
mod tpm;
mod wire;

#[cfg(feature = "tpm")]
pub use tpm::{collect_with, CollectOptions};

/// PCRs we quote, all in the SHA-256 bank. 0-7: firmware and boot chain
/// (7 holds Secure Boot state where the firmware supports it). 10: IMA.
pub const QUOTED_PCRS: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 10];

/// The PCR IMA extends by default.
pub const IMA_PCR: u8 = 10;

/// Where the kernel exposes the IMA log. Readable by root only.
pub const IMA_LOG_PATH: &str = "/sys/kernel/security/ima/binary_runtime_measurements";

/// A SHA-256 PCR value.
pub type PcrValue = [u8; 32];

/// The public part of an attestation key: an uncompressed SEC1 P-256 point
/// (`0x04 || x || y`, 65 bytes). The AK is a restricted ECDSA-SHA256 signing
/// key, so it only signs structures the TPM itself produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkPublic(pub Vec<u8>);

/// What the client sends back for a nonce.
#[derive(Debug, Clone)]
pub struct Evidence {
    pub nonce: Vec<u8>,
    /// Marshalled TPMS_ATTEST (a TPM2_Quote), signed by the attestation key.
    pub quote: Vec<u8>,
    /// Marshalled TPMT_SIGNATURE over `quote`.
    pub signature: Vec<u8>,
    /// SHA-256 values of [`QUOTED_PCRS`], read next to the quote.
    pub pcrs: BTreeMap<u8, PcrValue>,
    /// The binary IMA log ([`IMA_LOG_PATH`]), if it was readable.
    pub ima_log: Option<Vec<u8>>,
    /// The key that signed the quote, as the client reports it. The verifier
    /// must not trust this; it checks against the AK it enrolled.
    pub ak_public: AkPublic,
}

/// Facts the verifier establishes. Matchmaking policy is built from these.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdict {
    pub quote_valid: bool,
    /// The PCR values the quote vouches for.
    pub pcrs: BTreeMap<u8, PcrValue>,
    /// An IMA log was present and replays to the quoted PCR 10.
    pub ima_log_verified: bool,
    pub secure_boot: Option<bool>,
    pub kernel_lockdown: Option<bool>,
    pub fairplayd_hash_ok: bool,
    pub lsm_program_hash_ok: bool,
}

#[derive(Debug)]
pub enum Error {
    /// Built without the `tpm` feature, or no TPM device present.
    NoTpm,
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NoTpm => f.write_str("no TPM"),
            Error::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

/// Why the verifier rejected evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// The trusted AK isn't a valid P-256 point.
    BadAkPublic,
    /// The signature isn't a TPMT_SIGNATURE we can check (we accept
    /// ECDSA with SHA-256 only).
    MalformedSignature(String),
    /// The signature doesn't verify against the trusted AK.
    BadSignature,
    /// The signed blob doesn't parse as a TPMS_ATTEST.
    MalformedQuote(String),
    /// The signed blob is a TPM attestation, but not a quote.
    NotAQuote,
    /// The quote was made for a different nonce (stale or replayed).
    NonceMismatch,
    /// The quote doesn't cover exactly the SHA-256 bank of [`QUOTED_PCRS`].
    PcrSelectionMismatch,
    /// The evidence is missing a value for this PCR.
    MissingPcr(u8),
    /// The reported PCR values don't hash to the quoted PCR digest.
    PcrDigestMismatch,
    /// The IMA log doesn't parse.
    MalformedImaLog(String),
    /// Replaying the IMA log doesn't reproduce the quoted PCR 10.
    ImaLogMismatch {
        quoted: PcrValue,
        replayed: PcrValue,
    },
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejection::BadAkPublic => f.write_str("trusted AK is not a P-256 public key"),
            Rejection::MalformedSignature(m) => write!(f, "malformed signature: {m}"),
            Rejection::BadSignature => f.write_str("quote signature does not verify with the AK"),
            Rejection::MalformedQuote(m) => write!(f, "malformed quote: {m}"),
            Rejection::NotAQuote => f.write_str("attestation is not a TPM2_Quote"),
            Rejection::NonceMismatch => f.write_str("quote is not for the expected nonce"),
            Rejection::PcrSelectionMismatch => {
                f.write_str("quote does not cover the expected PCR selection")
            }
            Rejection::MissingPcr(n) => write!(f, "evidence has no value for PCR {n}"),
            Rejection::PcrDigestMismatch => {
                f.write_str("reported PCR values do not match the quoted digest")
            }
            Rejection::MalformedImaLog(m) => write!(f, "malformed IMA log: {m}"),
            Rejection::ImaLogMismatch { .. } => {
                f.write_str("IMA log replay does not reproduce quoted PCR 10")
            }
        }
    }
}

impl std::error::Error for Rejection {}

/// Collect evidence on the client from the system TPM (`/dev/tpmrm0`) and
/// IMA log. Returns [`Error::NoTpm`] when built without the `tpm` feature or
/// when there is no TPM device.
pub fn collect(nonce: &[u8]) -> Result<Evidence, Error> {
    #[cfg(feature = "tpm")]
    {
        if !std::path::Path::new("/dev/tpmrm0").exists() {
            return Err(Error::NoTpm);
        }
        collect_with(nonce, &CollectOptions::default())
    }
    #[cfg(not(feature = "tpm"))]
    {
        let _ = nonce;
        Err(Error::NoTpm)
    }
}

/// Verify evidence on the server against the nonce it sent and the AK it
/// trusts for this machine. On success the [`Verdict`] lists the PCR values
/// the TPM vouched for; policy on those values is the server's business.
pub fn verify(
    evidence: &Evidence,
    expected_nonce: &[u8],
    trusted_ak: &AkPublic,
) -> Result<Verdict, Rejection> {
    use p256::ecdsa::signature::Verifier;

    // 1. The signature, over the exact bytes we are about to parse.
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&trusted_ak.0)
        .map_err(|_| Rejection::BadAkPublic)?;
    let (r, s) = wire::parse_ecdsa_signature(&evidence.signature)
        .map_err(|e| Rejection::MalformedSignature(e.0))?;
    let sig = p256::ecdsa::Signature::from_scalars(r, s)
        .map_err(|_| Rejection::MalformedSignature("r or s out of range".into()))?;
    key.verify(&evidence.quote, &sig)
        .map_err(|_| Rejection::BadSignature)?;

    // 2. It is a quote, for our nonce.
    let quote = wire::parse_quote(&evidence.quote).map_err(|e| match e {
        wire::ParseError(m) if m == wire::NOT_A_QUOTE => Rejection::NotAQuote,
        wire::ParseError(m) => Rejection::MalformedQuote(m),
    })?;
    if quote.extra_data != expected_nonce {
        return Err(Rejection::NonceMismatch);
    }

    // 3. Over the PCRs we asked for, and the reported values match.
    let expected_selection: Vec<(u16, Vec<u8>)> =
        vec![(wire::TPM_ALG_SHA256, wire::pcr_bitmap(QUOTED_PCRS))];
    if quote.pcr_select != expected_selection {
        return Err(Rejection::PcrSelectionMismatch);
    }
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    let mut pcrs = BTreeMap::new();
    // The TPM concatenates selected PCRs in ascending index order.
    for &n in QUOTED_PCRS {
        let v = evidence.pcrs.get(&n).ok_or(Rejection::MissingPcr(n))?;
        sha2::Digest::update(&mut hasher, v);
        pcrs.insert(n, *v);
    }
    if sha2::Digest::finalize(hasher).as_slice() != quote.pcr_digest.as_slice() {
        return Err(Rejection::PcrDigestMismatch);
    }

    // 4. The IMA log, if any, replays to the quoted PCR 10.
    let mut ima_log_verified = false;
    if let Some(log) = &evidence.ima_log {
        let replayed = ima::replay_sha256(log, IMA_PCR).map_err(Rejection::MalformedImaLog)?;
        let quoted = pcrs[&IMA_PCR];
        if replayed != quoted {
            return Err(Rejection::ImaLogMismatch { quoted, replayed });
        }
        ima_log_verified = true;
    }

    Ok(Verdict {
        quote_valid: true,
        pcrs,
        ima_log_verified,
        ..Verdict::default()
    })
}

/// Test helpers: build IMA log entries and compute what they extend.
#[doc(hidden)]
pub mod testing {
    pub use crate::ima::{ima_ng_entry, sha256_extend_value};
}
