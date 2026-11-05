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
//! The boot mode (player or developer) is read from [`MODE_PCR`]; see
//! [`MeasuredMode`]. Which PCR that is, and what the boot extends into it,
//! is provisional until the design doc pins it down.
//!
//! The socket API's encoding of [`Evidence`] lives in `fairplay-api`.
//!
//! Not done yet: trusting the AK (EK certificate chain and enrollment), and
//! per-vendor keys or ECDAA for privacy.

use std::collections::BTreeMap;

mod ima;
#[cfg(feature = "tpm")]
mod swtpm;
#[cfg(feature = "tpm")]
mod tpm;
mod wire;

#[cfg(feature = "tpm")]
pub use tpm::{collect_with, CollectOptions};

/// PCRs we quote, all in the SHA-256 bank, in ascending order. 0-7:
/// firmware and boot chain (7 holds Secure Boot state where the firmware
/// supports it). 10: IMA. [`MODE_PCR`]: the boot mode.
pub const QUOTED_PCRS: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, IMA_PCR, MODE_PCR];

/// The PCR the boot extends, once, with [`mode_event`] for the mode it
/// booted in.
///
/// PROVISIONAL: the design doc says the quote covers "the mode" but not
/// which PCR or what is extended. 13 is a placeholder (on Linux it is only
/// used by systemd-stub for system extension images, which the player image
/// won't load). The boot component that picks the mode must extend it
/// before running anything it didn't verify, in both modes, so a developer
/// boot can never reach the player value later.
pub const MODE_PCR: u8 = 13;

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
    ///
    /// Only part of this is authenticated by the quote: the hash chain covers
    /// the template data of entries for PCR 10, in order. Entries for other
    /// PCRs, each entry's template name, and the SHA-1 template digest field
    /// are not covered and may be anything. Policy that reads the log (e.g.
    /// "was fairplayd's hash measured") must use only PCR-10 entries'
    /// template data, and only after [`verify`] returned
    /// `ima_log_verified: true`.
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
    /// An IMA log was present and replays to the quoted PCR 10. This vouches
    /// only for the template data of the log's PCR-10 entries, in order; see
    /// [`Evidence::ima_log`] for what it does not cover.
    pub ima_log_verified: bool,
    pub secure_boot: Option<bool>,
    pub kernel_lockdown: Option<bool>,
    pub fairplayd_hash_ok: bool,
    pub lsm_program_hash_ok: bool,
    /// The boot mode, from the quoted [`MODE_PCR`].
    pub mode: MeasuredMode,
}

/// The modes the OS boots in (design doc, "Modes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Player,
    Developer,
}

impl Mode {
    fn tag(self) -> &'static [u8] {
        match self {
            Mode::Player => b"player",
            Mode::Developer => b"developer",
        }
    }
}

/// What the quoted [`MODE_PCR`] says about the boot mode.
///
/// This is only as good as the boot chain that extended it: a server should
/// trust `Player` only together with PCR values (0-7) of a boot chain it
/// knows extends the mode PCR correctly. Anything but `Player` must not be
/// treated as player mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MeasuredMode {
    /// The PCR is still all zeros: nothing measured a mode (a boot chain
    /// that predates this, or this VM).
    #[default]
    Unmeasured,
    /// Extended exactly once, with [`mode_event`]`(Player)`.
    Player,
    /// Extended exactly once, with [`mode_event`]`(Developer)`.
    Developer,
    /// Anything else: extended more than once (e.g. by root after boot), or
    /// with an event this verifier doesn't know.
    Unrecognized,
}

/// The SHA-256 digest the boot extends into [`MODE_PCR`] for `mode`:
/// `SHA-256("fairplay-os/mode/v1:" || "player" | "developer")`.
/// PROVISIONAL, like [`MODE_PCR`].
pub fn mode_event(mode: Mode) -> PcrValue {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"fairplay-os/mode/v1:");
    h.update(mode.tag());
    h.finalize().into()
}

/// The value [`MODE_PCR`] has after a boot in `mode`: one extend of
/// [`mode_event`] from the reset value (zeros).
pub fn mode_pcr_value(mode: Mode) -> PcrValue {
    pcr_extend(&[0; 32], &mode_event(mode))
}

/// What a SHA-256 PCR holds after extending `old` with `digest`.
pub fn pcr_extend(old: &PcrValue, digest: &PcrValue) -> PcrValue {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(old);
    h.update(digest);
    h.finalize().into()
}

fn measured_mode(pcr: &PcrValue) -> MeasuredMode {
    if *pcr == [0; 32] {
        MeasuredMode::Unmeasured
    } else if *pcr == mode_pcr_value(Mode::Player) {
        MeasuredMode::Player
    } else if *pcr == mode_pcr_value(Mode::Developer) {
        MeasuredMode::Developer
    } else {
        MeasuredMode::Unrecognized
    }
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
    /// The server passed an empty nonce, which would disable replay
    /// protection. A server bug, not a client failure.
    EmptyNonce,
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
            Rejection::EmptyNonce => f.write_str("expected nonce is empty"),
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

    // 0. An empty nonce would match a quote with empty extraData: no
    // freshness at all. Refuse before looking at anything else.
    if expected_nonce.is_empty() {
        return Err(Rejection::EmptyNonce);
    }

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

    let mode = measured_mode(&pcrs[&MODE_PCR]);
    Ok(Verdict {
        quote_valid: true,
        pcrs,
        ima_log_verified,
        mode,
        ..Verdict::default()
    })
}

/// Test helpers: build IMA log entries and compute what they extend, and
/// (with the `tpm` feature) run a software TPM.
#[doc(hidden)]
pub mod testing {
    pub use crate::ima::{ima_ng_entry, sha256_extend_value};
    #[cfg(feature = "tpm")]
    pub use crate::swtpm::Swtpm;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_pcrs_ascending() {
        // verify hashes the values in this order, as the TPM does.
        assert!(QUOTED_PCRS.windows(2).all(|w| w[0] < w[1]));
        assert!(QUOTED_PCRS.contains(&MODE_PCR));
    }

    #[test]
    fn mode_values() {
        let player = mode_pcr_value(Mode::Player);
        let developer = mode_pcr_value(Mode::Developer);
        assert_ne!(player, developer);
        assert_eq!(measured_mode(&[0; 32]), MeasuredMode::Unmeasured);
        assert_eq!(measured_mode(&player), MeasuredMode::Player);
        assert_eq!(measured_mode(&developer), MeasuredMode::Developer);
        // Root extending "player" again after a developer boot gets nowhere.
        let upgraded = pcr_extend(&developer, &mode_event(Mode::Player));
        assert_eq!(measured_mode(&upgraded), MeasuredMode::Unrecognized);
        let twice = pcr_extend(&player, &mode_event(Mode::Player));
        assert_eq!(measured_mode(&twice), MeasuredMode::Unrecognized);
    }

    #[test]
    fn empty_nonce_rejected_first() {
        // Garbage everywhere else: the empty nonce must be the reason.
        let ev = Evidence {
            nonce: Vec::new(),
            quote: Vec::new(),
            signature: Vec::new(),
            pcrs: BTreeMap::new(),
            ima_log: None,
            ak_public: AkPublic(Vec::new()),
        };
        assert_eq!(verify(&ev, &[], &ev.ak_public), Err(Rejection::EmptyNonce));
        assert_eq!(
            verify(&ev, b"n", &ev.ak_public),
            Err(Rejection::BadAkPublic)
        );
    }
}
