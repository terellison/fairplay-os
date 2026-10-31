//! Attestation (milestone 10). API shape only for now.
//!
//! The client answers a server nonce with a TPM quote over the boot PCRs plus
//! the IMA event log. The verifier, which runs on the vendor's server, checks
//! the quote signature, replays the log against the PCRs, and turns the result
//! into a [`Verdict`]. The OS reports facts; the server sets policy.

/// PCRs we quote. 0-7: firmware and boot chain (7 holds Secure Boot state
/// where the firmware supports it). 10: IMA measurements.
pub const QUOTED_PCRS: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 10];

/// What the client sends back for a nonce.
#[derive(Debug, Clone)]
pub struct Evidence {
    pub nonce: Vec<u8>,
    /// TPMS_ATTEST blob, signed by the attestation key.
    pub quote: Vec<u8>,
    pub signature: Vec<u8>,
    /// /sys/kernel/security/ima/binary_runtime_measurements
    pub ima_log: Vec<u8>,
}

/// Facts the verifier establishes. Matchmaking policy is built from these.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdict {
    pub quote_valid: bool,
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

/// Collect evidence on the client. Implemented in milestone 10.
pub fn collect(_nonce: &[u8]) -> Result<Evidence, Error> {
    #[cfg(feature = "tpm")]
    {
        // TODO(m10): tss_esapi Context on /dev/tpmrm0, load or create the AK,
        // Quote(QUOTED_PCRS, nonce), read the IMA log.
        Err(Error::Other("not implemented yet".into()))
    }
    #[cfg(not(feature = "tpm"))]
    Err(Error::NoTpm)
}

/// Verify evidence on the server. Implemented in milestone 10.
pub fn verify(_evidence: &Evidence, _expected_nonce: &[u8]) -> Verdict {
    // TODO(m10): check signature against the enrolled AK, nonce freshness,
    // replay IMA log into PCR 10, parse the event log for Secure Boot state.
    Verdict::default()
}
