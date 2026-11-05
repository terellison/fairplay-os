//! `attest` (milestone 10): a TPM quote over the boot PCRs and the IMA log,
//! for the caller's nonce, encoded as `fairplay-api`'s `WireEvidence`.
//!
//! Without a TPM (this VM boots with none) the answer is `unavailable`;
//! fairplayd never makes evidence up. Built without the `tpm` feature, it is
//! always `unavailable`.
//!
//! Pointing fairplayd at another TPM (`--tpm-tcti`, e.g. swtpm in tests)
//! doesn't help a cheater: the server checks the quote against the AK it
//! enrolled for this machine's TPM.

use std::{path::PathBuf, sync::Mutex};

use fairplay_api::{parse_nonce, ApiError, ErrorCode, Reply, WireEvidence};

/// Which TPM and IMA log to use.
#[derive(Debug, Clone)]
pub struct AttestConfig {
    /// A libtss2 TCTI string.
    pub tcti: String,
    /// The binary IMA log; `None` sends none.
    #[cfg_attr(not(feature = "tpm"), allow(dead_code))]
    pub ima_log: Option<PathBuf>,
}

/// One quote at a time: each creates the attestation key, which takes a
/// real TPM a while, and the TPM has few object slots.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Answers `attest`. Blocks on the TPM; call it off the async runtime.
pub fn attest(cfg: &AttestConfig, nonce: &str) -> Result<Reply, ApiError> {
    let with_nonce = |mut e: ApiError| {
        e.nonce = Some(nonce.to_owned());
        e
    };
    let Some(bytes) = parse_nonce(nonce) else {
        return Err(with_nonce(ApiError::new(
            ErrorCode::BadRequest,
            "nonce must be 1-64 bytes of hex",
        )));
    };
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    match collect(cfg, &bytes) {
        Ok(ev) => Ok(Reply::Evidence(Box::new(WireEvidence::encode(&ev)))),
        Err(fairplay_attest::Error::NoTpm) => Err(with_nonce(ApiError::new(
            ErrorCode::Unavailable,
            no_tpm_message(cfg),
        ))),
        Err(fairplay_attest::Error::Other(m)) => Err(with_nonce(ApiError::new(
            ErrorCode::Unavailable,
            format!("TPM: {m}"),
        ))),
    }
}

#[cfg(feature = "tpm")]
fn collect(
    cfg: &AttestConfig,
    nonce: &[u8],
) -> Result<fairplay_attest::Evidence, fairplay_attest::Error> {
    fairplay_attest::collect_with(
        nonce,
        &fairplay_attest::CollectOptions {
            tcti: cfg.tcti.clone(),
            ima_log: cfg.ima_log.clone(),
        },
    )
}

#[cfg(not(feature = "tpm"))]
fn collect(
    _: &AttestConfig,
    _: &[u8],
) -> Result<fairplay_attest::Evidence, fairplay_attest::Error> {
    Err(fairplay_attest::Error::NoTpm)
}

fn no_tpm_message(cfg: &AttestConfig) -> String {
    if cfg!(feature = "tpm") {
        format!(
            "no TPM at {}; attestation needs one (milestone 10)",
            cfg.tcti
        )
    } else {
        "fairplayd was built without TPM support (the tpm feature)".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_tpm() -> AttestConfig {
        AttestConfig {
            tcti: "device:/dev/fairplay-no-such-tpm".into(),
            ima_log: None,
        }
    }

    #[test]
    fn bad_nonce_is_bad_request() {
        for bad in ["", "0", "zz", &"ab".repeat(65)] {
            let e = attest(&no_tpm(), bad).unwrap_err();
            assert_eq!(e.code, ErrorCode::BadRequest, "{bad:?}");
            assert_eq!(e.nonce.as_deref(), Some(bad));
        }
    }

    #[test]
    fn no_tpm_is_unavailable_never_evidence() {
        let e = attest(&no_tpm(), "00ff").unwrap_err();
        assert_eq!(e.code, ErrorCode::Unavailable);
        assert_eq!(e.nonce.as_deref(), Some("00ff"));
        assert!(e.message.contains("TPM"), "{}", e.message);
    }

    /// The whole path a vendor sees, against a software TPM: a request line
    /// in, a reply line out, decoded and checked by the server-side
    /// verifier. Skips (passes) without swtpm.
    #[cfg(feature = "tpm")]
    #[test]
    fn swtpm_attest_end_to_end() {
        use fairplay_api::{decode_request, encode, Request, Response};
        use fairplay_attest::{
            mode_event, testing::Swtpm, verify, MeasuredMode, Mode, Rejection, MODE_PCR,
        };

        let Some(tpm) = Swtpm::start("fairplayd-attest") else {
            return;
        };
        // What a player-mode boot would have done before fairplayd ran.
        tpm.extend(MODE_PCR, mode_event(Mode::Player));
        let cfg = AttestConfig {
            tcti: tpm.tcti(),
            ima_log: None,
        };

        let nonce = "5e7e2c0ffee0123456789abcdef0";
        let Request::Attest { nonce: got } =
            decode_request(format!("{{\"op\":\"attest\",\"nonce\":\"{nonce}\"}}\n").as_bytes())
                .unwrap()
        else {
            panic!("not attest")
        };
        let line = encode(&Response::from(attest(&cfg, &got)));

        // The vendor's server.
        let Response::Ok(Reply::Evidence(wire)) = serde_json::from_slice(&line).unwrap() else {
            panic!("no evidence: {}", String::from_utf8_lossy(&line))
        };
        let ev = wire.decode().expect("decodes");
        let expected = parse_nonce(nonce).unwrap();
        // AK enrollment isn't built yet: trust the key the evidence names,
        // but check it is this TPM's by quoting directly.
        let direct = fairplay_attest::collect_with(
            &expected,
            &fairplay_attest::CollectOptions {
                tcti: tpm.tcti(),
                ima_log: None,
            },
        )
        .unwrap();
        assert_eq!(ev.ak_public, direct.ak_public);
        let verdict = verify(&ev, &expected, &direct.ak_public).expect("verifies");
        assert!(verdict.quote_valid);
        assert_eq!(verdict.mode, MeasuredMode::Player);

        // A replay for another nonce is refused.
        assert_eq!(
            verify(&ev, b"another nonce", &direct.ak_public),
            Err(Rejection::NonceMismatch)
        );

        // Root extending the mode PCR afterwards makes it unrecognized,
        // not player.
        tpm.extend(MODE_PCR, mode_event(Mode::Player));
        let Ok(Reply::Evidence(wire)) = attest(&cfg, nonce) else {
            panic!("no evidence")
        };
        let verdict = verify(&wire.decode().unwrap(), &expected, &direct.ak_public).unwrap();
        assert_eq!(verdict.mode, MeasuredMode::Unrecognized);
    }
}
