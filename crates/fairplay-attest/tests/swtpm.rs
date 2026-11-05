//! Quote and verify against a software TPM. Each test starts its own `swtpm`
//! (see `fairplay_attest::testing::Swtpm`).
//!
//! Needs the `tpm` feature and `swtpm` on PATH (`apt install swtpm`); without
//! either, the tests print why and pass, so plain `cargo test` keeps working.
#![cfg(feature = "tpm")]

use std::path::PathBuf;

use fairplay_attest::testing::{ima_ng_entry, sha256_extend_value, Swtpm};
use fairplay_attest::{
    collect_with, mode_event, verify, CollectOptions, Error, Evidence, MeasuredMode, Mode,
    Rejection, IMA_PCR, MODE_PCR,
};

fn options(tpm: &Swtpm, ima_log: Option<PathBuf>) -> CollectOptions {
    CollectOptions {
        tcti: tpm.tcti(),
        ima_log,
    }
}

const NONCE: &[u8] = b"server-nonce-0123456789abcdef";

fn fresh(tpm: &Swtpm, ima_log: Option<PathBuf>) -> Evidence {
    collect_with(NONCE, &options(tpm, ima_log)).expect("collect")
}

/// Write a synthetic IMA log, extend PCR 10 to match it, return its path.
fn synthetic_ima_log(tpm: &Swtpm) -> PathBuf {
    let mut log = Vec::new();
    for (i, path) in ["boot_aggregate", "/usr/bin/fairplayd", "/usr/lib/game.so"]
        .iter()
        .enumerate()
    {
        let (entry, data) = ima_ng_entry(u32::from(IMA_PCR), &[i as u8 + 1; 32], path);
        tpm.extend(IMA_PCR, sha256_extend_value(&data));
        log.extend_from_slice(&entry);
    }
    let path = tpm.dir().join("binary_runtime_measurements");
    std::fs::write(&path, log).unwrap();
    path
}

#[test]
fn fresh_quote_verifies() {
    let Some(tpm) = Swtpm::start("fresh") else {
        return;
    };
    let ev = fresh(&tpm, None);
    assert!(ev.ima_log.is_none());
    let verdict = verify(&ev, NONCE, &ev.ak_public).expect("verify");
    assert!(verdict.quote_valid);
    assert!(!verdict.ima_log_verified);
    assert_eq!(verdict.pcrs.len(), fairplay_attest::QUOTED_PCRS.len());
    // Nothing extended the mode PCR.
    assert_eq!(verdict.mode, MeasuredMode::Unmeasured);

    // The AK is a primary: the same TPM derives the same key every time.
    let again = fresh(&tpm, None);
    assert_eq!(again.ak_public, ev.ak_public);
}

#[test]
fn wrong_nonce_rejected() {
    let Some(tpm) = Swtpm::start("nonce") else {
        return;
    };
    let ev = fresh(&tpm, None);
    assert_eq!(
        verify(&ev, b"a-different-nonce", &ev.ak_public),
        Err(Rejection::NonceMismatch)
    );
}

#[test]
fn tampered_pcr_rejected() {
    let Some(tpm) = Swtpm::start("pcr") else {
        return;
    };
    let mut ev = fresh(&tpm, None);
    ev.pcrs.get_mut(&7).unwrap()[0] ^= 1;
    assert_eq!(
        verify(&ev, NONCE, &ev.ak_public),
        Err(Rejection::PcrDigestMismatch)
    );

    let mut ev = fresh(&tpm, None);
    ev.pcrs.remove(&0);
    assert_eq!(
        verify(&ev, NONCE, &ev.ak_public),
        Err(Rejection::MissingPcr(0))
    );
}

#[test]
fn tampered_signature_rejected() {
    let Some(tpm) = Swtpm::start("sig") else {
        return;
    };
    let ev = fresh(&tpm, None);

    // Flip a bit in the signature's s value (the last byte).
    let mut bad = ev.clone();
    *bad.signature.last_mut().unwrap() ^= 1;
    assert_eq!(
        verify(&bad, NONCE, &ev.ak_public),
        Err(Rejection::BadSignature)
    );

    // Change the signed quote itself (a byte of the PCR digest).
    let mut bad = ev.clone();
    *bad.quote.last_mut().unwrap() ^= 1;
    assert_eq!(
        verify(&bad, NONCE, &ev.ak_public),
        Err(Rejection::BadSignature)
    );

    // A valid quote from a different TPM is not signed by the trusted AK.
    let Some(other) = Swtpm::start("sig-other") else {
        return;
    };
    let foreign = fresh(&other, None);
    assert_ne!(foreign.ak_public, ev.ak_public);
    assert_eq!(
        verify(&foreign, NONCE, &ev.ak_public),
        Err(Rejection::BadSignature)
    );
}

#[test]
fn ima_log_replays_to_pcr10() {
    let Some(tpm) = Swtpm::start("ima-ok") else {
        return;
    };
    let log = synthetic_ima_log(&tpm);
    let ev = fresh(&tpm, Some(log));
    assert!(ev.ima_log.is_some());
    let verdict = verify(&ev, NONCE, &ev.ak_public).expect("verify");
    assert!(verdict.ima_log_verified);
}

#[test]
fn tampered_ima_log_rejected() {
    let Some(tpm) = Swtpm::start("ima-bad") else {
        return;
    };
    let log = synthetic_ima_log(&tpm);
    let ev = fresh(&tpm, Some(log));

    // Rename a measured file: same length, different template data.
    let mut renamed = ev.clone();
    let log = renamed.ima_log.as_mut().unwrap();
    let at = log
        .windows(b"game.so".len())
        .position(|w| w == b"game.so")
        .unwrap();
    log[at] = b'h';
    assert!(matches!(
        verify(&renamed, NONCE, &ev.ak_public),
        Err(Rejection::ImaLogMismatch { .. })
    ));

    // Drop the last entry: the log no longer explains PCR 10.
    let mut shortened = ev.clone();
    let (last, _) = ima_ng_entry(u32::from(IMA_PCR), &[3; 32], "/usr/lib/game.so");
    let log = shortened.ima_log.as_mut().unwrap();
    log.truncate(log.len() - last.len());
    assert!(matches!(
        verify(&shortened, NONCE, &ev.ak_public),
        Err(Rejection::ImaLogMismatch { .. })
    ));

    // Garbage at the end doesn't parse.
    let mut garbage = ev.clone();
    garbage
        .ima_log
        .as_mut()
        .unwrap()
        .extend_from_slice(&[1, 2, 3]);
    assert!(matches!(
        verify(&garbage, NONCE, &ev.ak_public),
        Err(Rejection::MalformedImaLog(_))
    ));
}

#[test]
fn mode_is_measured() {
    for (name, events, want) in [
        ("mode-player", &[Mode::Player][..], MeasuredMode::Player),
        ("mode-dev", &[Mode::Developer][..], MeasuredMode::Developer),
        // Root on a developer boot extending "player" doesn't make it one.
        (
            "mode-upgrade",
            &[Mode::Developer, Mode::Player][..],
            MeasuredMode::Unrecognized,
        ),
    ] {
        let Some(tpm) = Swtpm::start(name) else {
            return;
        };
        for &m in events {
            tpm.extend(MODE_PCR, mode_event(m));
        }
        let ev = fresh(&tpm, None);
        let verdict = verify(&ev, NONCE, &ev.ak_public).expect("verify");
        assert_eq!(verdict.mode, want, "{name}");
    }

    // The reported mode PCR is covered by the quote like any other.
    let Some(tpm) = Swtpm::start("mode-forged") else {
        return;
    };
    tpm.extend(MODE_PCR, mode_event(Mode::Developer));
    let mut ev = fresh(&tpm, None);
    ev.pcrs
        .insert(MODE_PCR, fairplay_attest::mode_pcr_value(Mode::Player));
    assert_eq!(
        verify(&ev, NONCE, &ev.ak_public),
        Err(Rejection::PcrDigestMismatch)
    );
}

#[test]
fn missing_device_is_no_tpm() {
    let opts = CollectOptions {
        tcti: "device:/dev/fairplay-no-such-tpm".into(),
        ima_log: None,
    };
    assert!(matches!(collect_with(NONCE, &opts), Err(Error::NoTpm)));
}
