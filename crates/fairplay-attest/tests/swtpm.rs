//! Quote and verify against a software TPM. Each test starts its own `swtpm`
//! on free local ports with a temporary state directory.
//!
//! Needs the `tpm` feature and `swtpm` on PATH (`apt install swtpm`); without
//! either, the tests print why and pass, so plain `cargo test` keeps working.
#![cfg(feature = "tpm")]

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use fairplay_attest::testing::{ima_ng_entry, sha256_extend_value};
use fairplay_attest::{collect_with, verify, CollectOptions, Evidence, Rejection, IMA_PCR};
use tss_esapi::{
    handles::PcrHandle,
    interface_types::algorithm::HashingAlgorithm,
    structures::{Digest, DigestValues},
    tcti_ldr::TctiNameConf,
    Context,
};

struct Swtpm {
    child: Child,
    dir: PathBuf,
    port: u16,
}

impl Swtpm {
    /// Start swtpm, or `None` (test skipped) if it isn't installed.
    fn start(name: &str) -> Option<Swtpm> {
        if Command::new("swtpm")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            eprintln!("skipping {name}: swtpm is not installed");
            return None;
        }
        let dir =
            std::env::temp_dir().join(format!("fairplay-attest-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Tests run in parallel threads. Pick ports and wait for swtpm to own
        // them under one lock, so two tests never race for the same pair.
        static START: Mutex<()> = Mutex::new(());
        let _guard = START.lock().unwrap_or_else(|e| e.into_inner());
        for _ in 0..5 {
            let port = free_port_pair();
            let mut child = Command::new("swtpm")
                .args(["socket", "--tpm2", "--flags", "not-need-init,startup-clear"])
                .arg("--tpmstate")
                .arg(format!("dir={}", dir.display()))
                .arg("--server")
                .arg(format!("type=tcp,bindaddr=127.0.0.1,port={port}"))
                .arg("--ctrl")
                .arg(format!("type=tcp,bindaddr=127.0.0.1,port={}", port + 1))
                .stdout(Stdio::null())
                .spawn()
                .expect("spawn swtpm");
            if wait_ready(&mut child, port) {
                return Some(Swtpm { child, dir, port });
            }
            // swtpm exited, most likely because another process took a port
            // between our probe and its bind: try another pair.
            let _ = child.kill();
            let _ = child.wait();
        }
        panic!("swtpm did not start");
    }

    fn tcti(&self) -> String {
        format!("swtpm:host=127.0.0.1,port={}", self.port)
    }

    fn options(&self, ima_log: Option<PathBuf>) -> CollectOptions {
        CollectOptions {
            tcti: self.tcti(),
            ima_log,
        }
    }

    /// Extend the SHA-256 bank of PCR 10, as IMA would.
    fn extend_pcr10(&self, value: [u8; 32]) {
        let mut ctx = Context::new(self.tcti().parse::<TctiNameConf>().unwrap()).unwrap();
        let mut digests = DigestValues::new();
        digests.set(
            HashingAlgorithm::Sha256,
            Digest::try_from(value.to_vec()).unwrap(),
        );
        ctx.execute_with_nullauth_session(|c| c.pcr_extend(PcrHandle::Pcr10, digests))
            .unwrap();
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Both ports accept connections and our swtpm is still running (it exits
/// on a bind error, so a listener then belongs to someone else).
fn wait_ready(child: &mut Child, port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    let up = |p: u16| TcpStream::connect(("127.0.0.1", p)).is_ok();
    loop {
        if !matches!(child.try_wait(), Ok(None)) {
            return false;
        }
        if up(port) && up(port + 1) {
            std::thread::sleep(Duration::from_millis(50));
            return matches!(child.try_wait(), Ok(None));
        }
        assert!(Instant::now() < deadline, "swtpm did not start listening");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Two consecutive free ports (swtpm's TCTI uses port + 1 for control).
fn free_port_pair() -> u16 {
    for _ in 0..100 {
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = a.local_addr().unwrap().port();
        if port < u16::MAX && TcpListener::bind(("127.0.0.1", port + 1)).is_ok() {
            return port;
        }
    }
    panic!("no free port pair");
}

const NONCE: &[u8] = b"server-nonce-0123456789abcdef";

fn fresh(tpm: &Swtpm, ima_log: Option<PathBuf>) -> Evidence {
    collect_with(NONCE, &tpm.options(ima_log)).expect("collect")
}

/// Write a synthetic IMA log, extend PCR 10 to match it, return its path.
fn synthetic_ima_log(tpm: &Swtpm) -> PathBuf {
    let mut log = Vec::new();
    for (i, path) in ["boot_aggregate", "/usr/bin/fairplayd", "/usr/lib/game.so"]
        .iter()
        .enumerate()
    {
        let (entry, data) = ima_ng_entry(u32::from(IMA_PCR), &[i as u8 + 1; 32], path);
        tpm.extend_pcr10(sha256_extend_value(&data));
        log.extend_from_slice(&entry);
    }
    let path = tpm.dir.join("binary_runtime_measurements");
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
