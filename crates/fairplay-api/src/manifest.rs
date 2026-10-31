//! The game manifest, v0 (milestone 9; design doc, "The game manifest").
//!
//! A manifest is a JSON file next to a detached signature, `<manifest>.sig`:
//! base64 of an ed25519 signature over the manifest file's exact bytes.
//!
//! ```json
//! {
//!   "name": "Example Game",
//!   "signer": "<ed25519 public key, base64>",
//!   "launch":  [{"path": "bin/game", "sha256": "<hex>"}],
//!   "readers": [{"role": "anti_cheat", "path": "/opt/vendor/ac", "sha256": "<hex>"},
//!               {"role": "runtime_helper", "path": "proton/bin/wineserver", "sha256": "<hex>"}],
//!   "proton":  [{"path": "proton/lib/wine/x86_64-unix/ntdll.so", "sha256": "<hex>"}],
//!   "overlays": [{"path": "/usr/lib/overlay.so", "sha256": "<hex>"}],
//!   "block_virtual_input": false
//! }
//! ```
//!
//! Relative paths are relative to the manifest's directory. The signature is
//! checked against the manifest's *own* `signer` key: fairplayd keeps no list
//! of trusted publishers. It records the manifest's hash and the signer's
//! fingerprint in the session, and the vendor's server decides whether that
//! signer is the vendor (attestation, milestone 10).

use std::{
    fmt,
    io::{self, Read},
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Largest manifest file fairplayd reads.
pub const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
/// Most file entries (all lists together) one manifest may have.
pub const MAX_ENTRIES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub name: String,
    /// The ed25519 public key that signed this manifest, base64.
    pub signer: String,
    /// What `launch_protected` may start as the root of a domain.
    pub launch: Vec<FileEntry>,
    /// Programs that may read the game's memory.
    #[serde(default)]
    pub readers: Vec<ReaderEntry>,
    /// Runtime files (Proton) the session may map executable.
    #[serde(default)]
    pub proton: Vec<FileEntry>,
    /// Overlays the game accepts; the session may map them executable.
    #[serde(default)]
    pub overlays: Vec<FileEntry>,
    /// Block virtual input from executables not on fairplayd's input
    /// allowlist while the session runs (milestone 7's option; the launch
    /// request can also ask for it).
    #[serde(default)]
    pub block_virtual_input: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    /// Absolute, or relative to the manifest's directory.
    pub path: String,
    /// Lowercase hex SHA-256 of the file's contents.
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderEntry {
    pub role: Role,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The vendor's anti-cheat: started into the session by `join`.
    AntiCheat,
    /// A runtime helper the game starts itself (Proton's `wineserver`):
    /// a process becomes a reader by exec'ing this file.
    RuntimeHelper,
}

/// Why a manifest was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// Not valid manifest JSON, or a field is malformed.
    Invalid(String),
    /// The signature doesn't verify against the manifest's signer key.
    BadSignature(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::Invalid(m) => write!(f, "invalid manifest: {m}"),
            ManifestError::BadSignature(m) => write!(f, "manifest signature: {m}"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// A manifest whose signature verified. Its files are not checked yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub manifest: Manifest,
    /// Hex SHA-256 of the manifest file's bytes.
    pub sha256: String,
    /// [`fingerprint`] of the signer key.
    pub signer_fingerprint: String,
}

impl Verified {
    /// Checks `sig` (the `.sig` file's contents) over `bytes` (the manifest
    /// file's) against the key the manifest names, and that every entry is
    /// well formed.
    pub fn check(bytes: &[u8], sig: &[u8]) -> Result<Self, ManifestError> {
        let invalid = |m: String| ManifestError::Invalid(m);
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(invalid(format!("larger than {MAX_MANIFEST_BYTES} bytes")));
        }
        let manifest: Manifest =
            serde_json::from_slice(bytes).map_err(|e| invalid(e.to_string()))?;
        let key = parse_public_key(&manifest.signer).map_err(invalid)?;
        let sig = parse_signature(sig).map_err(ManifestError::BadSignature)?;
        key.verify_strict(bytes, &sig).map_err(|_| {
            ManifestError::BadSignature("does not verify against the manifest's signer key".into())
        })?;
        manifest.validate().map_err(invalid)?;
        Ok(Self {
            sha256: hex(&Sha256::digest(bytes)),
            signer_fingerprint: fingerprint(&key),
            manifest,
        })
    }
}

impl Manifest {
    fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("name is empty".into());
        }
        if self.launch.is_empty() {
            return Err("no launch executables".into());
        }
        let entries =
            self.launch.len() + self.readers.len() + self.proton.len() + self.overlays.len();
        if entries > MAX_ENTRIES {
            return Err(format!("more than {MAX_ENTRIES} file entries"));
        }
        let files = self
            .launch
            .iter()
            .chain(&self.proton)
            .chain(&self.overlays)
            .map(|e| (&e.path, &e.sha256))
            .chain(self.readers.iter().map(|r| (&r.path, &r.sha256)));
        for (path, sha) in files {
            if path.is_empty() || path.contains('\0') {
                return Err(format!("bad path {path:?}"));
            }
            parse_sha256(sha).map_err(|e| format!("{path}: {e}"))?;
        }
        Ok(())
    }

    /// The readers with `role`.
    pub fn readers(&self, role: Role) -> impl Iterator<Item = &ReaderEntry> {
        self.readers.iter().filter(move |r| r.role == role)
    }
}

/// Where an entry's file is: `path` itself if absolute, else under `base`
/// (the manifest's directory).
pub fn resolve(base: &Path, path: &str) -> PathBuf {
    base.join(path)
}

/// The signature file for a manifest: `<manifest>.sig`.
pub fn sig_path(manifest: &Path) -> PathBuf {
    let mut s = manifest.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

/// A short, stable name for a signer key: `ed25519:` + hex SHA-256 of the
/// 32 key bytes.
pub fn fingerprint(key: &VerifyingKey) -> String {
    format!("ed25519:{}", hex(&Sha256::digest(key.as_bytes())))
}

pub fn parse_public_key(b64: &str) -> Result<VerifyingKey, String> {
    let bytes = B64
        .decode(b64.trim())
        .map_err(|e| format!("signer is not base64: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "signer is not a 32-byte ed25519 key".to_string())?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "signer is not a valid ed25519 key".into())
}

fn parse_signature(text: &[u8]) -> Result<Signature, String> {
    let text = std::str::from_utf8(text).map_err(|_| "not text".to_string())?;
    let bytes = B64
        .decode(text.trim())
        .map_err(|e| format!("not base64: {e}"))?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| "not a 64-byte ed25519 signature".to_string())?;
    Ok(Signature::from_bytes(&bytes))
}

/// The 32 bytes of a lowercase or uppercase hex SHA-256.
pub fn parse_sha256(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("sha256 must be 64 hex digits".into());
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("checked hex");
    }
    Ok(out)
}

/// SHA-256 of everything `r` yields.
pub fn sha256_of(mut r: impl Read) -> io::Result<[u8; 32]> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return Ok(h.finalize().into()),
            Ok(n) => h.update(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A signing key from 32 secret bytes (the key file holds them, base64).
pub fn signing_key(secret_b64: &str) -> Result<SigningKey, String> {
    let bytes = B64
        .decode(secret_b64.trim())
        .map_err(|e| format!("key is not base64: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "key is not 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// The key file's contents for 32 random secret bytes.
pub fn encode_secret(secret: &[u8; 32]) -> String {
    B64.encode(secret)
}

pub fn encode_public(key: &VerifyingKey) -> String {
    B64.encode(key.as_bytes())
}

/// The `.sig` file's contents for `bytes`.
pub fn sign(key: &SigningKey, bytes: &[u8]) -> String {
    B64.encode(key.sign(bytes).to_bytes()) + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn manifest_for(k: &SigningKey) -> Vec<u8> {
        serde_json::to_vec_pretty(&serde_json::json!({
            "name": "Test Game",
            "signer": encode_public(&k.verifying_key()),
            "launch": [{"path": "bin/game", "sha256": ZERO}],
            "readers": [
                {"role": "anti_cheat", "path": "/opt/ac/ac", "sha256": ZERO},
                {"role": "runtime_helper", "path": "proton/wineserver", "sha256": ZERO},
            ],
        }))
        .unwrap()
    }

    #[test]
    fn signed_manifest_verifies() {
        let k = key(1);
        let bytes = manifest_for(&k);
        let v = Verified::check(&bytes, sign(&k, &bytes).as_bytes()).unwrap();
        assert_eq!(v.manifest.name, "Test Game");
        assert_eq!(v.sha256, hex(&Sha256::digest(&bytes)));
        assert_eq!(v.signer_fingerprint, fingerprint(&k.verifying_key()));
        assert!(v.signer_fingerprint.starts_with("ed25519:"));
        assert_eq!(v.manifest.readers(Role::AntiCheat).count(), 1);
        assert_eq!(
            v.manifest.readers(Role::RuntimeHelper).next().unwrap().path,
            "proton/wineserver"
        );
        assert!(v.manifest.proton.is_empty() && !v.manifest.block_virtual_input);
    }

    #[test]
    fn tampered_manifest_is_refused() {
        let k = key(1);
        let bytes = manifest_for(&k);
        let sig = sign(&k, &bytes);
        let mut tampered = bytes.clone();
        let i = tampered.windows(4).position(|w| w == b"Test").unwrap();
        tampered[i] = b'B';
        assert!(matches!(
            Verified::check(&tampered, sig.as_bytes()),
            Err(ManifestError::BadSignature(_))
        ));
        // Even a whitespace change: the signature covers the exact bytes.
        let mut spaced = bytes.clone();
        spaced.push(b' ');
        assert!(matches!(
            Verified::check(&spaced, sig.as_bytes()),
            Err(ManifestError::BadSignature(_))
        ));
    }

    #[test]
    fn wrong_key_is_refused() {
        // Signed by key 2, but names key 1 as its signer.
        let bytes = manifest_for(&key(1));
        let sig = sign(&key(2), &bytes);
        assert!(matches!(
            Verified::check(&bytes, sig.as_bytes()),
            Err(ManifestError::BadSignature(_))
        ));
        // Garbage and truncated signatures.
        for bad in [&b"not base64!"[..], b"AAAA", b""] {
            assert!(matches!(
                Verified::check(&bytes, bad),
                Err(ManifestError::BadSignature(_))
            ));
        }
    }

    #[test]
    fn any_signer_is_accepted() {
        // No list of trusted publishers: a manifest signed by its own key
        // verifies, whoever made it. The server judges the signer.
        for n in [3, 4, 5] {
            let k = key(n);
            let bytes = manifest_for(&k);
            assert!(Verified::check(&bytes, sign(&k, &bytes).as_bytes()).is_ok());
        }
    }

    #[test]
    fn malformed_manifests() {
        let k = key(1);
        let pk = encode_public(&k.verifying_key());
        for (what, json) in [
            ("not json", "nope".to_string()),
            (
                "no launch",
                format!(r#"{{"name":"x","signer":"{pk}","launch":[]}}"#),
            ),
            (
                "empty name",
                format!(
                    r#"{{"name":" ","signer":"{pk}","launch":[{{"path":"a","sha256":"{ZERO}"}}]}}"#
                ),
            ),
            (
                "short hash",
                format!(
                    r#"{{"name":"x","signer":"{pk}","launch":[{{"path":"a","sha256":"00"}}]}}"#
                ),
            ),
            (
                "bad role",
                format!(
                    r#"{{"name":"x","signer":"{pk}","launch":[{{"path":"a","sha256":"{ZERO}"}}],"readers":[{{"role":"cheat","path":"b","sha256":"{ZERO}"}}]}}"#
                ),
            ),
            (
                "unknown field",
                format!(
                    r#"{{"name":"x","signer":"{pk}","launch":[{{"path":"a","sha256":"{ZERO}"}}],"trusted":true}}"#
                ),
            ),
            (
                "bad key",
                format!(
                    r#"{{"name":"x","signer":"AAAA","launch":[{{"path":"a","sha256":"{ZERO}"}}]}}"#
                ),
            ),
            (
                "empty path",
                format!(
                    r#"{{"name":"x","signer":"{pk}","launch":[{{"path":"","sha256":"{ZERO}"}}]}}"#
                ),
            ),
        ] {
            let sig = sign(&k, json.as_bytes());
            assert!(
                matches!(
                    Verified::check(json.as_bytes(), sig.as_bytes()),
                    Err(ManifestError::Invalid(_))
                ),
                "{what}"
            );
        }
    }

    #[test]
    fn options_parse() {
        let k = key(1);
        let pk = encode_public(&k.verifying_key());
        let json = format!(
            r#"{{"name":"x","signer":"{pk}","launch":[{{"path":"a","sha256":"{ZERO}"}}],
               "proton":[{{"path":"p","sha256":"{ZERO}"}}],
               "overlays":[{{"path":"/o.so","sha256":"{ZERO}"}}],"block_virtual_input":true}}"#
        );
        let v = Verified::check(json.as_bytes(), sign(&k, json.as_bytes()).as_bytes()).unwrap();
        assert_eq!(v.manifest.proton.len(), 1);
        assert_eq!(v.manifest.overlays[0].path, "/o.so");
        assert!(v.manifest.block_virtual_input);
    }

    #[test]
    fn hashing_and_paths() {
        assert_eq!(
            hex(&sha256_of(&b"abc"[..]).unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(parse_sha256(&"Ab".repeat(32)).unwrap(), [0xab; 32]);
        assert!(parse_sha256(&"zz".repeat(32)).is_err());
        assert_eq!(resolve(Path::new("/g"), "bin/x"), PathBuf::from("/g/bin/x"));
        assert_eq!(resolve(Path::new("/g"), "/opt/x"), PathBuf::from("/opt/x"));
        assert_eq!(
            sig_path(Path::new("/g/m.json")),
            PathBuf::from("/g/m.json.sig")
        );
    }

    #[test]
    fn key_files_round_trip() {
        let k = signing_key(&encode_secret(&[7; 32])).unwrap();
        assert_eq!(k.to_bytes(), [7; 32]);
        assert!(signing_key("AAAA").is_err());
        let pk = encode_public(&k.verifying_key());
        assert_eq!(parse_public_key(&pk).unwrap(), k.verifying_key());
    }
}
