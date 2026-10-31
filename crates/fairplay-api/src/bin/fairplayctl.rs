//! fairplayctl: talk to fairplayd from a shell.
//!
//!     fairplayctl launch --manifest game.json -- cheatsim game  # launcher group or root
//!     fairplayctl launch --join 1 -- anticheat  # a manifest-named reader, into session 1
//!     fairplayctl launch --manifest game.json --block-virtual-input -- game
//!     fairplayctl status 1
//!     fairplayctl violations 1                  # streams until Ctrl-C
//!     fairplayctl list
//!     fairplayctl attest
//!
//!     fairplayctl manifest keygen --out vendor.key   # prints the public key
//!     fairplayctl manifest new --key vendor.key --name Game --launch bin/game \
//!         --anti-cheat /opt/ac/ac --out game.json    # hashes, writes and signs
//!     fairplayctl manifest sign --key vendor.key game.json
//!     fairplayctl manifest verify game.json
//!
//! Prints the daemon's JSON lines as they arrive. Exits 0 for `ok`, 1 for
//! `error`, 2 if it couldn't talk to the daemon at all. `manifest` commands
//! print one JSON line and exit 0, or 1 if verification fails.

use std::{
    io::{Read, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use fairplay_api::{
    client::{default_socket, Client},
    encode,
    manifest::{self, FileEntry, Manifest, ReaderEntry, Role, Verified},
    Event, Request, Response, SessionId,
};

#[derive(Parser)]
#[command(about = "Client for fairplayd's socket API")]
struct Args {
    /// Daemon socket [default: $FAIRPLAYD_SOCKET, else /run/fairplayd.sock]
    #[arg(long)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start a program protected. Its stdin/stdout/stderr are this command's,
    /// and it keeps running after fairplayctl exits.
    Launch {
        /// Give the program /dev/null instead of this terminal.
        #[arg(long)]
        no_stdio: bool,
        /// Run as this uid (root must give one; others may only give their own).
        #[arg(long)]
        run_as: Option<u32>,
        /// The signed game manifest that names the program (required
        /// unless --join). Relative to the current directory.
        #[arg(long, required_unless_present = "join", conflicts_with = "join")]
        manifest: Option<PathBuf>,
        /// Start inside this session's protection domain as a reader: the
        /// program must be an anti_cheat reader its manifest names.
        #[arg(long)]
        join: Option<SessionId>,
        /// Directory whose code files the program may map executable
        /// [default: the program's directory]. Relative to the current one.
        #[arg(long)]
        install_dir: Option<PathBuf>,
        /// While this session runs, deny (not just report) virtual input
        /// from executables not on fairplayd's input allowlist.
        #[arg(long)]
        block_virtual_input: bool,
        /// Program and its arguments.
        #[arg(required = true, last = true)]
        command: Vec<String>,
    },
    /// Is a session protected? Also lockdown mode and virtual input devices
    /// (with who made each).
    /// Without SESSION: the session this process belongs to, if any.
    Status { session: Option<SessionId> },
    /// Stream denied attempts as they happen. Without SESSION: your own
    /// session (as root: every protected process).
    Violations {
        session: Option<SessionId>,
        /// Exit after this many violation events.
        #[arg(long)]
        count: Option<u64>,
    },
    /// List your sessions (all sessions, as root).
    List,
    /// Ask for attestation evidence (milestone 10; unavailable for now).
    Attest {
        /// Server-chosen nonce, hex. Random if omitted.
        #[arg(long)]
        nonce: Option<String>,
    },
    /// Make, sign and check game manifests (no daemon needed).
    #[command(subcommand)]
    Manifest(ManifestCmd),
}

#[derive(Subcommand)]
enum ManifestCmd {
    /// Make an ed25519 signing key. Writes the secret key (base64, mode
    /// 0600) and prints the public key.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a manifest: writes <MANIFEST>.sig over its exact bytes. Refuses
    /// if the manifest's signer isn't this key.
    Sign {
        #[arg(long)]
        key: PathBuf,
        manifest: PathBuf,
    },
    /// Check a manifest's signature against its own signer key, and every
    /// file's hash. Exits 1 if anything doesn't match.
    Verify { manifest: PathBuf },
    /// Write a manifest for these files (hashing each now), then sign it.
    /// Paths are written as given: relative ones are relative to the
    /// manifest's directory.
    New {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        name: String,
        /// A launch executable (repeatable).
        #[arg(long, required = true)]
        launch: Vec<String>,
        /// An anti_cheat reader (repeatable).
        #[arg(long)]
        anti_cheat: Vec<String>,
        /// A runtime_helper reader (repeatable).
        #[arg(long)]
        runtime_helper: Vec<String>,
        /// An accepted runtime (Proton) file (repeatable).
        #[arg(long)]
        proton: Vec<String>,
        /// An accepted overlay (repeatable).
        #[arg(long)]
        overlay: Vec<String>,
        #[arg(long)]
        block_virtual_input: bool,
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(None) => ExitCode::SUCCESS,
        Ok(Some(e)) => {
            eprintln!("fairplayctl: {e}");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("fairplayctl: {e:#}");
            ExitCode::from(2)
        }
    }
}

/// `Ok(Some(e))` if the daemon answered with an error.
fn run() -> Result<Option<fairplay_api::ApiError>> {
    let args = Args::parse();
    if let Cmd::Manifest(cmd) = args.cmd {
        return manifest_cmd(cmd);
    }
    let socket = args.socket.unwrap_or_else(default_socket);
    let mut fds = vec![];
    let mut stream_count = None;
    let req = match args.cmd {
        Cmd::Launch {
            no_stdio,
            run_as,
            manifest,
            join,
            install_dir,
            block_virtual_input,
            command,
        } => {
            if !no_stdio {
                fds = vec![0, 1, 2];
            }
            let mut req = launch_request(command, run_as, manifest, join, install_dir)?;
            if let Request::LaunchProtected {
                block_virtual_input: b,
                ..
            } = &mut req
            {
                *b = block_virtual_input;
            }
            req
        }
        Cmd::Status { session } => Request::SessionStatus { session },
        Cmd::Violations { session, count } => {
            stream_count = Some(count.unwrap_or(u64::MAX));
            Request::Violations { session }
        }
        Cmd::List => Request::ListSessions {},
        Cmd::Attest { nonce } => Request::Attest {
            nonce: match nonce {
                Some(n) => n,
                None => random_nonce()?,
            },
        },
        Cmd::Manifest(_) => unreachable!("handled above"),
    };
    let mut client = Client::connect(&socket)?;
    let resp = client.call_with_fds(&req, &fds)?;
    print_line(&resp)?;
    if let Response::Error(e) = resp {
        return Ok(Some(e));
    }
    if let Some(mut left) = stream_count {
        while left > 0 {
            let Some(resp) = client.next_response()? else {
                bail!("fairplayd closed the stream");
            };
            print_line(&resp)?;
            if matches!(resp, Response::Event(Event::Violation(_))) {
                left -= 1;
            }
        }
    }
    Ok(None)
}

fn print_line(resp: &Response) -> Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(&encode(resp))?;
    out.flush()?;
    Ok(())
}

fn launch_request(
    command: Vec<String>,
    run_as: Option<u32>,
    manifest: Option<PathBuf>,
    join: Option<SessionId>,
    install_dir: Option<PathBuf>,
) -> Result<Request> {
    let cwd = std::env::current_dir().context("current directory")?;
    let manifest = manifest.map(|m| utf8(&cwd.join(m))).transpose()?;
    let install_dir = install_dir.map(|d| utf8(&cwd.join(d))).transpose()?;
    let program = resolve(&command[0], &cwd)?;
    let env = std::env::vars_os()
        .filter_map(|(k, v)| {
            let mut kv = k.into_string().ok()?;
            kv.push('=');
            kv.push_str(v.to_str()?);
            Some(kv)
        })
        .collect();
    Ok(Request::LaunchProtected {
        manifest,
        program: utf8(&program)?,
        argv: command,
        env,
        cwd: utf8(&cwd)?,
        run_as,
        join,
        install_dir,
        block_virtual_input: false,
    })
}

/// Finds `name` the way a shell would: a path if it has a slash, else `$PATH`.
/// Done here, as the caller, so the daemon never searches on anyone's behalf.
fn resolve(name: &str, cwd: &Path) -> Result<PathBuf> {
    if name.contains('/') {
        return Ok(cwd.join(name));
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let candidate = cwd.join(dir).join(name);
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }
    bail!("{name}: not found in PATH")
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

fn utf8(p: &Path) -> Result<String> {
    match std::str::from_utf8(p.as_os_str().as_bytes()) {
        Ok(s) => Ok(s.to_owned()),
        Err(_) => bail!("{} is not valid UTF-8", p.display()),
    }
}

fn random_nonce() -> Result<String> {
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .context("reading /dev/urandom")?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// `manifest` subcommands. `Ok(Some(e))` (exit 1) if verification failed.
fn manifest_cmd(cmd: ManifestCmd) -> Result<Option<fairplay_api::ApiError>> {
    use fairplay_api::{ApiError, ErrorCode};
    match cmd {
        ManifestCmd::Keygen { out } => {
            let mut secret = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut secret))
                .context("reading /dev/urandom")?;
            write_private(&out, manifest::encode_secret(&secret) + "\n")?;
            let key = manifest::signing_key(&manifest::encode_secret(&secret))
                .map_err(anyhow::Error::msg)?;
            print_json(&serde_json::json!({
                "public_key": manifest::encode_public(&key.verifying_key()),
                "fingerprint": manifest::fingerprint(&key.verifying_key()),
            }))?;
        }
        ManifestCmd::Sign { key, manifest } => {
            let key = read_key(&key)?;
            let bytes = std::fs::read(&manifest)
                .with_context(|| format!("reading {}", manifest.display()))?;
            let m: Manifest = serde_json::from_slice(&bytes).context("parsing the manifest")?;
            if m.signer != manifest::encode_public(&key.verifying_key()) {
                bail!("the manifest's signer is not this key's public key");
            }
            let sig = manifest::sig_path(&manifest);
            std::fs::write(&sig, manifest::sign(&key, &bytes))
                .with_context(|| format!("writing {}", sig.display()))?;
            print_json(&serde_json::json!({ "signed": manifest, "sig": sig }))?;
        }
        ManifestCmd::Verify { manifest } => {
            let bytes = std::fs::read(&manifest)
                .with_context(|| format!("reading {}", manifest.display()))?;
            let sig_path = manifest::sig_path(&manifest);
            let sig = std::fs::read(&sig_path)
                .with_context(|| format!("reading {}", sig_path.display()))?;
            let v = match Verified::check(&bytes, &sig) {
                Ok(v) => v,
                Err(e) => return Ok(Some(ApiError::new(ErrorCode::Forbidden, e.to_string()))),
            };
            let base = manifest.parent().unwrap_or(Path::new("."));
            let m = &v.manifest;
            let entries = m
                .launch
                .iter()
                .chain(&m.proton)
                .chain(&m.overlays)
                .map(|e| (&e.path, &e.sha256))
                .chain(m.readers.iter().map(|r| (&r.path, &r.sha256)));
            let mut bad = vec![];
            for (path, sha) in entries {
                let p = manifest::resolve(base, path);
                let got = std::fs::File::open(&p).and_then(manifest::sha256_of);
                match got {
                    Ok(h) if manifest::hex(&h) == sha.to_ascii_lowercase() => {}
                    Ok(_) => bad.push(format!("{}: hash mismatch", p.display())),
                    Err(e) => bad.push(format!("{}: {e}", p.display())),
                }
            }
            print_json(&serde_json::json!({
                "name": m.name,
                "sha256": v.sha256,
                "signer": m.signer,
                "signer_fingerprint": v.signer_fingerprint,
                "signature": "ok",
                "file_problems": bad,
            }))?;
            if !bad.is_empty() {
                return Ok(Some(ApiError::new(
                    ErrorCode::Forbidden,
                    format!("{} file(s) don't match", bad.len()),
                )));
            }
        }
        ManifestCmd::New {
            key,
            name,
            launch,
            anti_cheat,
            runtime_helper,
            proton,
            overlay,
            block_virtual_input,
            out,
        } => {
            let key = read_key(&key)?;
            let base = out.parent().unwrap_or(Path::new(".")).to_owned();
            let entry = |path: &String| -> Result<FileEntry> {
                let p = manifest::resolve(&base, path);
                let h = std::fs::File::open(&p)
                    .and_then(manifest::sha256_of)
                    .with_context(|| format!("hashing {}", p.display()))?;
                Ok(FileEntry {
                    path: path.clone(),
                    sha256: manifest::hex(&h),
                })
            };
            let entries = |v: &[String]| v.iter().map(entry).collect::<Result<Vec<_>>>();
            let reader = |role: Role| {
                move |e: FileEntry| ReaderEntry {
                    role,
                    path: e.path,
                    sha256: e.sha256,
                }
            };
            let m = Manifest {
                name,
                signer: manifest::encode_public(&key.verifying_key()),
                launch: entries(&launch)?,
                readers: entries(&anti_cheat)?
                    .into_iter()
                    .map(reader(Role::AntiCheat))
                    .chain(
                        entries(&runtime_helper)?
                            .into_iter()
                            .map(reader(Role::RuntimeHelper)),
                    )
                    .collect(),
                proton: entries(&proton)?,
                overlays: entries(&overlay)?,
                block_virtual_input,
            };
            let mut bytes = serde_json::to_vec_pretty(&m)?;
            bytes.push(b'\n');
            std::fs::write(&out, &bytes).with_context(|| format!("writing {}", out.display()))?;
            let sig = manifest::sig_path(&out);
            let sig_text = manifest::sign(&key, &bytes);
            std::fs::write(&sig, &sig_text)
                .with_context(|| format!("writing {}", sig.display()))?;
            let v = Verified::check(&bytes, sig_text.as_bytes()).map_err(anyhow::Error::msg)?;
            print_json(&serde_json::json!({
                "manifest": out,
                "sig": sig,
                "sha256": v.sha256,
                "signer_fingerprint": v.signer_fingerprint,
            }))?;
        }
    }
    Ok(None)
}

fn read_key(path: &Path) -> Result<ed25519_dalek::SigningKey> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    manifest::signing_key(&text).map_err(anyhow::Error::msg)
}

fn write_private(path: &Path, text: String) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(text.as_bytes())?;
    Ok(())
}

fn print_json(v: &serde_json::Value) -> Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, v)?;
    out.write_all(b"\n")?;
    Ok(())
}
