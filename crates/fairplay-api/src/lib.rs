//! fairplayd's socket protocol (milestone 4).
//!
//! Follows the design doc's vendor-facing API: four calls, `launch_protected`,
//! `session_status`, `attest` and `violations`, plus `list_sessions` for
//! humans. fairplayd listens on a Unix domain socket ([`DEFAULT_SOCKET`]). A
//! client writes one JSON [`Request`] per line and reads JSON [`Response`]
//! lines back. Several requests may share a connection, except that
//! `violations` turns the connection into a one-way stream of events.
//!
//! The daemon learns who is calling from the kernel (`SO_PEERCRED`), never
//! from the request, so nothing in a request claims an identity. The
//! client checks the other way too: the socket must be served by root and,
//! inside a protected session, by the fairplayd that launched it
//! ([`PID_ENV`]).
//!
//! `launch_protected` starts only what a signed game manifest names
//! (milestone 9, see [`manifest`]): a launch executable for a new session,
//! or with `join`, one of the session manifest's `anti_cheat` readers.
//!
//! `launch_protected` may carry the caller's stdin, stdout and stderr as
//! file descriptors (`SCM_RIGHTS`) on the same `sendmsg` as the request line;
//! the game then writes to the caller's terminal. Without them it gets
//! `/dev/null`.
//!
//! ```text
//! -> {"op":"launch_protected","manifest":"/games/x/game.json","program":"/games/x/game","argv":["game"],"env":["HOME=/home/me"],"cwd":"/home/me"}
//! <- {"ok":{"launched":{"session":1,"pid":4242}}}
//! -> {"op":"session_status","session":1}
//! <- {"ok":{"status":{"protected":true,"session":{...},"lockdown":"none","virtual_input_devices":[]}}}
//! -> {"op":"attest","nonce":"00ff"}
//! <- {"error":{"code":"unavailable","message":"...","nonce":"00ff"}}
//! -> {"op":"violations","session":1}
//! <- {"ok":{"subscribed":{"session":1}}}
//! <- {"event":{"violation":{"session":1,"caller":777,"comm":"cheatsim",...}}}
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};

pub mod client;
pub mod manifest;

/// Where fairplayd listens unless told otherwise.
pub const DEFAULT_SOCKET: &str = "/run/fairplayd.sock";
/// Environment variable clients read to find a non-default socket.
pub const SOCKET_ENV: &str = "FAIRPLAYD_SOCKET";
/// Environment variable fairplayd sets, to its own pid, for every process
/// it launches (and so everything they start). A client that finds it
/// refuses a socket served by any other process (see [`client`]).
pub const PID_ENV: &str = "FAIRPLAYD_PID";
/// Group whose members may call `launch_protected` (root always may).
pub const DEFAULT_LAUNCHER_GROUP: &str = "fairplay-launcher";
/// Longest request line the daemon accepts, newline included.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// File descriptors a `launch_protected` request may carry: stdin, stdout, stderr.
pub const STDIO_FDS: usize = 3;
/// Longest attestation nonce, in bytes (twice that in hex).
pub const MAX_NONCE_BYTES: usize = 64;

/// Identifies one protected session: a game plus the processes launched
/// into its protection domain. Assigned by the daemon, never reused while
/// it runs.
pub type SessionId = u64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Start a program in a protection domain, protected from its first
    /// instruction. Launchers only: root, or members of the launcher group.
    /// The program must be one the game manifest names, with the hash it
    /// names (milestone 9).
    LaunchProtected {
        /// Absolute path of a signed game manifest (its signature is
        /// `<manifest>.sig`). Required for a new session; must be left out
        /// with `join`, which uses the session's manifest.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manifest: Option<String>,
        /// Absolute path of the executable. The client resolves `PATH`.
        /// Without `join`: one of the manifest's `launch` entries. With
        /// `join`: one of its `anti_cheat` readers.
        program: String,
        /// Full argv, including argv[0].
        argv: Vec<String>,
        /// `KEY=VALUE` strings. The daemon drops dynamic-loader variables
        /// (`LD_*`), which would inject code into the protected process.
        #[serde(default)]
        env: Vec<String>,
        /// Absolute working directory, entered after dropping privileges.
        cwd: String,
        /// uid to run as. A non-root launcher may only name itself (or
        /// leave this out). Root must name one: games never run as root by
        /// default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        run_as: Option<u32>,
        /// Start the program inside this existing session's protection
        /// domain instead of a new one, as a reader: how the vendor's
        /// anti-cheat joins the game it watches. Only an `anti_cheat` reader
        /// the session's manifest names may join.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        join: Option<SessionId>,
        /// Absolute path of the directory the program's code comes from
        /// (default: the program's own directory). Every ELF or PE file in
        /// it when the launch happens may be mapped executable by the
        /// session; files added or replaced later may not (milestone 8).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        install_dir: Option<String>,
        /// Deny, not just report, new virtual input (uinput or uhid
        /// devices, writes into `/dev/input/event*`) from executables not on
        /// fairplayd's input allowlist, for as long as this session runs
        /// (milestone 7). Machine-wide while it lasts. Off by default:
        /// Steam Input and accessibility tools rely on virtual devices.
        #[serde(default, skip_serializing_if = "is_false")]
        block_virtual_input: bool,
    },
    /// Whether a session is protected, plus machine state a vendor cares
    /// about. Without `session`: the session the calling process belongs to.
    SessionStatus {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<SessionId>,
    },
    /// Subscribe to denied attempts as they happen. Without `session`: the
    /// caller's own session, or for root, every protected process.
    Violations {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<SessionId>,
    },
    /// The caller's sessions (every session, for root).
    ListSessions {},
    /// Evidence of what booted, for a server-chosen nonce (hex). Milestone 10;
    /// answers `unavailable` until there is a TPM.
    Attest { nonce: String },
}

/// One line from the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Ok(Reply),
    Error(ApiError),
    /// Pushed on a `violations` subscription.
    Event(Event),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reply {
    Launched {
        session: SessionId,
        pid: u32,
    },
    Status(StatusReport),
    /// The subscription is live; [`Event`]s follow on this connection.
    Subscribed {
        session: Option<SessionId>,
    },
    Sessions(Vec<SessionInfo>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusReport {
    /// The session's game is running and registered with the kernel program.
    pub protected: bool,
    /// The session asked about, or the caller's; `None` if the caller is not
    /// in one.
    pub session: Option<SessionInfo>,
    /// Kernel lockdown mode (`none`, `integrity`, `confidentiality`), or
    /// `None` if the kernel doesn't report one.
    pub lockdown: Option<String>,
    /// Virtual input devices that exist right now (made through
    /// `/dev/uinput` or `/dev/uhid`), with who made them (milestone 7).
    pub virtual_input_devices: Vec<VirtualInputDevice>,
}

/// One virtual input device, and the process that made it as far as
/// fairplayd can tell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualInputDevice {
    /// The kernel's name for it, e.g. `input7`.
    pub device: String,
    /// The name its creator gave it (sysfs `name`).
    pub name: String,
    pub kind: InputKind,
    /// The process that created it: from the kernel's record of the
    /// creation, matched to this device by name (uinput) or to the live
    /// processes that opened `/dev/uhid` (uhid). `None` if it was made
    /// before fairplayd started or the record was forgotten.
    pub created_by: Option<InputCreator>,
    /// The creator's executable is on fairplayd's input allowlist. False
    /// when the creator is unknown.
    pub allowlisted: bool,
    /// More than one live process could have made it (the same device name
    /// twice, or several uhid users); `created_by` is the newest, and
    /// `allowlisted` holds only if every candidate is allowlisted.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ambiguous: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    /// Made through `/dev/uinput`.
    Uinput,
    /// Made through `/dev/uhid` (a virtual HID device).
    Uhid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputCreator {
    /// tgid (the process id).
    pub pid: u32,
    /// Captured in the kernel when it created the device.
    pub comm: String,
    /// File name of its executable, captured in the kernel.
    pub exe: String,
    /// Full path, if it was running when fairplayd looked.
    pub exe_path: Option<String>,
    /// Seconds since the Unix epoch.
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session: SessionId,
    /// Who called `launch_protected`.
    pub launcher_uid: u32,
    /// Who the game runs as.
    pub uid: u32,
    pub game: ProcessInfo,
    /// Other processes launched into the domain (the vendor's anti-cheat).
    /// Processes these start join the domain on their own and aren't listed.
    pub members: Vec<ProcessInfo>,
    /// Seconds since the Unix epoch.
    pub started_at: u64,
    pub violations: u64,
    /// Some process started in this domain could not be protected (the
    /// kernel's map was full) and runs outside it. The game itself may
    /// still be protected; what a server makes of this is its policy.
    #[serde(default)]
    pub protection_degraded: bool,
    /// How many such processes (a lower bound).
    #[serde(default)]
    pub unprotected_children: u64,
    /// The signed manifest the session was launched from (milestone 9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Box<ManifestInfo>>,
}

/// What `session_status` says about a session's manifest. The OS doesn't
/// judge the signer; the vendor's server checks it is the vendor's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestInfo {
    pub name: String,
    /// Hex SHA-256 of the manifest file's exact bytes.
    pub sha256: String,
    /// The signer's ed25519 public key, base64, as the manifest names it.
    pub signer: String,
    /// `ed25519:` + hex SHA-256 of the signer key's 32 bytes.
    pub signer_fingerprint: String,
    /// The manifest asks for virtual input devices to be blocked.
    pub block_virtual_input: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub argv: Vec<String>,
    /// Serialized inline: `"state":"running"` or
    /// `"state":"exited","code":0,"signal":null`.
    #[serde(flatten)]
    pub state: ProcessState,
    /// Set for the vendor's anti-cheat (a `join`), which runs in a sandbox
    /// (milestone 9, part B).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<Box<SandboxInfo>>,
}

/// What a sandboxed process can see of the file system. Everything else
/// (the home directory, other users' files, display and D-Bus sockets) is
/// not in its mount namespace at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxInfo {
    /// Its own read-write data directory,
    /// `$XDG_DATA_HOME/fairplay/<signer fingerprint>/`. The only place it
    /// can keep anything across runs.
    pub data_dir: String,
    /// Directories it sees read-only besides the system ones: its own
    /// install directory and the game's.
    pub read_only: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProcessState {
    Running,
    /// `code` is the exit status for a normal exit, `signal` the signal
    /// number if it was killed. Exactly one is set.
    Exited {
        code: Option<i32>,
        signal: Option<i32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Violation(ViolationEvent),
    /// This subscriber fell behind and `missed` events were dropped.
    Lagged {
        missed: u64,
    },
}

/// One attempt the kernel denied, or (virtual input, milestone 7) one it
/// let through and reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViolationEvent {
    /// Session whose process was targeted (`None` for processes protected
    /// from fairplayd's command line).
    pub session: Option<SessionId>,
    /// Process (tgid) that tried.
    pub caller: u32,
    /// Its short name, captured in the kernel at the time of the attempt.
    pub comm: String,
    /// File name of its executable, captured in the kernel.
    pub exe: String,
    /// Full path of its executable, if it was still running when fairplayd
    /// looked. Best-effort; `exe` is the reliable one.
    pub exe_path: Option<String>,
    /// The protected process it targeted; 0 for virtual input, which
    /// targets the whole machine.
    pub target: u32,
    /// LSM hook that denied it, e.g. `ptrace_access_check`, or `mmap_file`
    /// / `file_mprotect` for code the game tried to map that isn't on its
    /// allowlist (then `caller` and `target` are both the game), or
    /// `bprm_check_security` for a program not on it that the game (or a
    /// process it started) tried to exec; `execve` failed. For
    /// virtual input: `uinput_create`, `uhid_create`, `evdev_write`, or
    /// `uinput_write` (input through a uinput device, refused while a
    /// session blocks virtual input).
    pub hook: String,
    /// Whether the kernel stopped it. Virtual input is `reported` unless a
    /// session asked for `block_virtual_input`; everything else is
    /// `denied`.
    #[serde(default)]
    pub outcome: Outcome,
    /// ptrace access mode bits the caller asked for, or for `mmap_file` and
    /// `file_mprotect` the `PROT_*` bits, or for virtual input the device
    /// node's kernel `dev_t` (`major << 20 | minor`).
    pub mode: u32,
    /// File name (no directory) of the file it tried to map, for
    /// `mmap_file` and `file_mprotect`, or exec, for
    /// `bprm_check_security`. For `uinput_create`, the name the
    /// caller gave the device; for the others, the device node (`uhid`,
    /// `event3`, `uinput`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Seconds since the Unix epoch, when fairplayd read the record.
    pub seen_at: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The kernel refused it.
    #[default]
    Denied,
    /// The kernel let it happen; this is a report, not a denial.
    Reported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    /// `attest` echoes the caller's nonce, even when it can't answer it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Malformed or invalid request.
    BadRequest,
    /// The caller may not do this (e.g. launch without being a launcher).
    Forbidden,
    /// No such session, or not the caller's. The two are deliberately
    /// indistinguishable so one user can't probe another's sessions.
    NotFound,
    /// A per-user or global limit was hit.
    LimitReached,
    /// The program could not be started (bad path, permission, ...).
    LaunchFailed,
    /// The feature needs something this machine doesn't have (e.g. a TPM).
    Unavailable,
    /// The daemon itself failed.
    Internal,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            nonce: None,
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = serde_json::to_value(self.code).unwrap_or_default();
        write!(f, "{}: {}", code.as_str().unwrap_or("error"), self.message)
    }
}

impl std::error::Error for ApiError {}

impl From<ApiError> for Response {
    fn from(e: ApiError) -> Self {
        Response::Error(e)
    }
}

impl From<Reply> for Response {
    fn from(r: Reply) -> Self {
        Response::Ok(r)
    }
}

impl From<Result<Reply, ApiError>> for Response {
    fn from(r: Result<Reply, ApiError>) -> Self {
        match r {
            Ok(r) => Response::Ok(r),
            Err(e) => Response::Error(e),
        }
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Serializes a message as one line, newline included.
pub fn encode<T: Serialize>(msg: &T) -> Vec<u8> {
    let mut line = serde_json::to_vec(msg).expect("protocol types always serialize");
    line.push(b'\n');
    line
}

/// Parses one request line (with or without its newline).
pub fn decode_request(line: &[u8]) -> Result<Request, ApiError> {
    if line.len() > MAX_REQUEST_BYTES {
        return Err(ApiError::new(ErrorCode::BadRequest, "request too long"));
    }
    serde_json::from_slice(line.strip_suffix(b"\n").unwrap_or(line))
        .map_err(|e| ApiError::new(ErrorCode::BadRequest, format!("invalid request: {e}")))
}

/// Checks an attestation nonce: non-empty hex, at most [`MAX_NONCE_BYTES`].
pub fn valid_nonce(nonce: &str) -> bool {
    !nonce.is_empty()
        && nonce.len().is_multiple_of(2)
        && nonce.len() <= 2 * MAX_NONCE_BYTES
        && nonce.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_format_is_stable() {
        let r = Request::SessionStatus { session: Some(7) };
        assert_eq!(encode(&r), b"{\"op\":\"session_status\",\"session\":7}\n");
        assert_eq!(
            encode(&Request::Violations { session: None }),
            b"{\"op\":\"violations\"}\n"
        );
        assert_eq!(
            decode_request(br#"{"op":"session_status"}"#).unwrap(),
            Request::SessionStatus { session: None }
        );
        let launch = decode_request(
            br#"{"op":"launch_protected","manifest":"/g/m.json","program":"/bin/game","argv":["game","-x"],"cwd":"/"}"#,
        )
        .unwrap();
        assert_eq!(
            launch,
            Request::LaunchProtected {
                manifest: Some("/g/m.json".into()),
                program: "/bin/game".into(),
                argv: vec!["game".into(), "-x".into()],
                env: vec![],
                cwd: "/".into(),
                run_as: None,
                join: None,
                install_dir: None,
                block_virtual_input: false,
            }
        );
        assert!(!String::from_utf8(encode(&launch))
            .unwrap()
            .contains("block_virtual_input"));
    }

    #[test]
    fn requests_round_trip() {
        for r in [
            Request::LaunchProtected {
                manifest: None,
                program: "/bin/true".into(),
                argv: vec!["true".into()],
                env: vec!["A=b".into()],
                cwd: "/tmp".into(),
                run_as: Some(1000),
                join: Some(3),
                install_dir: Some("/games/x".into()),
                block_virtual_input: true,
            },
            Request::SessionStatus { session: Some(1) },
            Request::SessionStatus { session: None },
            Request::Violations { session: Some(2) },
            Request::ListSessions {},
            Request::Attest {
                nonce: "00ff".into(),
            },
        ] {
            assert_eq!(decode_request(&encode(&r)).unwrap(), r);
        }
    }

    #[test]
    fn rejects_bad_requests() {
        for bad in [
            &b"not json"[..],
            br#"{"op":"format_disk"}"#,
            br#"{"op":"attest"}"#,
            br#"{"op":"session_status","session":-1}"#,
            // An identity in the request is meaningless and refused, not ignored.
            br#"{"op":"list_sessions","uid":0}"#,
            br#"{"op":"launch_protected","program":"/x","argv":["x"],"cwd":"/","uid":0}"#,
        ] {
            let e = decode_request(bad).unwrap_err();
            assert_eq!(
                e.code,
                ErrorCode::BadRequest,
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        let long = vec![b' '; MAX_REQUEST_BYTES + 1];
        assert_eq!(
            decode_request(&long).unwrap_err().code,
            ErrorCode::BadRequest
        );
    }

    #[test]
    fn response_wire_format() {
        let ok: Response = Reply::Launched {
            session: 1,
            pid: 42,
        }
        .into();
        assert_eq!(
            String::from_utf8(encode(&ok)).unwrap(),
            "{\"ok\":{\"launched\":{\"session\":1,\"pid\":42}}}\n"
        );
        let mut err = ApiError::new(ErrorCode::Unavailable, "no TPM");
        err.nonce = Some("ab".into());
        assert_eq!(
            String::from_utf8(encode(&Response::from(err))).unwrap(),
            "{\"error\":{\"code\":\"unavailable\",\"message\":\"no TPM\",\"nonce\":\"ab\"}}\n"
        );
        let game = ProcessInfo {
            pid: 9,
            argv: vec!["g".into()],
            state: ProcessState::Exited {
                code: Some(0),
                signal: None,
            },
            sandbox: None,
        };
        let text = String::from_utf8(encode(&game)).unwrap();
        assert!(
            text.contains("\"state\":\"exited\",\"code\":0,\"signal\":null"),
            "{text}"
        );
        let status = Response::Ok(Reply::Status(StatusReport {
            protected: false,
            session: Some(SessionInfo {
                session: 3,
                launcher_uid: 1000,
                uid: 1000,
                game,
                members: vec![],
                started_at: 1,
                violations: 3,
                protection_degraded: true,
                unprotected_children: 2,
                manifest: Some(Box::new(ManifestInfo {
                    name: "g".into(),
                    sha256: "00".repeat(32),
                    signer: "AAAA".into(),
                    signer_fingerprint: "ed25519:00".into(),
                    block_virtual_input: false,
                })),
            }),
            lockdown: Some("none".into()),
            virtual_input_devices: vec![
                VirtualInputDevice {
                    device: "input7".into(),
                    name: "clicker".into(),
                    kind: InputKind::Uinput,
                    created_by: Some(InputCreator {
                        pid: 77,
                        comm: "cheatsim".into(),
                        exe: "cheatsim".into(),
                        exe_path: None,
                        created_at: 4,
                    }),
                    allowlisted: false,
                    ambiguous: false,
                },
                VirtualInputDevice {
                    device: "input9".into(),
                    name: "pad".into(),
                    kind: InputKind::Uhid,
                    created_by: None,
                    allowlisted: false,
                    ambiguous: true,
                },
            ],
        }));
        let text = String::from_utf8(encode(&status)).unwrap();
        assert!(text.contains("\"kind\":\"uinput\""), "{text}");
        assert_eq!(text.matches("\"ambiguous\"").count(), 1, "{text}");
        assert_eq!(serde_json::from_str::<Response>(&text).unwrap(), status);
    }

    #[test]
    fn event_wire_format() {
        let ev = Response::Event(Event::Violation(ViolationEvent {
            session: Some(1),
            caller: 7,
            comm: "cheatsim".into(),
            exe: "cheatsim".into(),
            exe_path: None,
            target: 9,
            hook: "ptrace_access_check".into(),
            outcome: Outcome::Denied,
            mode: 0x11,
            file: None,
            seen_at: 5,
        }));
        let text = String::from_utf8(encode(&ev)).unwrap();
        assert!(
            text.starts_with("{\"event\":{\"violation\":{\"session\":1,"),
            "{text}"
        );
        assert!(!text.contains("\"file\""), "no file for process hooks");
        assert_eq!(serde_json::from_str::<Response>(&text).unwrap(), ev);

        let mapping = Response::Event(Event::Violation(ViolationEvent {
            session: Some(1),
            caller: 9,
            comm: "game".into(),
            exe: "game".into(),
            exe_path: None,
            target: 9,
            hook: "mmap_file".into(),
            outcome: Outcome::Denied,
            mode: 0x5,
            file: Some("cheat.so".into()),
            seen_at: 5,
        }));
        let text = String::from_utf8(encode(&mapping)).unwrap();
        assert!(text.contains("\"file\":\"cheat.so\""), "{text}");
        assert!(text.contains("\"outcome\":\"denied\""), "{text}");
        assert_eq!(serde_json::from_str::<Response>(&text).unwrap(), mapping);

        // An event from before milestone 7 (no outcome) reads as a denial.
        let old = text.replace(",\"outcome\":\"denied\"", "");
        assert_eq!(serde_json::from_str::<Response>(&old).unwrap(), mapping);
        assert_eq!(
            serde_json::to_string(&Outcome::Reported).unwrap(),
            "\"reported\""
        );
    }

    #[test]
    fn nonces() {
        assert!(valid_nonce("00ff"));
        assert!(valid_nonce(&"a".repeat(2 * MAX_NONCE_BYTES)));
        for bad in ["", "0", "zz", "00 ff", &"a".repeat(2 * MAX_NONCE_BYTES + 2)] {
            assert!(!valid_nonce(bad), "{bad:?}");
        }
    }

    #[test]
    fn error_display_uses_wire_code() {
        let e = ApiError::new(ErrorCode::NotFound, "no session 4");
        assert_eq!(e.to_string(), "not_found: no session 4");
    }
}
