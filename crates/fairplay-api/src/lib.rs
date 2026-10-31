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
//! from the request, so nothing in a request claims an identity.
//!
//! `launch_protected` may carry the caller's stdin, stdout and stderr as
//! file descriptors (`SCM_RIGHTS`) on the same `sendmsg` as the request line;
//! the game then writes to the caller's terminal. Without them it gets
//! `/dev/null`.
//!
//! ```text
//! -> {"op":"launch_protected","program":"/usr/bin/game","argv":["game"],"env":["HOME=/home/me"],"cwd":"/home/me"}
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

/// Where fairplayd listens unless told otherwise.
pub const DEFAULT_SOCKET: &str = "/run/fairplayd.sock";
/// Environment variable clients read to find a non-default socket.
pub const SOCKET_ENV: &str = "FAIRPLAYD_SOCKET";
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
    LaunchProtected {
        /// Absolute path of the executable. The client resolves `PATH`.
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
        /// domain instead of a new one: how the vendor's anti-cheat joins
        /// the game it watches.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        join: Option<SessionId>,
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
    /// Names of virtual input devices that exist right now (e.g. ones made
    /// through `/dev/uinput`). Reported, not blocked (milestone 7).
    pub virtual_input_devices: Vec<String>,
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
    pub members: Vec<ProcessInfo>,
    /// Seconds since the Unix epoch.
    pub started_at: u64,
    pub violations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub argv: Vec<String>,
    /// Serialized inline: `"state":"running"` or
    /// `"state":"exited","code":0,"signal":null`.
    #[serde(flatten)]
    pub state: ProcessState,
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

/// One attempt the kernel denied.
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
    /// The protected process it targeted.
    pub target: u32,
    /// LSM hook that denied it, e.g. `ptrace_access_check`.
    pub hook: String,
    /// ptrace access mode bits the caller asked for.
    pub mode: u32,
    /// Seconds since the Unix epoch, when fairplayd read the record.
    pub seen_at: u64,
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
            br#"{"op":"launch_protected","program":"/bin/game","argv":["game","-x"],"cwd":"/"}"#,
        )
        .unwrap();
        assert_eq!(
            launch,
            Request::LaunchProtected {
                program: "/bin/game".into(),
                argv: vec!["game".into(), "-x".into()],
                env: vec![],
                cwd: "/".into(),
                run_as: None,
                join: None,
            }
        );
    }

    #[test]
    fn requests_round_trip() {
        for r in [
            Request::LaunchProtected {
                program: "/bin/true".into(),
                argv: vec!["true".into()],
                env: vec!["A=b".into()],
                cwd: "/tmp".into(),
                run_as: Some(1000),
                join: Some(3),
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
            }),
            lockdown: Some("none".into()),
            virtual_input_devices: vec![],
        }));
        let text = String::from_utf8(encode(&status)).unwrap();
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
            mode: 0x11,
            seen_at: 5,
        }));
        let text = String::from_utf8(encode(&ev)).unwrap();
        assert!(
            text.starts_with("{\"event\":{\"violation\":{\"session\":1,"),
            "{text}"
        );
        assert_eq!(serde_json::from_str::<Response>(&text).unwrap(), ev);
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
