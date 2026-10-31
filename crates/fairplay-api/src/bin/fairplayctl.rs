//! fairplayctl: talk to fairplayd from a shell.
//!
//!     fairplayctl launch -- cheatsim game       # launcher group or root
//!     fairplayctl launch --join 1 -- anticheat  # into session 1's domain
//!     fairplayctl status 1
//!     fairplayctl violations 1                  # streams until Ctrl-C
//!     fairplayctl list
//!     fairplayctl attest
//!
//! Prints the daemon's JSON lines as they arrive. Exits 0 for `ok`, 1 for
//! `error`, 2 if it couldn't talk to the daemon at all.

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
    encode, Event, Request, Response, SessionId,
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
        /// Start inside this session's protection domain (e.g. the anti-cheat).
        #[arg(long)]
        join: Option<SessionId>,
        /// Program and its arguments.
        #[arg(required = true, last = true)]
        command: Vec<String>,
    },
    /// Is a session protected? Also lockdown mode and virtual input devices.
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
    let socket = args.socket.unwrap_or_else(default_socket);
    let mut fds = vec![];
    let mut stream_count = None;
    let req = match args.cmd {
        Cmd::Launch {
            no_stdio,
            run_as,
            join,
            command,
        } => {
            if !no_stdio {
                fds = vec![0, 1, 2];
            }
            launch_request(command, run_as, join)?
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
    join: Option<SessionId>,
) -> Result<Request> {
    let cwd = std::env::current_dir().context("current directory")?;
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
        program: utf8(&program)?,
        argv: command,
        env,
        cwd: utf8(&cwd)?,
        run_as,
        join,
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
