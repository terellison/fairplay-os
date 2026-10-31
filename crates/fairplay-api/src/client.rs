//! A blocking client for fairplayd's socket.
//!
//! [`Client::connect`] checks who serves the socket before sending
//! anything (issue #27): root can delete `/run/fairplayd.sock` and serve a
//! fake one that answers "protected" to everything. The kernel says who
//! listens (`SO_PEERCRED`), and the client requires:
//!
//! - uid 0. fairplayd always runs as root; this rules out anything else
//!   serving a socket at `$FAIRPLAYD_SOCKET`.
//! - inside a protected session, the very fairplayd that launched it: the
//!   pid in `$FAIRPLAYD_PID`, which fairplayd sets for what it launches. A
//!   self-protected fairplayd can't be killed, so its pid can't be taken
//!   over, and root can't change a protected process's environment.
//!
//! Outside a session (a launcher, `fairplayctl`) only the uid can be
//! checked: any root process could be serving. Attestation (milestone 10)
//! is the real answer: a quote over the measured boot chain, from the TPM,
//! that a fake can't produce.

use std::{
    io::{BufRead, BufReader, IoSlice, Write},
    os::{
        fd::{AsRawFd, RawFd},
        unix::net::UnixStream,
    },
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use nix::sys::socket::{getsockopt, sendmsg, sockopt::PeerCredentials, ControlMessage, MsgFlags};

use crate::{encode, Reply, Request, Response, DEFAULT_SOCKET, PID_ENV, SOCKET_ENV};

/// `$FAIRPLAYD_SOCKET`, else [`DEFAULT_SOCKET`].
pub fn default_socket() -> PathBuf {
    std::env::var_os(SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET))
}

pub struct Client {
    reader: BufReader<UnixStream>,
}

/// `$FAIRPLAYD_PID`: the fairplayd that launched this process, if any.
pub fn expected_pid() -> Result<Option<u32>> {
    match std::env::var(PID_ENV) {
        Ok(v) => v
            .parse()
            .map(Some)
            .with_context(|| format!("${PID_ENV} is {v:?}, not a pid")),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading ${PID_ENV}")),
    }
}

/// Is the process serving the socket (`uid`, `pid`, from `SO_PEERCRED`)
/// one we may talk to? See the module docs.
pub fn check_server(uid: u32, pid: u32, expected_pid: Option<u32>) -> Result<()> {
    if uid != 0 {
        bail!("the socket is served by pid {pid} running as uid {uid}, not by root: not fairplayd");
    }
    if let Some(want) = expected_pid {
        if pid != want {
            bail!(
                "the socket is served by pid {pid}, not by the fairplayd that launched \
                 this process (pid {want}, from ${PID_ENV})"
            );
        }
    }
    Ok(())
}

impl Client {
    /// Connects and checks who serves the socket ([`check_server`]), with
    /// `$FAIRPLAYD_PID` if it is set.
    pub fn connect(path: &Path) -> Result<Self> {
        Self::connect_expecting(path, expected_pid()?)
    }

    /// [`Client::connect`], requiring the server to be `pid` if given.
    pub fn connect_expecting(path: &Path, pid: Option<u32>) -> Result<Self> {
        let stream = UnixStream::connect(path)
            .with_context(|| format!("connecting to fairplayd at {}", path.display()))?;
        let peer = getsockopt(&stream, PeerCredentials)
            .with_context(|| format!("asking the kernel who serves {}", path.display()))?;
        check_server(peer.uid(), peer.pid() as u32, pid)
            .with_context(|| format!("refusing {}", path.display()))?;
        Ok(Self {
            reader: BufReader::new(stream),
        })
    }

    /// Sends one request and waits for its response.
    pub fn call(&mut self, req: &Request) -> Result<Response> {
        self.call_with_fds(req, &[])
    }

    /// Like [`Client::call`], passing `fds` (e.g. stdin, stdout, stderr) to
    /// the daemon alongside the request.
    pub fn call_with_fds(&mut self, req: &Request, fds: &[RawFd]) -> Result<Response> {
        let line = encode(req);
        let stream = self.reader.get_mut();
        let sent = if fds.is_empty() {
            0
        } else {
            // The fds ride on the first bytes of the request.
            let cmsg = [ControlMessage::ScmRights(fds)];
            sendmsg::<()>(
                stream.as_raw_fd(),
                &[IoSlice::new(&line)],
                &cmsg,
                MsgFlags::empty(),
                None,
            )
            .context("sending request")?
        };
        stream.write_all(&line[sent..]).context("sending request")?;
        match self.next_response()? {
            Some(r) => Ok(r),
            None => bail!("fairplayd closed the connection"),
        }
    }

    /// The next line from the daemon: after a `violations` subscription,
    /// each [`Response::Event`]. `None` when the daemon hangs up.
    pub fn next_response(&mut self) -> Result<Option<Response>> {
        let mut buf = String::new();
        if self
            .reader
            .read_line(&mut buf)
            .context("reading response")?
            == 0
        {
            return Ok(None);
        }
        serde_json::from_str(&buf)
            .map(Some)
            .with_context(|| format!("bad response from fairplayd: {buf}"))
    }

    /// [`Client::call`], turning an error response into `Err`.
    pub fn ok(&mut self, req: &Request) -> Result<Reply> {
        match self.call(req)? {
            Response::Ok(r) => Ok(r),
            Response::Error(e) => Err(e.into()),
            Response::Event(e) => bail!("unexpected event {e:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_must_be_root() {
        assert!(check_server(0, 42, None).is_ok());
        let e = check_server(1000, 42, None).unwrap_err().to_string();
        assert!(e.contains("uid 1000"), "{e}");
    }

    #[test]
    fn inside_a_session_it_must_be_the_launching_fairplayd() {
        assert!(check_server(0, 42, Some(42)).is_ok());
        let e = check_server(0, 43, Some(42)).unwrap_err().to_string();
        assert!(e.contains("pid 43") && e.contains("pid 42"), "{e}");
        assert!(
            check_server(1000, 42, Some(42)).is_err(),
            "uid still counts"
        );
    }
}
