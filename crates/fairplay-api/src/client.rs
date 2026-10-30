//! A blocking client for fairplayd's socket.

use std::{
    io::{BufRead, BufReader, IoSlice, Write},
    os::{
        fd::{AsRawFd, RawFd},
        unix::net::UnixStream,
    },
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};

use crate::{encode, Reply, Request, Response, DEFAULT_SOCKET, SOCKET_ENV};

/// `$FAIRPLAYD_SOCKET`, else [`DEFAULT_SOCKET`].
pub fn default_socket() -> PathBuf {
    std::env::var_os(SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET))
}

pub struct Client {
    reader: BufReader<UnixStream>,
}

impl Client {
    pub fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path)
            .with_context(|| format!("connecting to fairplayd at {}", path.display()))?;
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
