//! The Unix socket: accept, identify the caller, parse requests, dispatch.

use std::{
    io::{self, IoSliceMut},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::PermissionsExt,
    },
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use anyhow::{bail, Context, Result};
use fairplay_api::{
    decode_request, encode, valid_nonce, ApiError, ErrorCode, Event, Reply, Request, Response,
    StatusReport, ViolationEvent, MAX_REQUEST_BYTES, STDIO_FDS,
};
use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
use tokio::{
    io::Interest,
    net::{UnixListener, UnixStream},
    sync::broadcast,
};

use crate::{
    exec_allow, host, input, launch,
    state::{launch_identity, Peer, Subscription},
    Shared,
};

/// Simultaneous connections; more are refused. Each costs one task.
const MAX_CONNECTIONS: usize = 128;

#[derive(Clone)]
pub struct Ctx {
    pub daemon: Shared,
    pub events: broadcast::Sender<ViolationEvent>,
    pub launcher_gid: Option<u32>,
    /// Kernel devices of the system filesystems (milestone 8): files there
    /// that only root can write need no allowlist entry.
    pub system_devs: Arc<[u32]>,
}

/// Binds the socket, refusing to steal one a live daemon is serving. The
/// socket is world-connectable: every caller is identified by the kernel
/// and each call does its own authorization.
pub fn bind(path: &Path) -> Result<UnixListener> {
    if path.exists() {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            bail!(
                "another fairplayd is already listening on {}",
                path.display()
            );
        }
        std::fs::remove_file(path).with_context(|| format!("removing stale {}", path.display()))?;
    }
    let l = UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(l)
}

pub async fn serve(listener: UnixListener, ctx: Ctx) -> Result<()> {
    let live = Arc::new(AtomicUsize::new(0));
    loop {
        let (stream, _) = listener.accept().await?;
        if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            live.fetch_sub(1, Ordering::SeqCst);
            continue; // dropping closes it
        }
        let (ctx, live) = (ctx.clone(), live.clone());
        tokio::spawn(async move {
            if let Err(e) = connection(stream, ctx).await {
                eprintln!("fairplayd: connection: {e:#}");
            }
            live.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

async fn connection(stream: UnixStream, ctx: Ctx) -> Result<()> {
    let peer = host::peer_of(&stream)?;
    let mut reader = LineReader::default();
    while let Some((line, fds)) = reader.next(&stream).await? {
        let req = match decode_request(&line) {
            Ok(r) => r,
            Err(e) => {
                send(&stream, &Response::Error(e)).await?;
                continue;
            }
        };
        if let Request::Violations { session } = req {
            return stream_violations(&stream, &ctx, &peer, session).await;
        }
        let resp = match req {
            Request::LaunchProtected { .. } => {
                let ctx = ctx.clone();
                let peer = peer.clone();
                tokio::task::spawn_blocking(move || launch_protected(&ctx, &peer, req, fds))
                    .await
                    .unwrap_or_else(|e| Err(ApiError::new(ErrorCode::Internal, e.to_string())))
            }
            _ if !fds.is_empty() => Err(ApiError::new(
                ErrorCode::BadRequest,
                "only launch_protected takes file descriptors",
            )),
            Request::SessionStatus { session } => session_status(&ctx, &peer, session),
            Request::ListSessions {} => Ok(ctx.daemon.lock().unwrap().list(&peer)),
            Request::Attest { nonce } => Err(attest(nonce)),
            Request::Violations { .. } => unreachable!("handled above"),
        };
        send(&stream, &resp.into()).await?;
    }
    Ok(())
}

fn launch_protected(
    ctx: &Ctx,
    peer: &Peer,
    req: Request,
    fds: Vec<OwnedFd>,
) -> Result<Reply, ApiError> {
    let Request::LaunchProtected {
        program,
        argv,
        env,
        cwd,
        run_as,
        join,
        install_dir,
        block_virtual_input,
    } = req
    else {
        unreachable!()
    };
    let identity = launch_identity(peer, ctx.launcher_gid, run_as, host::lookup_user)?;
    let stdio = match <[OwnedFd; STDIO_FDS]>::try_from(fds) {
        Ok(fds) => Some(fds),
        Err(fds) if fds.is_empty() => None,
        Err(_) => {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "pass exactly 3 file descriptors (stdin, stdout, stderr) or none",
            ))
        }
    };
    let prep = launch::prepare(&program, &argv, &env, &cwd)?;
    // The code the program may map (milestone 8), listed before taking the
    // lock: a big install directory takes a while to walk.
    let dir = exec_allow::install_dir(&program, install_dir.as_deref())?;
    let files = exec_allow::launch_files(
        Path::new(&program),
        &dir,
        &ctx.system_devs,
        exec_allow::Limits::DEFAULT,
    )?;

    // Fork and register under the lock, so the reaper (which also takes it)
    // can't see the child before its session exists.
    let released = {
        let mut d = ctx.daemon.lock().unwrap();
        let mut ticket = d.begin_launch(peer, join)?;
        ticket.block_input = block_virtual_input;
        let allowed = d.allow_exec(&ticket, &files)?;
        let paused = match launch::fork_paused(&prep, &identity, stdio) {
            Ok(p) => p,
            Err(e) => {
                d.abandon_launch(&ticket);
                return Err(e);
            }
        };
        if let Err(e) = d.register(ticket, paused.pid(), peer, identity.uid, argv) {
            // `paused` drops here: the child is killed before it runs anything.
            d.abandon_launch(&ticket);
            return Err(ApiError::new(
                ErrorCode::Internal,
                format!("registering: {e:#}"),
            ));
        }
        let pid = paused.pid();
        eprintln!(
            "fairplayd: session {}: pid {pid} ({program}) protected in domain {}, running as uid {}{}{}{}; {} code files from {} allowed ({allowed} new)",
            ticket.session,
            ticket.domain,
            identity.uid,
            if ticket.join { ", joined" } else { "" },
            if ticket.block_input {
                ", blocking virtual input"
            } else {
                ""
            },
            if prep.dropped_env.is_empty() {
                String::new()
            } else {
                format!(", dropped env {:?}", prep.dropped_env)
            },
            files.len(),
            dir.display(),
        );
        (ticket.session, paused.release()?)
    };
    let (session, released) = released;
    let pid = released.wait_exec()?;
    Ok(Reply::Launched { session, pid })
}

fn session_status(ctx: &Ctx, peer: &Peer, session: Option<u64>) -> Result<Reply, ApiError> {
    // sysfs first: if a device appears between the two reads, its record
    // is already in the log.
    let devices = input::scan();
    let d = ctx.daemon.lock().unwrap();
    let (protected, session) = d.status(peer, session)?;
    let virtual_input_devices = input::correlate(devices, d.input_log(), input::pid_alive);
    Ok(Reply::Status(StatusReport {
        protected,
        session,
        lockdown: host::lockdown(),
        virtual_input_devices,
    }))
}

/// Milestone 10. There is no TPM in the VM, so say so; never fake a quote.
fn attest(nonce: String) -> ApiError {
    let mut e = if !valid_nonce(&nonce) {
        ApiError::new(ErrorCode::BadRequest, "nonce must be 1-64 bytes of hex")
    } else {
        let bytes: Vec<u8> = (0..nonce.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&nonce[i..i + 2], 16).unwrap())
            .collect();
        match fairplay_attest::collect(&bytes) {
            Err(fairplay_attest::Error::NoTpm) => ApiError::new(
                ErrorCode::Unavailable,
                if Path::new("/dev/tpmrm0").exists() {
                    "attestation is not implemented yet (milestone 10)"
                } else {
                    "no TPM on this machine; attestation needs one (milestone 10)"
                },
            ),
            Err(fairplay_attest::Error::Other(m)) => ApiError::new(ErrorCode::Unavailable, m),
            Ok(_) => ApiError::new(
                ErrorCode::Unavailable,
                "evidence encoding is not defined yet (milestone 10)",
            ),
        }
    };
    e.nonce = Some(nonce);
    e
}

async fn stream_violations(
    stream: &UnixStream,
    ctx: &Ctx,
    peer: &Peer,
    session: Option<u64>,
) -> Result<()> {
    // Subscribe before confirming, so nothing between the two is missed.
    let mut rx = ctx.events.subscribe();
    let sub = ctx.daemon.lock().unwrap().subscribe(peer, session);
    let sub = match sub {
        Ok(s) => s,
        Err(e) => {
            drop(rx);
            return send(stream, &Response::Error(e)).await;
        }
    };
    let session = match sub {
        Subscription::Session(id) => Some(id),
        Subscription::All => None,
    };
    send(stream, &Reply::Subscribed { session }.into()).await?;
    let mut scratch = [0u8; 256];
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(ev) if sub.wants(&ev) => send(stream, &Response::Event(Event::Violation(ev))).await?,
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    send(stream, &Response::Event(Event::Lagged { missed })).await?
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
            // The subscriber sends nothing more; EOF means it hung up.
            r = stream.readable() => {
                r?;
                match stream.try_read(&mut scratch) {
                    Ok(0) => return Ok(()),
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
}

async fn send(stream: &UnixStream, resp: &Response) -> Result<()> {
    let line = encode(resp);
    let mut sent = 0;
    while sent < line.len() {
        stream.writable().await?;
        match stream.try_write(&line[sent..]) {
            Ok(n) => sent += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Splits the byte stream into lines, collecting any file descriptors that
/// arrive with a line's bytes (the client sends them on the line's first
/// `sendmsg`).
#[derive(Default)]
struct LineReader {
    buf: Vec<u8>,
    fds: Vec<OwnedFd>,
}

impl LineReader {
    async fn next(&mut self, stream: &UnixStream) -> Result<Option<(Vec<u8>, Vec<OwnedFd>)>> {
        loop {
            if let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=i).collect();
                return Ok(Some((line, std::mem::take(&mut self.fds))));
            }
            if self.buf.len() >= MAX_REQUEST_BYTES {
                bail!("request longer than {MAX_REQUEST_BYTES} bytes");
            }
            let mut chunk = [0u8; 4096];
            let (n, fds) = stream
                .async_io(Interest::READABLE, || recv_with_fds(stream, &mut chunk))
                .await?;
            self.fds.extend(fds);
            if self.fds.len() > STDIO_FDS {
                bail!("too many file descriptors");
            }
            if n == 0 {
                return Ok(None);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

fn recv_with_fds(stream: &UnixStream, buf: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    let mut cmsg = nix::cmsg_space!([std::os::fd::RawFd; STDIO_FDS + 1]);
    let mut iov = [IoSliceMut::new(buf)];
    let msg = recvmsg::<()>(
        stream.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::MSG_CMSG_CLOEXEC | MsgFlags::MSG_DONTWAIT,
    )
    .map_err(io::Error::from)?;
    let mut fds = vec![];
    for c in msg.cmsgs().map_err(io::Error::from)? {
        if let ControlMessageOwned::ScmRights(raw) = c {
            // SAFETY: the kernel just installed these descriptors for us.
            fds.extend(
                raw.into_iter()
                    .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
            );
        }
    }
    if msg.flags.contains(MsgFlags::MSG_CTRUNC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "too many file descriptors",
        ));
    }
    Ok((msg.bytes, fds))
}
