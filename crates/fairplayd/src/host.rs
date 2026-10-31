//! Facts about the machine and its users, read from the kernel and the user
//! database. Best-effort: a missing file means "unknown", not an error.

use std::{fs, os::fd::AsRawFd};

use anyhow::{bail, Result};
use nix::{
    sys::socket::{getsockopt, sockopt::PeerCredentials},
    unistd::{getgrouplist, Gid, Group, Uid, User},
};

use crate::state::Peer;

/// Selected kernel lockdown mode, from `/sys/kernel/security/lockdown`.
pub fn lockdown() -> Option<String> {
    parse_lockdown(&fs::read_to_string("/sys/kernel/security/lockdown").ok()?)
}

/// `"[none] integrity confidentiality"` -> `"none"`.
pub fn parse_lockdown(s: &str) -> Option<String> {
    let start = s.find('[')? + 1;
    let len = s[start..].find(']')?;
    Some(s[start..start + len].to_owned())
}

/// A uid's primary gid and full group list, from the user database.
pub fn lookup_user(uid: u32) -> Option<(u32, Vec<u32>)> {
    let user = User::from_uid(Uid::from_raw(uid)).ok()??;
    let name = std::ffi::CString::new(user.name).ok()?;
    let groups = getgrouplist(&name, user.gid).ok()?;
    Some((
        user.gid.as_raw(),
        groups.into_iter().map(Gid::as_raw).collect(),
    ))
}

/// `uid`'s home directory, from the user database.
pub fn home_dir(uid: u32) -> Option<std::path::PathBuf> {
    Some(User::from_uid(Uid::from_raw(uid)).ok()??.dir)
}

pub fn group_gid(name: &str) -> Option<u32> {
    Group::from_name(name).ok()?.map(|g| g.gid.as_raw())
}

/// The connecting process's credentials, as the kernel recorded them at
/// `connect()`.
pub fn peer_of(sock: &impl AsRawFd) -> Result<Peer> {
    let fd = sock.as_raw_fd();
    // SAFETY: fd is a live socket for the duration of this call.
    let bfd = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    let cred = getsockopt(&bfd, PeerCredentials)?;
    Ok(Peer {
        pid: cred.pid() as u32,
        uid: cred.uid(),
        gid: cred.gid(),
        groups: peer_groups(fd)?,
    })
}

/// `SO_PEERGROUPS` (Linux 4.13+): the peer's supplementary groups.
fn peer_groups(fd: i32) -> Result<Vec<u32>> {
    // Same value on every architecture we build for (asm-generic).
    const SO_PEERGROUPS: libc::c_int = 59;
    let mut groups: Vec<libc::gid_t> = vec![0; 64];
    loop {
        let mut len = (groups.len() * std::mem::size_of::<libc::gid_t>()) as libc::socklen_t;
        // SAFETY: the buffer is `len` bytes long and outlives the call.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_PEERGROUPS,
                groups.as_mut_ptr().cast(),
                &mut len,
            )
        };
        let n = len as usize / std::mem::size_of::<libc::gid_t>();
        if rc == 0 {
            groups.truncate(n);
            return Ok(groups);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ERANGE) && n > groups.len() && n <= 65536 {
            groups.resize(n, 0);
            continue;
        }
        bail!("SO_PEERGROUPS: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockdown_modes() {
        assert_eq!(
            parse_lockdown("[none] integrity confidentiality\n").as_deref(),
            Some("none")
        );
        assert_eq!(
            parse_lockdown("none [integrity] confidentiality").as_deref(),
            Some("integrity")
        );
        assert_eq!(parse_lockdown("garbage"), None);
    }

    #[test]
    fn peer_credentials_over_a_socketpair() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let p = peer_of(&a).unwrap();
        assert_eq!(p.pid, std::process::id());
        // SAFETY: no preconditions.
        assert_eq!(p.uid, unsafe { libc::geteuid() });
        assert_eq!(p.gid, unsafe { libc::getegid() });
    }

    #[test]
    fn root_is_in_the_user_database() {
        let (gid, groups) = lookup_user(0).unwrap();
        assert_eq!(gid, 0);
        assert!(groups.contains(&0));
    }
}
