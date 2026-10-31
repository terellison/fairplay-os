//! `socket_connect` and `socket_sendmsg` (milestone 9, part B): no
//! abstract Unix sockets for a sandboxed process. An abstract address
//! (`sun_path[0] == 0`, written `@name`) has no file, so the sandbox's
//! mount namespace can't hide it: it belongs to the network namespace,
//! which the anti-cheat shares to reach its server. X11 and XWayland listen
//! on `@/tmp/.X11-unix/X<n>` (keylogging, screenshots), and so do some
//! system daemons. Pathname sockets are already limited to what the
//! sandbox's file system holds (the fairplayd socket).
//!
//! `connect` covers stream sockets and connected datagram sockets;
//! `sendmsg` covers `sendto`/`sendmsg` with an address on an unconnected
//! datagram socket. Both see the address already copied into the kernel.

use aya_ebpf::{helpers::bpf_probe_read_kernel, macros::lsm, programs::LsmContext};
use core::ptr::addr_of;
use fairplay_common::Hook;

use crate::{
    domain::{record_in, sandboxed, Name, EPERM},
    vmlinux::msghdr,
};

const AF_UNIX: u16 = 1;

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    // int socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
    // For BPF LSM, arg 3 is the verdict from earlier LSMs in the stack.
    let prev: i32 = unsafe { ctx.arg(3) };
    if prev != 0 {
        return prev;
    }
    let addr: *const u8 = unsafe { ctx.arg(1) };
    let len: i32 = unsafe { ctx.arg(2) };
    match abstract_denied(addr, len) {
        Ok(true) => -EPERM,
        _ => 0,
    }
}

#[lsm(hook = "socket_sendmsg")]
pub fn socket_sendmsg(ctx: LsmContext) -> i32 {
    // int socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
    let prev: i32 = unsafe { ctx.arg(3) };
    if prev != 0 {
        return prev;
    }
    let msg: *const msghdr = unsafe { ctx.arg(1) };
    let verdict = (|| -> Result<bool, i64> {
        if sandboxed().is_none() {
            return Ok(false);
        }
        let addr = unsafe { bpf_probe_read_kernel(addr_of!((*msg).msg_name))? } as *const u8;
        let len = unsafe { bpf_probe_read_kernel(addr_of!((*msg).msg_namelen))? };
        if addr.is_null() {
            return Ok(false);
        }
        abstract_denied(addr, len)
    })();
    match verdict {
        Ok(true) => -EPERM,
        _ => 0,
    }
}

/// For a sandboxed caller: is `addr` an abstract Unix address? Records it.
fn abstract_denied(addr: *const u8, len: i32) -> Result<bool, i64> {
    let Some((caller, domain)) = sandboxed() else {
        return Ok(false);
    };
    // sa_family (2 bytes), then at least the leading NUL of the name.
    if len <= 2 {
        return Ok(false);
    }
    let family: u16 = unsafe { bpf_probe_read_kernel(addr as *const u16)? };
    if family != AF_UNIX {
        return Ok(false);
    }
    let first: u8 = unsafe { bpf_probe_read_kernel(addr.add(2))? };
    if first != 0 {
        return Ok(false);
    }
    // The name after the leading NUL, up to its first NUL.
    record_in(
        caller,
        0,
        domain,
        Hook::UnixAbstract,
        len as u32,
        0,
        Name::Str(unsafe { addr.add(3) }),
    );
    Ok(true)
}
