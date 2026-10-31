//! Milestone 7: synthetic input, the way aimbots and triggerbots fake it.
//!
//! - `clicker`: a virtual mouse through `/dev/uinput` that clicks;
//! - `uhid`: a virtual HID mouse through `/dev/uhid` that moves;
//! - `inject`: one event written straight into an existing
//!   `/dev/input/event*` node.
//!
//! Each prints one line a test can wait for: `CREATED ...` or
//! `CREATE-BLOCKED ...: <error>`, `INJECTED ...` or `INJECT-BLOCKED ...`.
//! Devices live until `--hold` runs out or the process is killed (the kernel
//! removes them when the fd closes).

use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::fd::AsRawFd,
    process::ExitCode,
    thread,
    time::Duration,
};

const EV_SYN: u16 = 0;
const EV_KEY: u16 = 1;
const EV_REL: u16 = 2;
const SYN_REPORT: u16 = 0;
const BTN_LEFT: u16 = 0x110;
const REL_X: u16 = 0;
const REL_Y: u16 = 1;
const BUS_VIRTUAL: u16 = 6;

/// `<linux/uinput.h>` ioctls: `_IOW('U', nr, size)`.
const fn iow(nr: u64, size: u64) -> u64 {
    (1 << 30) | (size << 16) | ((b'U' as u64) << 8) | nr
}
const UI_SET_EVBIT: u64 = iow(100, 4);
const UI_SET_KEYBIT: u64 = iow(101, 4);
const UI_SET_RELBIT: u64 = iow(102, 4);
const UI_DEV_SETUP: u64 = iow(3, UINPUT_SETUP_SIZE as u64);
/// `_IO('U', 1)`
const UI_DEV_CREATE: u64 = 0x5501;
/// `_IO('U', 2)`
const UI_DEV_DESTROY: u64 = 0x5502;
const UINPUT_MAX_NAME_SIZE: usize = 80;
/// `struct uinput_setup`: `struct input_id` (4 x u16), name, ff_effects_max.
const UINPUT_SETUP_SIZE: usize = 8 + UINPUT_MAX_NAME_SIZE + 4;

fn ioctl(f: &File, req: u64, arg: libc::c_ulong) -> std::io::Result<()> {
    // SAFETY: every request used here takes an int by value or a pointer
    // to a buffer of the size encoded in the request, which the caller owns.
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), req as _, arg) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `struct input_event` as the kernel reads it on 64-bit: a zero timestamp
/// (the kernel stamps it), type, code, value.
fn input_event(kind: u16, code: u16, value: i32) -> [u8; 24] {
    let mut e = [0u8; 24];
    e[16..18].copy_from_slice(&kind.to_ne_bytes());
    e[18..20].copy_from_slice(&code.to_ne_bytes());
    e[20..24].copy_from_slice(&value.to_ne_bytes());
    e
}

fn open_rw(path: &str) -> std::io::Result<File> {
    OpenOptions::new().read(true).write(true).open(path)
}

fn hold(secs: u64) {
    thread::sleep(Duration::from_secs(secs));
}

/// A uinput mouse named `name` that clicks `clicks` times, then stays for
/// `hold_secs`.
pub fn clicker(name: &str, clicks: u32, hold_secs: u64) -> ExitCode {
    let f = match open_rw("/dev/uinput") {
        Ok(f) => f,
        Err(e) => {
            println!("CREATE-BLOCKED uinput {name}: open /dev/uinput: {e}");
            return ExitCode::FAILURE;
        }
    };
    let setup = (|| {
        ioctl(&f, UI_SET_EVBIT, EV_KEY.into())?;
        ioctl(&f, UI_SET_KEYBIT, BTN_LEFT.into())?;
        ioctl(&f, UI_SET_EVBIT, EV_REL.into())?;
        ioctl(&f, UI_SET_RELBIT, REL_X.into())?;
        ioctl(&f, UI_SET_RELBIT, REL_Y.into())?;
        let mut s = [0u8; UINPUT_SETUP_SIZE];
        s[0..2].copy_from_slice(&BUS_VIRTUAL.to_ne_bytes());
        s[2..4].copy_from_slice(&0xfa1du16.to_ne_bytes()); // vendor
        s[4..6].copy_from_slice(&0x0007u16.to_ne_bytes()); // product
        let n = name.len().min(UINPUT_MAX_NAME_SIZE - 1);
        s[8..8 + n].copy_from_slice(&name.as_bytes()[..n]);
        ioctl(&f, UI_DEV_SETUP, s.as_ptr() as libc::c_ulong)
    })();
    if let Err(e) = setup {
        println!("CREATE-BLOCKED uinput {name}: setup: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = ioctl(&f, UI_DEV_CREATE, 0) {
        println!("CREATE-BLOCKED uinput {name}: UI_DEV_CREATE: {e}");
        return ExitCode::FAILURE;
    }
    println!("CREATED uinput {name}");
    let mut w = &f;
    for _ in 0..clicks {
        for (k, c, v) in [
            (EV_KEY, BTN_LEFT, 1),
            (EV_SYN, SYN_REPORT, 0),
            (EV_KEY, BTN_LEFT, 0),
            (EV_SYN, SYN_REPORT, 0),
        ] {
            if let Err(e) = w.write_all(&input_event(k, c, v)) {
                println!("CLICK-FAILED: {e}");
                return ExitCode::FAILURE;
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    println!("CLICKED {clicks}");
    hold(hold_secs);
    let _ = ioctl(&f, UI_DEV_DESTROY, 0);
    ExitCode::SUCCESS
}

/// `<linux/uhid.h>`
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;
/// Offsets in the packed `struct uhid_event` for `UHID_CREATE2`.
const CREATE2_NAME: usize = 4;
const CREATE2_RD_SIZE: usize = 4 + 128 + 64 + 64;
const CREATE2_BUS: usize = CREATE2_RD_SIZE + 2;
const CREATE2_VENDOR: usize = CREATE2_BUS + 2;
const CREATE2_PRODUCT: usize = CREATE2_VENDOR + 4;
const CREATE2_RD_DATA: usize = CREATE2_PRODUCT + 4 + 4 + 4;
const UHID_DATA_MAX: usize = 4096;

/// A three-button relative mouse (the HID boot mouse descriptor).
const MOUSE_DESCRIPTOR: &[u8] = &[
    0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x09, 0x01, 0xa1, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29, 0x03,
    0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02, 0x95, 0x01, 0x75, 0x05, 0x81, 0x01,
    0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x15, 0x81, 0x25, 0x7f, 0x75, 0x08, 0x95, 0x02, 0x81, 0x06,
    0xc0, 0xc0,
];

/// A uhid mouse named `name` that moves `moves` times, then stays for
/// `hold_secs`.
pub fn uhid(name: &str, moves: u32, hold_secs: u64) -> ExitCode {
    let mut f = match open_rw("/dev/uhid") {
        Ok(f) => f,
        Err(e) => {
            println!("CREATE-BLOCKED uhid {name}: open /dev/uhid: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut ev = vec![0u8; CREATE2_RD_DATA + UHID_DATA_MAX];
    ev[0..4].copy_from_slice(&UHID_CREATE2.to_ne_bytes());
    let n = name.len().min(127);
    ev[CREATE2_NAME..CREATE2_NAME + n].copy_from_slice(&name.as_bytes()[..n]);
    ev[CREATE2_RD_SIZE..CREATE2_RD_SIZE + 2]
        .copy_from_slice(&(MOUSE_DESCRIPTOR.len() as u16).to_ne_bytes());
    ev[CREATE2_BUS..CREATE2_BUS + 2].copy_from_slice(&BUS_VIRTUAL.to_ne_bytes());
    ev[CREATE2_VENDOR..CREATE2_VENDOR + 4].copy_from_slice(&0xfa1du32.to_ne_bytes());
    ev[CREATE2_PRODUCT..CREATE2_PRODUCT + 4].copy_from_slice(&0x0008u32.to_ne_bytes());
    ev[CREATE2_RD_DATA..CREATE2_RD_DATA + MOUSE_DESCRIPTOR.len()].copy_from_slice(MOUSE_DESCRIPTOR);
    if let Err(e) = f.write_all(&ev) {
        println!("CREATE-BLOCKED uhid {name}: UHID_CREATE2: {e}");
        return ExitCode::FAILURE;
    }
    println!("CREATED uhid {name}");
    // Wait for the HID core to make the input device, then move.
    thread::sleep(Duration::from_millis(200));
    for i in 0..moves {
        let mut e = [0u8; 4 + 2 + 3];
        e[0..4].copy_from_slice(&UHID_INPUT2.to_ne_bytes());
        e[4..6].copy_from_slice(&3u16.to_ne_bytes());
        e[7] = if i % 2 == 0 { 5 } else { (-5i8) as u8 }; // dx
        if let Err(e) = f.write_all(&e) {
            println!("MOVE-FAILED: {e}");
            return ExitCode::FAILURE;
        }
        thread::sleep(Duration::from_millis(20));
    }
    println!("MOVED {moves}");
    hold(hold_secs);
    ExitCode::SUCCESS
}

/// Writes one `SYN_REPORT` into `device`: the smallest injected event, and
/// a harmless one.
pub fn inject(device: &str) -> ExitCode {
    let r = OpenOptions::new()
        .write(true)
        .open(device)
        .and_then(|mut f| f.write_all(&input_event(EV_SYN, SYN_REPORT, 0)));
    match r {
        Ok(()) => {
            println!("INJECTED {device}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("INJECT-BLOCKED {device}: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_numbers_match_the_headers() {
        assert_eq!(UI_SET_EVBIT, 0x4004_5564);
        assert_eq!(UI_SET_KEYBIT, 0x4004_5565);
        assert_eq!(UI_SET_RELBIT, 0x4004_5566);
        assert_eq!(UI_DEV_SETUP, 0x405c_5503);
    }

    #[test]
    fn uhid_create2_layout() {
        // struct uhid_create2_req: name[128] phys[64] uniq[64] rd_size bus
        // vendor product version country rd_data[4096], after the u32 type.
        assert_eq!(CREATE2_RD_SIZE, 260);
        assert_eq!(CREATE2_RD_DATA, 280);
        assert_eq!(CREATE2_RD_DATA + UHID_DATA_MAX, 4376);
    }

    #[test]
    fn event_layout() {
        let e = input_event(EV_KEY, BTN_LEFT, 1);
        assert_eq!(&e[..16], &[0; 16]);
        assert_eq!(u16::from_ne_bytes([e[18], e[19]]), BTN_LEFT);
    }
}
