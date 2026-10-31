//! `cheatsim forkbomb` (issue #21): a game that forks without end, to fill
//! the kernel's PROTECTED map and lock other sessions out. `--workers`
//! processes fork at once, each until a fork fails, so forks race on
//! several CPUs; with `--keep-trying` they go on trying for that many
//! seconds. Every process stays alive (blocked in `pause`) until the bomb
//! is killed, and dies with its parent, so killing the first process ends
//! them all.
//!
//! Prints `FORKBOMB forked=<n> errno=<names> refused=<n>`: how many
//! processes it forked in all (workers included), the error each worker's
//! first failed fork got (`EAGAIN` from the member cap; `none` if it
//! stopped at `--max`), and how many forks failed in all.

use std::{
    io::{Read, Write},
    process::ExitCode,
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    sys::{prctl, signal::Signal},
    unistd::{fork, getpid, getppid, pipe, ForkResult, Pid},
};

/// Forks a child that dies with this process and runs `child`; returns the
/// child's pid, or the fork's error.
fn spawn(child: impl FnOnce()) -> Result<Pid, Errno> {
    let parent = getpid();
    // SAFETY: single-threaded; the child only forks, writes and pauses.
    match unsafe { fork() }? {
        ForkResult::Child => {
            if prctl::set_pdeathsig(Signal::SIGKILL).is_err() || getppid() != parent {
                std::process::exit(1);
            }
            child();
            std::process::exit(0)
        }
        ForkResult::Parent { child } => Ok(child),
    }
}

fn hold() -> ! {
    loop {
        // SAFETY: no preconditions.
        unsafe { libc::pause() };
    }
}

/// One worker: forks until refused (or `max`), then keeps trying until
/// `keep_trying` has passed. Returns (forked, first error, refused).
fn work(max: u32, keep_trying: Duration) -> (u32, Errno, u32) {
    let (mut forked, mut refused) = (0u32, 0u32);
    let mut first = Errno::UnknownErrno;
    while forked < max {
        match spawn(|| hold()) {
            Ok(_) => forked += 1,
            Err(e) => {
                first = e;
                refused += 1;
                break;
            }
        }
    }
    let until = Instant::now() + keep_trying;
    while refused > 0 && forked < max && Instant::now() < until {
        match spawn(|| hold()) {
            Ok(_) => forked += 1,
            Err(_) => refused += 1,
        }
    }
    (forked, first, refused)
}

pub fn forkbomb(workers: u32, max: u32, keep_trying: u64) -> ExitCode {
    let (rd, wr) = match pipe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cheatsim: pipe: {e}");
            return ExitCode::FAILURE;
        }
    };
    let keep_trying = Duration::from_secs(keep_trying);
    let mut started = 0u32;
    for _ in 0..workers {
        let wr = wr.try_clone().expect("dup pipe");
        let r = spawn(move || {
            let (forked, first, refused) = work(max, keep_trying);
            let mut msg = [0u8; 12];
            msg[..4].copy_from_slice(&forked.to_ne_bytes());
            msg[4..8].copy_from_slice(&(first as i32).to_ne_bytes());
            msg[8..].copy_from_slice(&refused.to_ne_bytes());
            let mut f = std::fs::File::from(wr);
            let _ = f.write_all(&msg);
            drop(f);
            hold()
        });
        match r {
            Ok(_) => started += 1,
            Err(e) => {
                eprintln!("cheatsim: starting a worker: {e}");
                break;
            }
        }
    }
    drop(wr);
    let mut rd = std::fs::File::from(rd);
    let (mut total, mut refused) = (started, 0u32);
    let mut errors: Vec<String> = vec![];
    for _ in 0..started {
        let mut msg = [0u8; 12];
        if rd.read_exact(&mut msg).is_err() {
            break;
        }
        let word = |i: usize| <[u8; 4]>::try_from(&msg[i..i + 4]).unwrap();
        total += u32::from_ne_bytes(word(0));
        refused += u32::from_ne_bytes(word(8));
        let e = Errno::from_raw(i32::from_ne_bytes(word(4)));
        let name = if e == Errno::UnknownErrno {
            "none".to_string()
        } else {
            format!("{e:?}")
        };
        if !errors.contains(&name) {
            errors.push(name);
        }
    }
    println!(
        "FORKBOMB forked={total} errno={} refused={refused}",
        errors.join(",")
    );
    let _ = std::io::stdout().flush();
    hold()
}
