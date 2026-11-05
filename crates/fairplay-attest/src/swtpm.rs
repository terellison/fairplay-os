//! A software TPM (`swtpm`) for tests, here and in fairplayd. Each one runs
//! on free local ports with its own temporary state directory, and is
//! killed (and its directory removed) when dropped, or killed by the kernel
//! if the thread that started it dies first.

use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tss_esapi::{
    handles::PcrHandle,
    interface_types::algorithm::HashingAlgorithm,
    structures::{Digest, DigestValues},
    tcti_ldr::TctiNameConf,
    Context,
};

use crate::PcrValue;

pub struct Swtpm {
    child: Child,
    dir: PathBuf,
    port: u16,
}

impl Swtpm {
    /// Start swtpm, or `None` (the caller skips its test) if it isn't
    /// installed. `name` keeps parallel tests' state directories apart.
    pub fn start(name: &str) -> Option<Swtpm> {
        if Command::new("swtpm")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            eprintln!("skipping {name}: swtpm is not installed");
            return None;
        }
        let dir =
            std::env::temp_dir().join(format!("fairplay-swtpm-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("swtpm state directory");
        // Tests run in parallel threads. Pick ports and wait for swtpm to own
        // them under one lock, so two tests never race for the same pair.
        static START: Mutex<()> = Mutex::new(());
        let _guard = START.lock().unwrap_or_else(|e| e.into_inner());
        for _ in 0..5 {
            let port = free_port_pair();
            let mut cmd = Command::new("swtpm");
            cmd.args(["socket", "--tpm2", "--flags", "not-need-init,startup-clear"])
                .arg("--tpmstate")
                .arg(format!("dir={}", dir.display()))
                .arg("--server")
                .arg(format!("type=tcp,bindaddr=127.0.0.1,port={port}"))
                .arg("--ctrl")
                .arg(format!("type=tcp,bindaddr=127.0.0.1,port={}", port + 1))
                .stdout(Stdio::null());
            // SAFETY: prctl is async-signal-safe; nothing else runs here.
            // If the test is killed before Drop runs, swtpm goes with it.
            unsafe {
                cmd.pre_exec(|| {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = cmd.spawn().expect("spawn swtpm");
            if wait_ready(&mut child, port) {
                return Some(Swtpm { child, dir, port });
            }
            // swtpm exited, most likely because another process took a port
            // between our probe and its bind: try another pair.
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&dir);
        panic!("swtpm did not start");
    }

    /// The TCTI string libtss2 (and fairplayd's `--tpm-tcti`) takes.
    pub fn tcti(&self) -> String {
        format!("swtpm:host=127.0.0.1,port={}", self.port)
    }

    /// Its state directory, removed on drop: a place for test files.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Extend the SHA-256 bank of `pcr` with `digest`.
    pub fn extend(&self, pcr: u8, digest: PcrValue) {
        let mut ctx = Context::new(self.tcti().parse::<TctiNameConf>().unwrap()).unwrap();
        let mut digests = DigestValues::new();
        digests.set(
            HashingAlgorithm::Sha256,
            Digest::try_from(digest.to_vec()).unwrap(),
        );
        let handle = PcrHandle::try_from(u32::from(pcr)).expect("PCR handle");
        ctx.execute_with_nullauth_session(|c| c.pcr_extend(handle, digests))
            .unwrap();
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Both ports accept connections and our swtpm is still running (it exits
/// on a bind error, so a listener then belongs to someone else).
fn wait_ready(child: &mut Child, port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    let up = |p: u16| TcpStream::connect(("127.0.0.1", p)).is_ok();
    loop {
        if !matches!(child.try_wait(), Ok(None)) {
            return false;
        }
        if up(port) && up(port + 1) {
            std::thread::sleep(Duration::from_millis(50));
            return matches!(child.try_wait(), Ok(None));
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Two consecutive free ports (swtpm's TCTI uses port + 1 for control).
fn free_port_pair() -> u16 {
    for _ in 0..100 {
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = a.local_addr().unwrap().port();
        if port < u16::MAX && TcpListener::bind(("127.0.0.1", port + 1)).is_ok() {
            return port;
        }
    }
    panic!("no free port pair");
}
