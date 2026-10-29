//! Milestone 1 exit test: load a hello-world BPF LSM program and show it runs.
//!
//!     sudo lsm-hello --obj crates/lsm-hello-ebpf/target/bpfel-unknown-none/release/lsm-hello
//!     # in another shell:
//!     cat /etc/hostname
//!
//! Every file `cat` opens is logged here until Ctrl-C.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use aya::{programs::Lsm, Btf, Ebpf};
use aya_log::EbpfLogger;
use clap::Parser;

#[derive(Parser)]
#[command(about = "Log every file_open by a process named cat")]
struct Args {
    /// Compiled eBPF object (crates/lsm-hello-ebpf/target/bpfel-unknown-none/release/lsm-hello)
    #[arg(long)]
    obj: PathBuf,
    /// Exit after this many seconds instead of waiting for Ctrl-C
    #[arg(long)]
    seconds: Option<u64>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let mut ebpf =
        Ebpf::load_file(&args.obj).with_context(|| format!("loading {}", args.obj.display()))?;
    EbpfLogger::init(&mut ebpf).context("starting aya-log")?;
    let btf = Btf::from_sys_fs().context("reading kernel BTF")?;
    let prog: &mut Lsm = ebpf
        .program_mut("file_open")
        .context("program file_open missing from object")?
        .try_into()?;
    prog.load("file_open", &btf)?;
    prog.attach()?;
    eprintln!("lsm-hello: attached to file_open; run `cat <file>` in another shell");

    match args.seconds {
        Some(s) => tokio::time::sleep(Duration::from_secs(s)).await,
        None => tokio::signal::ctrl_c().await?,
    }
    Ok(())
}
