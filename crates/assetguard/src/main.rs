//! assetguard: a p4 sync that can't half-break the workspace (milestone 2).
//!
//! The workspace must be a btrfs subvolume, and the snapshot directory must be
//! on the same btrfs filesystem. Run from inside the workspace (or with P4CLIENT
//! set) so p4 resolves the right client.
//!
//!     assetguard sync --workspace /work/ws --snapshots /work/.snapshots [-- //game/...]
//!     assetguard verify [//game/...]
//!     assetguard case-check /work/ws

mod casecheck;
mod verify;
mod ztag;

use std::{
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use verify::Outcome;

#[derive(Parser)]
#[command(about = "Safe Perforce sync for large asset trees")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Snapshot, sync, verify, case-check; roll back on failure.
    Sync {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        snapshots: PathBuf,
        /// Depot paths to sync (default: the whole client).
        #[arg(last = true)]
        paths: Vec<String>,
    },
    /// Compare files on disk with the depot digests of the have revisions.
    Verify {
        paths: Vec<String>,
        /// Re-fetch mismatched files with `p4 sync -f`.
        #[arg(long)]
        repair: bool,
    },
    /// List paths under a directory that differ only by case.
    CaseCheck { root: PathBuf },
}

fn main() -> ExitCode {
    let result = match Args::parse().cmd {
        Cmd::Sync {
            workspace,
            snapshots,
            paths,
        } => sync(&workspace, &snapshots, &paths),
        Cmd::Verify { paths, repair } => verify_cmd(&paths, repair).map(|bad| bad == 0),
        Cmd::CaseCheck { root } => case_check(&root),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("assetguard: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn sync(workspace: &Path, snapshots: &Path, paths: &[String]) -> Result<bool> {
    let snap = snapshot(workspace, snapshots)?;
    eprintln!("snapshot: {}", snap.display());

    let ok = (|| -> Result<bool> {
        p4(&with_paths(&["sync"], paths))?;
        let bad = verify_cmd(paths, true)?;
        if bad > 0 {
            eprintln!("{bad} file(s) still wrong after repair");
            return Ok(false);
        }
        case_check(workspace)
    })();

    match ok {
        Ok(true) => {
            eprintln!("sync ok; snapshot kept for rollback: {}", snap.display());
            // TODO(m2): notify the editor of changed paths (inotify/fanotify consumer).
            Ok(true)
        }
        Ok(false) | Err(_) => {
            if let Err(e) = &ok {
                eprintln!("sync failed: {e:#}");
            }
            rollback(workspace, &snap)?;
            eprintln!("rolled back to {}", snap.display());
            Ok(false)
        }
    }
}

/// Returns the number of files that are still wrong.
fn verify_cmd(paths: &[String], repair: bool) -> Result<usize> {
    let have: Vec<String> = if paths.is_empty() {
        vec!["//...#have".into()]
    } else {
        paths.iter().map(|p| format!("{p}#have")).collect()
    };
    let out = p4(&with_paths(&["fstat", "-Ol"], &have))?;
    let mut bad = Vec::new();
    let (mut ok, mut skipped) = (0usize, 0usize);
    for r in ztag::parse(&out).iter().filter_map(verify::check) {
        match &r.outcome {
            Outcome::Ok => ok += 1,
            Outcome::Skipped(_) => skipped += 1,
            Outcome::Missing | Outcome::Mismatch { .. } => {
                eprintln!(
                    "BAD {} ({}): {:?}",
                    r.depot_file,
                    r.client_file.display(),
                    r.outcome
                );
                bad.push(r.depot_file.clone());
            }
        }
    }
    eprintln!("verify: {ok} ok, {skipped} skipped, {} bad", bad.len());
    if repair && !bad.is_empty() {
        let specs: Vec<String> = bad.iter().map(|f| format!("{f}#have")).collect();
        p4(&with_paths(&["sync", "-f"], &specs))?;
        return verify_cmd(&bad, false);
    }
    Ok(bad.len())
}

fn case_check(root: &Path) -> Result<bool> {
    let files = casecheck::walk(root).with_context(|| format!("walking {}", root.display()))?;
    let groups = casecheck::collisions(&files);
    for g in &groups {
        let names: Vec<_> = g.iter().map(|p| p.display().to_string()).collect();
        eprintln!("CASE COLLISION: {}", names.join("  <->  "));
    }
    Ok(groups.is_empty())
}

fn snapshot(workspace: &Path, snapshots: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(snapshots)?;
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let dest = snapshots.join(format!("pre-sync-{ts}"));
    run(
        "btrfs",
        &["subvolume", "snapshot", "-r", &s(workspace), &s(&dest)],
    )?;
    Ok(dest)
}

/// Move the broken workspace aside and put a writable copy of the snapshot in
/// its place. Anything holding files open in the workspace keeps the old inodes;
/// close the editor before rolling back.
fn rollback(workspace: &Path, snap: &Path) -> Result<()> {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let failed = workspace.with_file_name(format!(
        "{}.failed-{ts}",
        workspace
            .file_name()
            .context("workspace has no name")?
            .to_string_lossy()
    ));
    std::fs::rename(workspace, &failed).context("moving failed workspace aside")?;
    run("btrfs", &["subvolume", "snapshot", &s(snap), &s(workspace)])?;
    eprintln!(
        "failed workspace kept at {} (delete with btrfs subvolume delete)",
        failed.display()
    );
    // The have list on the server still reflects the failed sync; re-align it.
    p4(&["flush", "//...#have"]).map(|_| ())
}

fn with_paths<'a>(base: &[&'a str], paths: &'a [String]) -> Vec<&'a str> {
    base.iter()
        .copied()
        .chain(paths.iter().map(String::as_str))
        .collect()
}

fn p4(args: &[&str]) -> Result<String> {
    let mut full = vec!["-ztag"];
    full.extend_from_slice(args);
    run("p4", &full)
}

fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("running {cmd}"))?;
    if !out.status.success() {
        bail!(
            "{cmd} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn s(p: &Path) -> String {
    p.display().to_string()
}
