//! assetguard: a p4 sync that can't half-break the workspace (milestone 2).
//!
//! The workspace must be a btrfs subvolume, and the snapshot directory must be
//! on the same btrfs filesystem. Run from inside the workspace (or with P4CLIENT
//! set) so p4 resolves the right client.
//!
//!     assetguard sync --workspace /work/ws --snapshots /work/.snapshots [-- //game/...]
//!     assetguard verify [//game/...]
//!     assetguard case-check /work/ws
//!
//! `ASSETGUARD_P4` overrides the p4 binary (the milestone 2 test uses it to
//! inject faults into a real sync).

mod casecheck;
mod have;
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
    // Record the server's have list before touching anything: restoring files
    // without restoring it would leave the server believing we have the new
    // revisions, and the next sync would skip them.
    let before = have::read(&p4(&with_paths(&["have"], paths))?);
    let snap = snapshot(workspace, snapshots)?;
    let have_file = snap.with_extension("have");
    safewrite::write(&have_file, have::serialize(&before))
        .with_context(|| format!("saving have list to {}", have_file.display()))?;
    eprintln!("snapshot: {} ({} files)", snap.display(), before.len());

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
            rollback(workspace, &snap, &before, paths)?;
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
    let dest = fresh_name(snapshots, "pre-sync")?;
    run(
        "btrfs",
        &["subvolume", "snapshot", "-r", &s(workspace), &s(&dest)],
    )?;
    Ok(dest)
}

/// Move the broken workspace aside, put a writable copy of the snapshot in its
/// place, and reset the server's have list to what it was before the sync.
/// Anything holding files open in the workspace (including a shell whose cwd
/// is inside it) keeps the old inodes; close the editor before rolling back.
fn rollback(
    workspace: &Path,
    snap: &Path,
    before: &have::HaveList,
    paths: &[String],
) -> Result<()> {
    let name = workspace.file_name().context("workspace has no name")?;
    let failed = fresh_name(
        workspace.parent().context("workspace has no parent")?,
        &format!("{}.failed", name.to_string_lossy()),
    )?;
    std::fs::rename(workspace, &failed).context("moving failed workspace aside")?;
    run("btrfs", &["subvolume", "snapshot", &s(snap), &s(workspace)])?;
    eprintln!(
        "failed workspace kept at {} (delete with btrfs subvolume delete)",
        failed.display()
    );
    // The have list on the server still reflects the failed sync; re-align it.
    let now = have::read(&p4(&with_paths(&["have"], paths))?);
    let specs = have::restore_specs(before, &now);
    if specs.is_empty() {
        return Ok(());
    }
    let list = snap.with_extension("flush");
    safewrite::write(&list, specs.join("\n") + "\n")?;
    p4(&["-x", &s(&list), "flush"])?;
    eprintln!("have list restored ({} entries reset)", specs.len());
    Ok(())
}

/// `dir/prefix-<unix time>`, with `-2`, `-3`... appended if that exists
/// (a retry right after a failure lands in the same second).
fn fresh_name(dir: &Path, prefix: &str) -> Result<PathBuf> {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let base = dir.join(format!("{prefix}-{ts}"));
    let mut path = base.clone();
    let mut n = 1;
    // Check the .have sidecar too: it shares the snapshot's name.
    while path.exists() || path.with_extension("have").exists() {
        n += 1;
        path = PathBuf::from(format!("{}-{n}", base.display()));
    }
    Ok(path)
}

fn with_paths<'a>(base: &[&'a str], paths: &'a [String]) -> Vec<&'a str> {
    base.iter()
        .copied()
        .chain(paths.iter().map(String::as_str))
        .collect()
}

fn p4(args: &[&str]) -> Result<String> {
    let bin = std::env::var("ASSETGUARD_P4").unwrap_or_else(|_| "p4".into());
    let mut full = vec!["-ztag"];
    full.extend_from_slice(args);
    run(&bin, &full)
}

fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("running {cmd}"))?;
    if !out.status.success() {
        bail!(
            "{cmd} {} failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn s(p: &Path) -> String {
    p.display().to_string()
}
