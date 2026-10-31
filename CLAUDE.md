# fairplay-os

Prototype for a Linux-based OS that replaces Windows on player PCs and game-dev workstations,
so competitive games don't need kernel-level anti-cheat. Design doc:
[docs/design.md](docs/design.md). Read the relevant part before designing anything; where this
file adapts it to the VM (TPM, Secure Boot), this file wins.

Three parts:
- **A. File layer**: crash-safe Perforce workspaces on btrfs (`safewrite`, `assetguard`).
- **B. Fairness primitives**: the OS protects game processes and attests to it; anti-cheat
  vendors stay in user space. No vendor kernel code. Fairness is best-effort, policy is server-side.
- **C. Resource lanes**: interactive vs background cgroups. Measure on real hardware, not this VM.

Two boot modes: **player** (default; signed read-only image, lockdown, root fenced away from
`fairplayd`) and **developer** (open). Attestation reports the mode; games can only ask the
user to switch, never switch themselves. On a player PC, treat root as possibly the cheater.

## Where this runs

This is an arm64 Ubuntu VM under QEMU + HVF on the user's Apple Silicon Mac mini.
You have root via sudo. The Mac side (`vm/macos/*.sh`) is not run from here.

Known VM limits:
- **TPM**: `tpm-tis-device` currently crashes QEMU under HVF (`HV_BAD_ARGUMENT`), so the VM
  boots with `TPM=off`. TPM checks in `vm/check-milestone1.sh` are expected to fail for now.
  Attestation (milestone 10) is blocked on this.
- **Secure Boot**: not available with Homebrew's arm64 firmware. Milestone 10 tests
  "reject a different kernel" instead of "reject Secure Boot off".

## Milestones (each ends with a test a skeptic can run)

10, 11 and 12 need an x86 PC with a TPM; this VM can't run Proton or NVIDIA drivers either.

1. VM baseline: BPF LSM active, BTF, btrfs `/work/ws` subvolume, nightly + bpf-linker + aya-tool.
   Exit: `vm/check-milestone1.sh` passes (minus TPM), and a hello-world LSM program loads.
2. assetguard v0 against a test Perforce depot (a local `p4d` is fine).
   Exit: truncate a file mid-sync; assetguard detects it and rolls back.
3. Protected process. Exit: `cheatsim attack` leaks 3/3 unprotected, 0/3 with `fairplayd`,
   and fairplayd prints one DENIED line per attempt. Run the attacker as root on purpose.
4. fairplayd socket API: launch_protected, session_status, attest, violations.
5. The protection domain follows the game's child processes; drop Wine's DLL env variables.
6. fairplayd protects itself from root: no kill, trace, map access or program detach.
7. Input: report virtual input devices and who created them (don't block: Steam Input and
   accessibility tools use uinput).
8. Executable-mapping allowlist (also covers overlays and Wine DLL injection).
9. Game manifest + readers: launch only what a signed manifest names; only readers it names
   (the anti-cheat, `wineserver`) may read protected members; the anti-cheat runs sandboxed.
10. Attestation, including the mode (blocked on TPM, see above).
11. Player-mode image: signed, read-only, lockdown, Wayland only, atomic rollback.
12. Proton end to end on x86 hardware.

## Building

- User-space crates: `cargo test --workspace` from the repo root.
- eBPF crate is a separate workspace (nightly, `bpfel-unknown-none`):
  `cd crates/fairplay-ebpf && aya-tool generate task_struct > src/vmlinux.rs && cargo build --release`.
  `vmlinux.rs` is generated per kernel and gitignored.

## Working rules

- Keep the design doc's split: the kernel enforces, user space decides, the server sets policy.
- Prefer existing kernel mechanisms (BPF LSM, cgroups v2, IMA) over new kernel code.
- Never commit to or push `master`. All work goes through a PR. The lead agent's approval is
  the review; the owner also approves anything touching `docs/design.md`, `CLAUDE.md`,
  `tools/` or `.github/` (see `.github/CODEOWNERS`).

## Working as an agent (GitHub)

Several agents work on this repo at once, in two roles, each a GitHub App so no agent ever
acts as the owner:

- **Workers** act as `fairplay-os-agents`. A worker takes one task from the lead, works on
  its own branch and worktree, and opens a PR. Workers never approve anything.
- **The lead** acts as `fairplay-os-lead`. The App has write access, because GitHub only
  counts approvals from accounts that can push, but the lead never pushes. It splits milestones into tasks, assigns them, reviews each PR against the
  design doc, runs the VM tests itself for PRs that touch BPF or `fairplayd`, approves, and
  drafts design changes for the owner. It approves only through
  `tools/lead-approve.sh <pr> <reviewed-head-sha> <review-file>`, which refuses PRs not
  opened by a worker, PRs labelled `lead-authored`, and PRs whose head moved after review.
  PRs the lead writes itself (opened with the worker App) get the `lead-authored` label and
  the owner's review; the lead never approves its own work. Its token, for comments and
  labels: `FAIRPLAY_AGENT_ENV=~/.config/fairplay-lead/app.env tools/gh-app-token.sh`.
- **The owner** approves design and workflow changes (code owners) and can stop everything
  by turning off auto-merge or uninstalling the lead App.

`master` is protected by two rulesets: all four CI checks must pass on a branch that is up
to date with `master`, and a PR needs one approval: the lead's, plus the owner's when it
touches a code-owned file. Whoever pushed last can't approve, and new commits on the
branch dismiss an earlier approval; merging `master` in does not. If the owner needs to
approve a PR, a worker should update its branch rather than the owner's Update branch
button, which would make the owner the last pusher.

Steps for a worker:

1. **Stick to your task.** Run `gh pr list` and read open PR titles. If another PR already
   touches the same files, tell the lead before you start rather than racing it.
2. **Get a token** (1 hour, this repo only; config in `~/.config/fairplay-agents/`):
   ```
   export GH_TOKEN="$(tools/gh-app-token.sh)"
   git push "https://x-access-token:$GH_TOKEN@github.com/terellison/fairplay-os.git" HEAD:refs/heads/agent/<topic>
   ```
   Push with the URL inline like this, not via `origin`: `origin` may be SSH (the owner's
   key), and `git remote set-url` writes the token into `.git/config`, which every worktree
   shares, so parallel agents overwrite each other and expired tokens stay on disk.
   Commit as the App:
   ```
   export GIT_AUTHOR_NAME='fairplay-os-agents[bot]' GIT_COMMITTER_NAME='fairplay-os-agents[bot]'
   export GIT_AUTHOR_EMAIL='350097673+fairplay-os-agents[bot]@users.noreply.github.com'
   export GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
   ```
3. **One task, one branch:** `agent/<short-topic>` from the latest `origin/master`, in your
   own `git worktree`. Keep the PR small and about one thing; small PRs conflict less.
4. **Before pushing:** run what CI runs (`cargo fmt --check`, `cargo clippy -- -D warnings`,
   `cargo test --workspace`, shellcheck, and `vm/test-milestone2.sh` if assetguard or `vm/`
   changed). CI can't load BPF programs: if you touch `crates/*-ebpf` or `fairplayd`, run
   the milestone 1/3/4 tests on the VM and paste the output into the PR. The VM is shared,
   so run anything that loads BPF programs under the lock, one agent at a time:
   `flock /run/lock/fairplay-vm-tests ./vm/test-milestone4.sh`.
5. **Open the PR** with what changed, why, and how you tested it, then arm auto-merge:
   `gh pr merge --auto --squash`. It merges once the PR is approved and checks pass; never
   try to merge any other way. The lead finds new PRs on its own, and GitHub asks the owner
   automatically when the PR touches a code-owned file.
6. **When `master` moves**, update your branch (merge or rebase `origin/master`) so checks
   rerun against what will actually land. A merge of `master` keeps approvals; any other
   new commit dismisses them, and the PR has to be approved again.
7. **The App can't edit `.github/workflows/`.** If CI needs changing, describe the change
   in the PR or an issue and the owner will make it.
