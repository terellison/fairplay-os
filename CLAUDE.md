# fairplay-os

Prototype for a Linux-based gaming / game-dev workstation OS. Design doc:
https://claude.ai/artifact/F4Z7ANrbVehsBtfonY9GdG (ask the user to paste a section if you need it).

Three parts:
- **A. File layer**: crash-safe Perforce workspaces on btrfs (`safewrite`, `assetguard`).
- **B. Fairness primitives**: the OS protects game processes and attests to it; anti-cheat
  vendors stay in user space. No vendor kernel code. Fairness is best-effort, policy is server-side.
- **C. Resource lanes**: interactive vs background cgroups. Measure on real hardware, not this VM.

## Where this runs

This is an arm64 Ubuntu VM under QEMU + HVF on the user's Apple Silicon Mac mini.
You have root via sudo. The Mac side (`vm/macos/*.sh`) is not run from here.

Known VM limits:
- **TPM**: `tpm-tis-device` currently crashes QEMU under HVF (`HV_BAD_ARGUMENT`), so the VM
  boots with `TPM=off`. TPM checks in `vm/check-milestone1.sh` are expected to fail for now.
  Attestation (milestone 6) is blocked on this.
- **Secure Boot**: not available with Homebrew's arm64 firmware. Milestone 6 tests
  "reject a different kernel" instead of "reject Secure Boot off".

## Milestones (each ends with a test a skeptic can run)

1. VM baseline: BPF LSM active, BTF, btrfs `/work/ws` subvolume, nightly + bpf-linker + aya-tool.
   Exit: `vm/check-milestone1.sh` passes (minus TPM), and a hello-world LSM program loads.
2. assetguard v0 against a test Perforce depot (a local `p4d` is fine).
   Exit: truncate a file mid-sync; assetguard detects it and rolls back.
3. Protected process. Exit: `cheatsim attack` leaks 3/3 unprotected, 0/3 with `fairplayd`,
   and fairplayd prints one DENIED line per attempt. Run the attacker as root on purpose.
4. fairplayd socket API: launch_protected, session_status, attest, violations.
5. Block `/dev/uinput` opens during a protected session.
6. Attestation (blocked on TPM, see above).
7. Stretch: executable-mapping allowlist.

## Building

- User-space crates: `cargo test --workspace` from the repo root.
- eBPF crate is a separate workspace (nightly, `bpfel-unknown-none`):
  `cd crates/fairplay-ebpf && aya-tool generate task_struct > src/vmlinux.rs && cargo build --release`.
  `vmlinux.rs` is generated per kernel and gitignored.

## Working rules

- Keep the design doc's split: the kernel enforces, user space decides, the server sets policy.
- Prefer existing kernel mechanisms (BPF LSM, cgroups v2, IMA) over new kernel code.
- Never commit to or push `master`. All work goes through a PR; the owner's approval on the
  PR is the review.

## Working as an agent (GitHub)

Several agents may work on this repo at once. Each acts on GitHub as the
`fairplay-os-agents` GitHub App, never as the owner, so the owner's approval is a real
second identity. `master` is protected by two rulesets: all four CI checks must pass on a
branch that is up to date with `master`, and a PR needs the owner's approval given after
its last push.

1. **Check for overlap first:** `gh pr list` and read open PR titles. If another agent is
   already on the same files or milestone, pick something else or say so.
2. **Get a token** (1 hour, this repo only; config in `~/.config/fairplay-agents/`):
   ```
   export GH_TOKEN="$(tools/gh-app-token.sh)"
   git remote set-url origin "https://x-access-token:$GH_TOKEN@github.com/terellison/fairplay-os.git"
   ```
   Commit as the App:
   ```
   export GIT_AUTHOR_NAME='fairplay-os-agents[bot]' GIT_COMMITTER_NAME='fairplay-os-agents[bot]'
   export GIT_AUTHOR_EMAIL='350097673+fairplay-os-agents[bot]@users.noreply.github.com'
   export GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
   ```
3. **One task, one branch:** `agent/<short-topic>` from the latest `origin/master`. Keep the
   PR small and about one thing; small PRs from parallel agents conflict less.
4. **Before pushing:** run what CI runs (`cargo fmt --check`, `cargo clippy -- -D warnings`,
   `cargo test --workspace`, shellcheck, and `vm/test-milestone2.sh` if assetguard or `vm/`
   changed). CI can't load BPF programs: if you touch `crates/*-ebpf` or `fairplayd`, run
   the milestone 1/3 tests on the VM and paste the output into the PR.
5. **Open the PR** with what changed, why, and how you tested it, and request the owner's
   review so the Approve option shows up for them (REST, because Ubuntu's gh 2.45 breaks on
   `gh pr edit`): `gh api -X POST repos/terellison/fairplay-os/pulls/<n>/requested_reviewers -f 'reviewers[]=terellison'`.
   Then arm auto-merge: `gh pr merge --auto --squash`. It merges once the owner approves
   and checks pass; never try to merge any other way.
6. **When `master` moves**, update your branch (merge or rebase `origin/master`) so checks
   rerun against what will actually land. Any push after the owner's approval resets it.
7. **The App can't edit `.github/workflows/`.** If CI needs changing, describe the change
   in the PR or an issue and the owner will make it.
