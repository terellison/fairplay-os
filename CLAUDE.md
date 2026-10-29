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
- Ask before committing or pushing; the user reviews changes first.
