# fairplay-os

Prototype for the Gaming Workstation OS design doc: a crash-safe Perforce
workspace (Part A), OS-level fairness primitives that anti-cheat vendors build
on from user space (Part B), and resource lanes (Part C, later).

New here, or lost in acronyms? Start with [docs/GUIDE.md](docs/GUIDE.md): what
each piece does, how they fit, and a glossary.

## Layout

| Path | Milestone | State |
| --- | --- | --- |
| `crates/safewrite` | A | Done, tested: temp file, fsync, rename, fsync dir |
| `crates/assetguard` | 2 | Snapshot, sync, verify, case check, rollback (files + have list); tested against a local p4d |
| `crates/fairplay-common` | 3 | Shared map types |
| `crates/lsm-hello-ebpf` | 1 | Smoke-test LSM program: logs every `file_open` by `cat` |
| `crates/lsm-hello` | 1 | Loads it and prints its log |
| `crates/fairplay-ebpf` | 3 | LSM program on `ptrace_access_check`; builds on the VM |
| `crates/fairplayd` | 3-4 | Loads the program, registers PIDs, prints violations |
| `crates/cheatsim` | 3 | Attacker: ptrace, process_vm_readv, /proc/pid/mem |
| `crates/fairplay-attest` | 6 | API shape only |
| `vm/` | 1-2 | VM creation, provisioning, the milestone-1 check, the milestone-2 test |

## Milestone 1: the VM (Apple Silicon Mac)

The VM is arm64 Ubuntu under QEMU with Apple's Hypervisor framework, which runs
at near-native speed. `swtpm` provides a TPM 2.0, and a second disk holds the
btrfs workspace.

On the Mac:

    ./vm/macos/create-vm.sh     # once: installs qemu + swtpm, builds disks
    ./vm/macos/run-vm.sh        # boots headless; Ctrl-A X quits

In another terminal:

    ssh -p 2222 $USER@localhost
    git clone <this repo> && cd fairplay-os
    ./vm/provision-guest.sh && sudo reboot
    # after reboot:
    ./vm/check-milestone1.sh

Then prove an LSM program loads and runs:

    cd crates/lsm-hello-ebpf
    aya-tool generate file > src/vmlinux.rs
    cargo build --release
    cd ../..
    cargo build --release -p lsm-hello
    sudo ./target/release/lsm-hello \
      --obj crates/lsm-hello-ebpf/target/bpfel-unknown-none/release/lsm-hello
    # another terminal: each file cat opens shows up as a log line
    cat /etc/hostname

## Milestone 2: assetguard

Inside the VM (needs `p4` and `p4d`, which `provision-guest.sh` installs):

    ./vm/test-milestone2.sh

It starts a throwaway Perforce server on 127.0.0.1:16661, breaks syncs four
ways (p4 killed mid-file, persistent and one-off truncation, a case
collision), and checks with `p4 have` and `p4 reconcile -n` that each one
either rolled back cleanly or was repaired. It cleans up after itself and
doesn't touch `/work/ws`. See [docs/GUIDE.md](docs/GUIDE.md#part-a-the-file-layer)
for what it's proving.

## Milestone 3: protected process

Inside the VM:

    cd crates/fairplay-ebpf
    aya-tool generate task_struct > src/vmlinux.rs
    cargo build --release
    cd ../..
    cargo build --release

    # Terminal 1: the stand-in game
    ./target/release/cheatsim game
    # Terminal 2: attack it unprotected (expect 3/3 leaked)
    sudo ./target/release/cheatsim attack --pid <pid> --addr <addr>
    # Terminal 2: protect it
    sudo ./target/release/fairplayd \
      --obj crates/fairplay-ebpf/target/bpfel-unknown-none/release/fairplay --protect <pid>
    # Terminal 3: attack again (expect 0/3 leaked, 3 DENIED lines in terminal 2)
    sudo ./target/release/cheatsim attack --pid <pid> --addr <addr>

The attacker runs as root on purpose. Normal kernel rules let root read any
process, so a block proves the LSM program did it.

## Known gaps on arm64 QEMU

- **Secure Boot.** Homebrew's arm64 UEFI firmware has no Secure Boot keys
  enrolled. Measured boot still works: firmware measures the bootloader and
  kernel into TPM PCRs, so attestation can prove *what* booted. The milestone 6
  test "reject a quote after disabling Secure Boot" needs x86 hardware or
  enrolled keys, so test "reject a quote after booting a different kernel"
  instead.
- **Part C measurements.** Frame times in a VM measure the VM. Lanes get
  measured on real Linux hardware with a GPU.

## Building here vs on the VM

User-space crates build and test anywhere Linux runs: `cargo test --workspace`.
The eBPF crate needs nightly, `bpf-linker`, and `vmlinux.rs` generated from the
running kernel, so it builds on the VM.
