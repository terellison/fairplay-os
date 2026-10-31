# fairplay-os

Prototype for the Gaming Workstation OS [design doc](docs/design.md): a crash-safe Perforce
workspace (Part A), OS-level fairness primitives that anti-cheat vendors build
on from user space (Part B), and resource lanes (Part C, later).

New here, or lost in acronyms? Start with [docs/GUIDE.md](docs/GUIDE.md): what
each piece does, how they fit, and a glossary.

## Layout

| Path | Milestone | State |
| --- | --- | --- |
| `crates/safewrite` | A | Done, tested: temp file, fsync, rename, fsync dir |
| `crates/assetguard` | 2 | Snapshot, sync, verify, case check, rollback (files + have list); tested against a local p4d |
| `crates/fairplay-common` | 3 | Types shared by the BPF program and user space |
| `crates/fairplay-api` | 4 | The socket protocol (JSON types), a client, and `fairplayctl` |
| `crates/lsm-hello-ebpf` | 1 | Smoke-test LSM program: logs every `file_open` by `cat` |
| `crates/lsm-hello` | 1 | Loads it and prints its log |
| `crates/fairplay-ebpf` | 3, 5 | LSM program on `ptrace_access_check`, plus fork/exit tracing programs that make the domain follow the game; builds on the VM |
| `crates/fairplayd` | 3-5 | Loads the programs, owns the PROTECTED map, serves the socket API, streams violations |
| `crates/cheatsim` | 3, 5 | Attacker: ptrace, process_vm_readv, /proc/pid/mem; `game --depth N` hides the secret in a descendant |
| `crates/fairplay-attest` | 10 | API shape only |
| `vm/` | 1-5 | VM creation, provisioning, the milestone-1 check, the milestone-2, 4 and 5 tests |

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

Since milestone 4, `fairplayd` also serves its socket API while it runs (on
`/run/fairplayd.sock`; `--socket` picks another path). `--protect` still
works as above, for a process that is already running.

## Milestone 4: the socket API

`fairplayd` serves the design doc's vendor-facing API over a Unix socket,
one JSON object per line:

| Call | Who may call it | What it does |
| --- | --- | --- |
| `launch_protected` | root, or the `fairplay-launcher` group | Starts a program protected from its first instruction, as the launcher (never as root by default). `join` starts it inside an existing session's protection domain: that's how the vendor's anti-cheat gets in. |
| `session_status` | the session's launcher or user, its own processes, root | Protected or not, the game's state and exit code, members, violation count, kernel lockdown mode, virtual input devices present |
| `violations` | same | A stream: one event per denied attempt (process, its executable, the hook), pushed as it happens |
| `attest` | anyone | `unavailable` until milestone 10 (no TPM in the VM); echoes the nonce |
| `list_sessions` | anyone (sees their own) | For humans |

The exit test, inside the VM, as your normal user:

    ./vm/test-milestone4.sh

It builds everything, starts its own `fairplayd`, launches `cheatsim game`
through the socket as you (with the launcher group added via `setpriv`; your
account isn't changed), launches a mock anti-cheat written in Python into the
game's domain, attacks the game as root (0/3 leak), and checks that the mock
vendor's stream got exactly one event per attempt. It also checks the
authorization rules, that a domain member *can* read the game, `attest`,
and that the game's PID leaves the kernel map when it exits. It cleans up
after itself.

By hand:

    sudo groupadd --system fairplay-launcher && sudo usermod -aG fairplay-launcher $USER
    # log out and back in for the group to apply, then:
    sudo ./target/release/fairplayd \
      --obj crates/fairplay-ebpf/target/bpfel-unknown-none/release/fairplay
    # another terminal:
    ./target/release/fairplayctl launch -- ./target/release/cheatsim game
    ./target/release/fairplayctl violations 1      # streams; leave it running
    # a third terminal (pid and addr as printed by the game):
    sudo ./target/release/cheatsim attack --pid <pid> --addr <addr>
    ./target/release/fairplayctl status 1
    ./target/release/fairplayctl attest

## Milestone 5: the domain follows the game

A Proton game is a chain of processes (proton, wine, `game.exe`, plus
`wineserver`), and `fairplayd` only launches the first. So the kernel keeps
the protection domain in step with the process tree, from
`crates/fairplay-ebpf/src/follow.rs`:

- **At fork** (`tp_btf/sched_process_fork`): a new process whose parent is in
  `PROTECTED` is added with the parent's domain. This runs in the parent's
  fork call, before the child is first scheduled, so the child never runs
  unprotected. A child is visible in `/proc` a moment before that; for that
  gap, `ptrace_access_check` treats a not-yet-registered child of a protected
  process as protected too. New threads add nothing (the process is already
  in).
- **At exit** (`tp_btf/sched_process_exit`): when the last thread of a
  protected process exits, its entry is removed. That happens before the
  process is reaped, so before its PID can be handed to anything else.
- **Map full**: if `PROTECTED` (1024 entries) can't take a child, the child
  runs unprotected, and the kernel counts it per domain in `UNFOLLOWED`.
  `session_status` then reports `protection_degraded: true` and
  `unprotected_children`. Its direct parent still shields it from reads (the
  rule above), but its own children aren't followed.

Denied attempts on any process in the domain are filed under the game's
session. The launch environment now also drops Wine's DLL variables,
`WINEDLLOVERRIDES` and `WINEDLLPATH`, next to `LD_*`.

The exit test, inside the VM, as your normal user:

    flock /run/lock/fairplay-vm-tests ./vm/test-milestone5.sh

It launches `cheatsim game --depth 2` (the game forks a child, which forks a
grandchild that holds the secret) with `WINEDLLOVERRIDES`, `WINEDLLPATH` and
`LD_PRELOAD` set. It checks that the child and grandchild are in `PROTECTED`
with the game's domain, that a root attack on the grandchild leaks 0/3 with 3
`DENIED` lines, that none of those variables reach the grandchild (read from
inside the domain), and that the grandchild's entry is gone while it is
still an unreaped zombie. As controls, the same game started without
`fairplayd` leaks 3/3, and with `PROTECTED` filled up a new child is reported
as `protection_degraded`.

## Known gaps on arm64 QEMU

- **Secure Boot.** Homebrew's arm64 UEFI firmware has no Secure Boot keys
  enrolled. Measured boot still works: firmware measures the bootloader and
  kernel into TPM PCRs, so attestation can prove *what* booted. The milestone 10
  test "reject a quote after disabling Secure Boot" needs x86 hardware or
  enrolled keys, so test "reject a quote after booting a different kernel"
  instead.
- **Part C measurements.** Frame times in a VM measure the VM. Lanes get
  measured on real Linux hardware with a GPU.

## Building here vs on the VM

CI (`.github/workflows/ci.yml`) runs on every PR: fmt, clippy, unit tests,
both eBPF builds, the full milestone 2 test, and shellcheck. It can't load BPF
programs, so milestones 1, 3, 4 and 5 still need a run on the VM; see
[docs/GUIDE.md](docs/GUIDE.md#what-ci-checks).

User-space crates build and test anywhere Linux runs: `cargo test --workspace`.
The eBPF crate needs nightly, `bpf-linker`, and `vmlinux.rs` generated from the
running kernel, so it builds on the VM.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
