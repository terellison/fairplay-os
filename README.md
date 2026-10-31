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
| `crates/fairplay-ebpf` | 3, 5-8 | LSM programs on `ptrace_access_check`, `mmap_file` and `file_mprotect` (executable-mapping allowlist), `task_kill`, `bpf`, `bpf_map` and `bpf_prog` (self-protection), `file_ioctl`, `file_ioctl_compat` and `file_permission` (virtual input), plus fork/exit tracing programs that make the domain follow the game; builds on the VM |
| `crates/fairplayd` | 3-9 | Loads the programs, owns the PROTECTED, EXEC_ALLOWED and INPUT_* maps, serves the socket API, streams violations, says who made each virtual input device; `--self-protect` fences root away from it; launches from signed manifests and sandboxes the anti-cheat (milestone 9) |
| `crates/cheatsim` | 3, 5-8 | Attacker: ptrace, process_vm_readv, /proc/pid/mem; `game --depth N` hides the secret in a descendant; `game --dlopen` loads libraries like a tricked game; `self-attack` goes after fairplayd itself; `clicker`, `uhid`, `inject` fake input |
| `crates/fairplay-attest` | 10 | TPM quote collection and the server-side verifier (pure Rust), including the boot mode from a provisional mode PCR; tested against swtpm |
| `vm/` | 1-10 | VM creation, provisioning, the milestone-1 check, the milestone-2, 4, 5, 6, 7, 8 and 9 (parts A and B) tests, and `attest` end to end against swtpm |

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
| `launch_protected` | root, or the `fairplay-launcher` group | Starts a program protected from its first instruction, as the launcher (never as root by default). Since milestone 9, only a program a signed game manifest names. `join` starts the manifest's anti-cheat inside an existing session, as a reader: that's how the vendor's anti-cheat gets in. |
| `session_status` | the session's launcher or user, its own processes, root | Protected or not, the game's state and exit code, members, violation count, kernel lockdown mode, virtual input devices present |
| `violations` | same | A stream: one event per denied attempt (process, its executable, the hook), pushed as it happens |
| `attest` | anyone | A TPM quote over the boot PCRs plus the IMA log, for the caller's nonce (versioned JSON, see `fairplay_api::attest`). `unavailable` without a TPM, as in the VM; echoes the nonce |
| `list_sessions` | anyone (sees their own) | For humans |

The exit test, inside the VM, as your normal user:

    ./vm/test-milestone4.sh

It builds everything, starts its own `fairplayd`, launches `cheatsim game`
through the socket as you (with the launcher group added via `setpriv`; your
account isn't changed), launches a mock anti-cheat written in Python into the
game's session as its anti-cheat reader, attacks the game as root (0/3
leak), and checks that the mock vendor's stream got exactly one event per
attempt. It also checks the authorization rules, that the manifest's
anti-cheat reader *can* read the game (and an unnamed program can't join), `attest`,
and that the game's PID leaves the kernel map when it exits. It cleans up
after itself.

By hand:

    sudo groupadd --system fairplay-launcher && sudo usermod -aG fairplay-launcher $USER
    # log out and back in for the group to apply, then:
    sudo ./target/release/fairplayd \
      --obj crates/fairplay-ebpf/target/bpfel-unknown-none/release/fairplay
    # another terminal: a signed manifest naming the game (milestone 9)
    ./target/release/fairplayctl manifest keygen --out /tmp/test.key
    ./target/release/fairplayctl manifest new --key /tmp/test.key --name Test \
      --launch "$PWD/target/release/cheatsim" --out /tmp/game.json
    ./target/release/fairplayctl launch --manifest /tmp/game.json -- ./target/release/cheatsim game
    ./target/release/fairplayctl violations 1      # streams; leave it running
    # a third terminal (pid and addr as printed by the game):
    sudo ./target/release/cheatsim attack --pid <pid> --addr <addr>
    ./target/release/fairplayctl status 1
    ./target/release/fairplayctl attest

### Attestation against a software TPM (milestone 10 groundwork)

The VM has no TPM, so `attest` answers `unavailable` there. To see the whole
path work, `vm/test-attest-swtpm.sh` starts `swtpm`, extends the mode PCR as a
player-mode (then developer-mode) boot would, points `fairplayd` at it with
`--tpm-tcti`, and checks the answer with `fairplayctl verify-evidence`, the
vendor server's side:

    flock -o /run/lock/fairplay-vm-tests ./vm/test-attest-swtpm.sh

The verifier accepts the quote and reads the mode, and refuses a replayed
nonce, a PCR value the quote doesn't cover, and an unknown evidence version.
If root extends the mode PCR after boot, the mode reads `unrecognized`, never
`player`. Not yet: AK enrollment (the test trusts the AK the evidence names),
and which PCR the real boot extends with the mode is still provisional.

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
- **Member cap** (issue #21): one game that forks without end must not fill
  `PROTECTED` for everyone. A domain may have at most `--member-cap`
  processes (default 1024) forked into it at once; the processes `fairplayd`
  launched don't count. Beyond that, a protected process's fork fails with
  `EAGAIN`, like `RLIMIT_NPROC`, in a `task_alloc` LSM hook. The check and
  the count are one atomic add, the place is given back at exit (or at
  `task_free` if the fork failed), so racing forks can't slip past it and
  the count can't drift (see `crates/fairplay-ebpf/src/members.rs`).
  `PROTECTED` holds 32 caps' worth (33,792 entries), and `fairplayd` runs at
  most `32768 / cap - 1` sessions at once, so the caps of running sessions
  always fit. `session_status` reports `member_cap`, `forked_members` and
  `forks_denied`; each refused fork is a `task_alloc` violation, at most 8
  a second per session, each one's `mode` saying how many refusals it
  stands for.
- **Map full**: if `PROTECTED` can't take a child anyway, the child
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
as `protection_degraded`. With a member cap of 64, `cheatsim forkbomb` (four
processes forking at once, for two seconds after the first refusal) forks
exactly 64 and then gets `EAGAIN` every time; `forks_denied` matches its own
count of refusals, the `task_alloc` lines stay under the rate limit, a
second game still launches and is protected, and once the bomb is killed
its domain, the member count and the `COUNTED`/`PENDING` maps are empty.

## Milestone 6: fairplayd protects itself

In player mode root may be the cheater, and the cheapest cheat is to switch
the protection off: kill `fairplayd`, edit `PROTECTED`, or detach its
programs. With `--self-protect`, `fairplayd` fences every other process,
root included, away from itself, with four more LSM programs
(`crates/fairplay-ebpf/src/hooks/`, shared logic in `self_protect.rs`):

| Hook | What it refuses from any other process | DENIED `mode=` |
| --- | --- | --- |
| `task_kill` | any signal to `fairplayd`, SIGKILL and SIGSTOP included (signal 0, "does it exist?", is allowed) | the signal |
| `ptrace_access_check` | ptrace, `/proc/<pid>/mem`, `process_vm_readv`/`writev`, `pidfd_getfd`, `/proc/<pid>/fd` | ptrace mode bits |
| `bpf_map` | a file descriptor for any of `fairplayd`'s maps (`bpftool map dump/update id N`, a pin) | requested `FMODE_*` |
| `bpf_prog` | a file descriptor for any of its programs | 0 |
| `bpf` | `BPF_PROG_LOAD` (every program type), `BPF_LINK_GET_FD_BY_ID`, `BPF_LINK_DETACH`, `BPF_PROG_DETACH` | the command |

It is keyed on `fairplayd`'s tgid in a one-entry map, `SELF_PROTECT`, which
is 0 (all four hooks inert) unless asked for. "Its maps and programs" are
every BPF object `fairplayd` holds an fd for when it turns protection on
(read from `/proc/self/fdinfo`), listed by kernel id in `SELF_OBJECTS`;
`SELF_PROTECT` and `SELF_OBJECTS` are on that list themselves. The ids are
logged at startup (`self-protection on for pid N: maps PROTECTED=12 ...`),
since `bpftool` can no longer show them.

Why **all** program loads: a tracing program reads the memory of whatever
process it runs in with `bpf_probe_read_user`, which no LSM hook sees, and
most other program types (socket filters, cgroup programs) get the same
helper when root loads them, some running in the game's context when it
sends or connects. A competing LSM program could also deny what
`fairplayd` needs. The cost: while self-protection is on, nothing else can
load BPF programs, including systemd's `IPAddressDeny=`, `DeviceAllow=`,
`RestrictFileSystems=` and socket-bind filters. Player mode will have to
start those before `fairplayd`, or have `fairplayd` load them.

Signals the kernel raises itself (SIGCHLD from a game exiting, SIGPIPE, a
terminal's Ctrl-C) don't go through `task_kill`, so they still arrive.
Kernel-internal ptrace checks (`PTRACE_MODE_NOAUDIT`: `ps` reading
`/proc/<pid>/stat`) are refused quietly for `fairplayd`, without a DENIED
line.

**Off unless asked for.** Developer mode, and this shared VM, keep normal
root. There is no socket call to turn it off. The ways out:

    sudo fairplayd --obj ... --self-protect            # until it exits: Ctrl-C at its terminal, or reboot
    sudo fairplayd --obj ... --self-protect-for 60     # tests: off after 60 s, then exits normally

**Not covered here**, and what covers it instead:

- Changing the running kernel: modules, `/dev/mem`, `/proc/kcore`, `kexec`,
  hibernating and editing the image. Kernel lockdown (integrity), player
  mode.
- Rebooting into another kernel or developer mode: attestation.
- Kernel-raised signals root can provoke: `cgroup.kill` or `cgroup.freeze`
  on `fairplayd`'s cgroup, the OOM killer (raise its `oom_score_adj`, then
  exhaust memory or lower `memory.max`), `RLIMIT_CPU` via `prlimit`
  (SIGXCPU, then SIGKILL), and its controlling terminal (SIGINT, SIGHUP).
  None of these pass through `task_kill`. Player mode should run it as a
  service with no terminal in its own cgroup, and later hooks can refuse
  writes to that cgroup's files and to `/proc/<pid>/oom_score_adj`, and
  `task_setrlimit` on it.
- Slowing it down rather than stopping it: `nice`, scheduler policy, CPU
  affinity, I/O priority (`task_setnice`, `task_setscheduler`,
  `task_setioprio` hooks could refuse those).
- Reading the swap device (pages of `fairplayd` or the game swapped out):
  encrypted swap, or zram only.
- File descriptors to its BPF objects taken before self-protection started,
  and BPF programs loaded before it and attached later: player mode starts
  `fairplayd` early in boot, before any login.
- CPU-wide `perf_event_open` sampling the user stack and registers of
  whatever runs (no ptrace check when no pid is named): a `perf_event_open`
  LSM hook, or `perf_event_paranoid` with lockdown.
- Its socket: root can delete `/run/fairplayd.sock` and serve a fake one.
  Clients should check the peer (`SO_PEERCRED`) or rely on attestation.
- Replacing `fairplayd` or its BPF object on disk for the next start: the
  signed read-only image and attestation.

The exit test, inside the VM, as your normal user:

    flock /run/lock/fairplay-vm-tests ./vm/test-milestone6.sh

First, without `--self-protect`, root's `kill -9` ends `fairplayd` (developer
mode is unchanged). Then it starts `fairplayd --self-protect-for 60` and, as
root, tries `kill -9`, `kill -STOP` and `kill -TERM`; `bpftool map dump` and
`map update` on `PROTECTED`, `map update` on `SELF_PROTECT` (switching it
off), `prog dump` of a `fairplayd` program and `link detach`; and
`cheatsim self-attack`: ptrace attach, `process_vm_readv`, opening
`/proc/<pid>/mem`, `pidfd_getfd`, loading a trivial socket filter, raw
`BPF_LINK_DETACH` and `BPF_PROG_DETACH`, and opening a program by id. Each
must fail with one `DENIED` line. A game launched meanwhile is still
protected, and its exit still reaches `fairplayd`. Finally `fairplayd` turns
self-protection off on its own, exits with status 0, and leaves no program
loaded.
## Milestone 7: virtual input, reported with who made it

Aimbots and triggerbots fake input through the kernel, so the kernel says
who did it. Three hooks record each way in, with the process (tgid), comm
and executable that did it:

- `file_ioctl` (and `file_ioctl_compat` for 32-bit callers, Linux 6.8+):
  `UI_DEV_CREATE` on `/dev/uinput`, which creates a virtual input device.
  The record carries the name the creator gave the device. Any other ioctl
  costs one comparison.
- `file_permission`: the first write on an open `/dev/uhid` (that write is
  `UHID_CREATE2`, which creates a virtual HID device), and the first write
  on an open `/dev/input/event*` node (injecting events into an existing
  device). Once per open file (and verdict), not per event. While blocking
  is on, it also checks writes on `/dev/uinput` fds, which are input
  through an existing uinput device. A read costs one bit test; any other
  write, reading the inode's device number.

Devices are recognized by device number (`i_rdev`: 10:223 uinput, 10:239
uhid, 13:64+ evdev), not by path. **Reported, not blocked, by default**:
Steam Input and accessibility tools rely on virtual devices.

- `fairplayd --input-allow <path>` (repeatable) allowlists a remapper or
  accessibility tool, by inode like `--overlay`. Its devices show as
  allowlisted and never reach vendors.
- During a session, anything else prints a `REPORTED caller=... exe=...
  target=0 hook=uinput_create|uhid_create|evdev_write ... file=<device>`
  line and goes to every running session's violation stream with
  `"outcome":"reported"` (other hooks' events say `"denied"`).
- `launch_protected` takes `block_virtual_input: true` (`fairplayctl launch
  --block-virtual-input`). **Blocking stops input from non-allowlisted
  virtual devices, including ones created before the match.** While that
  session runs, a process whose executable isn't allowlisted can't create a
  uinput or uhid device, can't send input through one (any write on a
  `/dev/uinput` or `/dev/uhid` fd), and can't write into `/dev/input/event*`:
  each gets `EPERM`, prints a `DENIED` line and is streamed with
  `"outcome":"denied"`, once per fd (`hook=uinput_write` for input through
  an existing uinput device). **This applies to the whole machine, not just
  the game**, for as long as such a session runs, because input devices are
  machine-wide. Allowlisted tools keep working throughout, including their
  devices made earlier. Anyone else's devices go silent until the blocking
  session ends, then work again; nothing is left behind.
- With no session running nothing is reported; fairplayd still keeps the
  records (the last 256) so it can name the creators of devices made
  before a session started, such as Steam's virtual pads.

`session_status.virtual_input_devices` lists each uinput and uhid device
(from `/sys/class/input`) with `device` (`input7`), `name`, `kind`,
`created_by` (pid, comm, exe, exe_path, created_at) and `allowlisted`. A
uinput device is matched to its creation record by name; a uhid device to
the live processes that created uhid devices (a uhid device lives as long
as its fd, and the kernel can't see the HID device's name when it's
created). If several live processes fit, the entry is `ambiguous`, names
the newest, and is allowlisted only if all of them are, so a cheat can't
hide behind a remapper's device name. The violation stream is always exact:
it comes straight from the kernel's record.

Known limits: the device name is read from uinput's private
`struct uinput_device` and `struct input_dev`, whose first members (the
`input_dev` pointer, then the name) have been the same since Linux 2.6 but
aren't in the BTF we generate. A refused uinput writer is reported once per
fd for the daemon's lifetime, so a second blocking session later doesn't
report the same fd again (it is still refused). Synthetic input through XTest (X11 /
XWayland) is not covered here; the design doc handles that with Wayland
only. uhid is a module (`modprobe uhid`; on Ubuntu it ships in
`linux-modules-extra`).

The exit test, inside the VM, as your normal user:

    flock /run/lock/fairplay-vm-tests ./vm/test-milestone7.sh

During a protected session it starts `cheatsim clicker` as root (listed in
`session_status` as made by `cheatsim`, not allowlisted, and a `reported`
event), an allowlisted copy of it (allowlisted, no event), an evdev write and
a uhid device (reported; skipped if `/dev/uhid` can't be loaded), then a
second session with `block_virtual_input`. During it a new clicker, an evdev
write and a new uhid device get `EPERM` and `denied` events; so do a clicker
made before the match (its clicks stop, are reported once, and resume when
the session ends) and a uhid fd written to before the match that tries to
create its device during it. An allowlisted clicker made before the match
keeps clicking, and the allowlisted tool can still create devices. It also
checks that nothing is reported with no session running.

## Milestone 8: executable-mapping allowlist

`LD_PRELOAD` and Wine's DLL variables are dropped at launch, but a game can
still be tricked into loading a dropped library (a plugin path, a config
file), and since milestone 5 anything a protected game starts is inside its
domain. So a protected process may only map a *file* as code (`mmap` or
`mprotect` with `PROT_EXEC`, which is how `ld.so`, `dlopen`, `execve` and
Wine all load code) if the file is:

- a **system file**: on the filesystem holding `/usr` and `/lib`, owned by
  root, not writable by group or others. No allowlist entry needed: the
  loader, libc, Mesa, GPU drivers' libraries;
- in the game's **install directory** when it was launched: `fairplayd`
  walks `install_dir` (a new optional `launch_protected` field, default the
  program's directory; `fairplayctl launch --install-dir`) and puts every ELF
  or PE file there that the system rule doesn't cover into `EXEC_ALLOWED`,
  keyed by (session domain, device, inode);
- an **approved overlay**: `fairplayd --overlay <path>` (repeatable), allowed
  for every domain;
- or **memfd / shared anonymous memory** (the kernel's internal shmem mount),
  treated like anonymous memory.

Anonymous executable memory (JITs: Wine, .NET, LuaJIT, shader compilers) is
never checked: writing code into it from outside goes through
`ptrace_access_check`. Files are matched by inode, not path, so a file
created, or replaced by rename, after launch is not allowed even at an
allowed path. The inode generation is checked too where the filesystem has
one (ext4, btrfs), so a reused inode number isn't mistaken for the original.

The hooks are `mmap_file` and `file_mprotect`
(`crates/fairplay-ebpf/src/hooks/`, shared logic in `exec_allow.rs`); both
return at once unless the current process is in `PROTECTED`. A denial is
`EPERM` to the caller, a `DENIED ... hook=mmap_file ... file=<name>` line,
and a violation event with a new `file` field, filed under the session. What
the caller sees:

- `dlopen`: fails with "failed to map segment from shared object";
- `mprotect`: fails with `EPERM`;
- `execve` of an unapproved binary: the kernel maps the new program after
  the point of no return, so the process is killed with `SIGSEGV` (execve
  never returns).

Limits: at most 8192 code files per launch, 200,000 directory entries
walked, 32 levels deep, and 32768 `EXEC_ALLOWED` entries in all. A launch
over any limit is refused (`limit_reached`), never half-allowed. The walk
doesn't follow symlinks or cross mount points, and refuses pseudo
filesystems (`/proc`, `/sys`, ...). Entries go when the session's last
launched process exits.

Known weaknesses: a file that was allowed can be **rewritten in place** if
the user can write to it (the install directory is usually the user's);
content hashes (IMA or fs-verity) would close that. Root can make a file
pass the system rule (`chown root`); in player mode root is fenced.

The exit test, inside the VM, as your normal user:

    flock /run/lock/fairplay-vm-tests ./vm/test-milestone8.sh

A protected `cheatsim game --dlopen-stdin` is asked to load libraries after
launch: one dropped in `/tmp` (blocked, with a `DENIED` line and a violation
event), one in its install directory (loads), one in its install directory
replaced after launch (blocked), and an approved overlay (loads). It also
mprotects a dropped file executable (blocked) and an allowed one (works),
forks children that exec `/usr/bin/true` (works) and a copy of it dropped in
`/tmp` (killed), and checks that the same dropped library loads in an
unprotected game, that JIT-style anonymous and memfd code still works in a
protected process, and that allowlist entries are removed when the game
exits.

## Milestone 9, part A: game manifest, protected members vs readers

**The bypass this closes.** Until now every process in a protection domain
could read every other, and the launcher picked what `launch_protected`
started. On a player's PC the launcher is the player, so
`launch_protected(python3 wrapper.py)`, where the wrapper starts the real
game as its child, could read the game. The executable-mapping allowlist
doesn't help: `python3` is a system file, and a script is data.

**Protected members vs readers** (kernel, `crates/fairplay-ebpf/src/readers.rs`):

- `PROTECTED` (tgid -> domain) is unchanged: the game and everything it
  starts, followed from fork to exit.
- A new `READERS` map (tgid -> domain). `ptrace_access_check` lets a caller
  at a protected process only if the caller *is* that process or
  `READERS[caller]` is its domain. Being a member of the same domain no
  longer counts: protected members can't read each other (parent, child or
  sibling).
- A process becomes a reader only by **exec'ing** a file in `READER_FILES`
  ((domain, dev, inode) -> generation, the same identity as milestone 8's
  `EXEC_ALLOWED`), checked in a `sched_process_exec` tracing program. The
  exec of any other file ends reader status, and it is never inherited on
  fork: a reader's child is a plain member. `READERS` entries go at exit,
  with the `PROTECTED` ones (before the PID can be reused). This is how
  Proton's `wineserver`, which wine starts, becomes a reader.
- Readers are in `PROTECTED` too. fairplayd's self-protection (milestone 6)
  is unchanged.

**The game manifest** (`crates/fairplay-api/src/manifest.rs`, v0): JSON plus
a detached signature, `<manifest>.sig` (base64 ed25519 over the file's exact
bytes).

    {
      "name": "Example Game",
      "signer": "<ed25519 public key, base64>",
      "launch":  [{"path": "bin/game", "sha256": "<hex>"}],
      "readers": [{"role": "anti_cheat", "path": "/opt/vendor/ac", "sha256": "<hex>"},
                  {"role": "runtime_helper", "path": "proton/files/bin/wineserver", "sha256": "<hex>"}],
      "proton":  [{"path": "proton/files/lib/wine/x86_64-unix/ntdll.so", "sha256": "<hex>"}],
      "overlays": [{"path": "/usr/lib/mangohud/libMangoHud.so", "sha256": "<hex>"}],
      "block_virtual_input": false
    }

Relative paths are relative to the manifest's directory. `fairplayd` checks
the signature against the manifest's **own** `signer` key and keeps no list
of trusted publishers: the OS stays neutral, records the manifest's hash and
the signer's fingerprint in the session, and the vendor's server checks the
signer (via attestation, milestone 10). A cheater can sign a manifest of
their own; `session_status` will show their key, not the vendor's.

**What `launch_protected` does now:**

1. `manifest` (an absolute path) is required for a new session. fairplayd
   verifies the signature, then requires `program` to be one of the
   manifest's `launch` entries (paths compared after resolving symlinks).
2. It opens the program, hashes it **through that open descriptor**, and the
   child execs **that descriptor** (`fexecve`), so the path can't be swapped
   between the check and the exec. Scripts are refused: their interpreter
   would read them again by path.
3. The manifest's `runtime_helper` readers are hashed the same way and go
   into `READER_FILES`; its `proton` and `overlays` files go on the
   session's executable-mapping allowlist. Entries that are missing or don't
   match are skipped and logged (a manifest may list several Proton builds).
4. All of this opens files with the **caller's** file permissions (a
   per-thread `setfsuid`), so a launcher can't make fairplayd read or hash a
   file it couldn't read itself.
5. `join` now means "start one of the session manifest's `anti_cheat`
   readers in this session". It is hashed and exec'd the same way, its file
   is added to `READER_FILES`, and its exec makes it a reader. Anything the
   manifest doesn't name gets `forbidden`. The old "the launcher may join
   anything" path is gone.
6. `session_status` reports `manifest`: its name, `sha256`, `signer`,
   `signer_fingerprint` (`ed25519:` + SHA-256 of the key) and
   `block_virtual_input`. A manifest asking for `block_virtual_input` turns
   on milestone 7's blocking for its session, as the request flag does.

Signature, tamper and hash failures are `forbidden`, with nothing launched.
`fairplayd --protect <pid> --allow <pid>` (milestone 3) still works;
`--allow` now makes a reader.

**Tools for vendors and tests** (no daemon needed):

    fairplayctl manifest keygen --out vendor.key       # prints the public key and fingerprint
    fairplayctl manifest new --key vendor.key --name "Game" --launch bin/game \
      --anti-cheat /opt/vendor/ac --runtime-helper proton/wineserver --out game.json
    fairplayctl manifest sign --key vendor.key game.json   # after editing by hand
    fairplayctl manifest verify game.json                  # signature and every file's hash
    fairplayctl launch --manifest game.json -- bin/game
    fairplayctl launch --join 1 -- /opt/vendor/ac

**Remaining window.** The hashed file is the file exec'd, but whoever can
write to it can still rewrite it **in place** between the hash and the
exec, or later: a runtime helper is exec'd by the game long after launch,
and is matched by inode. fs-verity (the kernel checks each page against a
hash fixed when the file was sealed) is the later fix, for this and for
milestone 8's allowlist.

The exit test, inside the VM, as your normal user:

    flock /run/lock/fairplay-vm-tests ./vm/test-milestone9.sh

As root on purpose (so every block is the LSM's): (a) a cheater-signed
manifest launches `python3 wrapper.py`, which starts `cheatsim game` as its
child and reads it itself and from a sibling: 0/3 leaked, 4 `DENIED` lines
(unprotected, the same wrapper leaks); (b) the game's child can't read its
parent or a sibling; (c) the vendor's signed mock anti-cheat, joined as
`anti_cheat`, reads the game 3/3; (d) a helper the game execs from the
manifest's `runtime_helper` file reads it 3/3, and the same binary at an
unnamed path doesn't; (e) an unnamed binary (or a runtime helper) can't
join; (f) a tampered manifest, one signed by another key, and an exe whose
hash changed are each refused, with no session created; (g)
`session_status` shows the signer's fingerprint and the manifest's hash.
The milestone 4, 5, 6 and 8 tests now launch from manifests too.

## Milestone 9, part B: the anti-cheat sees the game and nothing else

The design doc lets the vendor's anti-cheat see the game's memory, the
game's install directory, its own data and the `fairplayd` socket: not the
home directory, not other programs, not the browser. Two layers do that.

**Not Landlock.** A Landlock-sandboxed process may not ptrace (or
`process_vm_readv`, or open `/proc/<pid>/mem` of) any process outside its
own Landlock domain. The game isn't Landlocked, so a Landlocked anti-cheat
couldn't read it. Checked on this kernel (6.8, Landlock ABI 4): a root
process reads `/proc/<sleep>/mem` of a `sleep` it started, then calls
`landlock_restrict_self` with a ruleset that handles only `EXECUTE`, and
the same read fails with `EACCES`.

**1. Memory, in the kernel** (`crates/fairplay-ebpf/src/hooks/ptrace.rs`).
`ptrace_access_check` now also points outward: a protected process (the
anti-cheat, the game, anything either starts) may reach only processes of
its own domain. Reaching an unprotected process, even one of the same user
such as the browser, is denied and filed under the caller's session
(`Violation::domain` is the caller's). Checks the kernel makes on its own
account (`PTRACE_MODE_NOAUDIT`, e.g. which `/proc/<pid>/stat` fields `ps`
may show) are denied quietly. Covered: ptrace attach, `process_vm_readv` /
`writev`, `/proc/<pid>/mem`, `environ`, `maps`, `smaps`, `pagemap`,
`auxv`, `stack`, `syscall`, the `fd/`, `cwd`, `root` and `exe` links, and
`pidfd_getfd`.

**2. Files, with a mount namespace** (`crates/fairplayd/src/sandbox.rs`),
for `anti_cheat` joins only. Before the privilege drop and exec, the
paused child `unshare(CLONE_NEWNS)`s, makes every mount private, builds a
new root on a tmpfs at `/run/fairplay-sandbox` (visible only in its
namespace) and `pivot_root`s into it. Paths keep their host names, so the
game's files and `/proc/<game>/exe` mean the same inside and out. It holds:

| Path | How |
| --- | --- |
| `/usr`, `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`, `/libx32` | read-only bind, or the same symlink (merged `/usr`); skipped if missing |
| `/etc/ld.so.cache`, `ssl/`, `resolv.conf`, `hosts`, `nsswitch.conf`, `passwd`, `group`, `localtime` | read-only binds, if present |
| the game's install directory, the anti-cheat's own | read-only binds (`nodev`) |
| `$XDG_DATA_HOME/fairplay/<signer fingerprint>/` | read-write, `noexec`, `nodev`; created as the user it runs as, mode 0700 |
| the `fairplayd` socket | read-only bind (connecting needs no write access) |
| `/proc` | a fresh procfs |
| `/dev` | tmpfs with `null`, `zero`, `full`, `random`, `urandom`, `tty` bound in, `shm` (tmpfs), `fd`, `stdin`, `stdout`, `stderr` links |
| `/tmp` | a private tmpfs |

Everything gets `nosuid`, every bind keeps the host mount's own `ro`,
`nodev` and `noexec`, and the new root itself is remounted read-only.
`XDG_DATA_HOME` comes from the launch's environment if absolute, else
`~/.local/share`. The environment loses `DISPLAY`, `WAYLAND_DISPLAY`,
`XAUTHORITY`, `DBUS_SESSION_BUS_ADDRESS`, `XDG_RUNTIME_DIR` and
`SSH_AUTH_SOCK`, and gets `HOME` and `FAIRPLAY_DATA_DIR` set to the data
directory and `TMPDIR=/tmp`. It starts in the requested working directory
if the sandbox has it, else in the data directory. The network stays (the
vendor talks to its server); there is no home directory, no display socket
and no D-Bus.

The user's directories are opened with that user's permissions, then
cloned into detached mounts (`open_tree(OPEN_TREE_CLONE)`) that the child
attaches with `move_mount`: never re-resolved by path as root. The mount
list is built before `fork` (the child of a threaded daemon may only make
async-signal-safe calls), and the child still blocks on its pipe until
fairplayd has registered it. A user directory that would cover a sandbox
path (`/`, `/etc`, `/tmp`, ...) is refused. A step that fails is named in
the `launch_failed` error.

`session_status` shows it: each sandboxed member has
`"sandbox": {"data_dir": ..., "read_only": [game dir, anti-cheat dir]}`;
the game has none. The game is not sandboxed.

**Known gaps.** The sandbox assumes the
anti-cheat runs as the user: run as root (as the memory tests do, to get
past Yama) it could mount its way out. If fairplayd restarts, a running
anti-cheat keeps a bind of the old socket file.

The exit test, inside the VM, as your normal user:

    flock /run/lock/fairplay-vm-tests ./vm/test-milestone9b.sh

The script's comments and step names list each check. As root: (a) the
sandboxed mock vendor reads the game; (c) it reads an unprotected `cheatsim
game` (the "browser") 0/3; (f) a reader's fork-only child, and the reader
itself after it execs `/bin/sh`, read the game 0/3. As you: (b) the vendor
can't read a marker file in `$HOME`, and `ls $HOME` finds no such directory;
(d) it writes and reads back a file in its data directory, which appears in
the real per-vendor directory, owned by you; its `/tmp` is private; (e) it
gets its session's `session_status` through the socket; (g) the game itself
still reads `$HOME` and its install directory.

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
programs, so milestones 1, 3, 4, 5, 6 and 8 still need a run on the VM; see
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
