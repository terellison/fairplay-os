#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2024
# (SC2016: $names in single quotes are jq variables. SC2024: output from
# sudo commands is meant to land in files we own.)
# Milestone 9 exit test, part B: the vendor's anti-cheat sees the game and
# nothing else. A signed mock vendor, joined to a game's session, can read
# the game's memory, its install directory, its own data directory and the
# fairplayd socket, and nothing else: not the user's home directory, not
# another program's memory, not the game's files or open files through
# /proc, not abstract Unix sockets (X11). It reads the game but can't write
# to it or signal it, it can't make namespaces or mounts or use keyrings or
# bpf (seccomp), and its /proc lists only its own processes and the
# game. Run inside the VM, as your normal user (not root), from the repo
# root, under the shared VM lock:
#   flock /run/lock/fairplay-vm-tests ./vm/test-milestone9b.sh
#
# Needs sudo, BPF LSM (vm/check-milestone1.sh), bpftool, jq and python3. Builds what
# it uses, starts its own fairplayd on $M9B_SOCKET, and on exit stops it,
# kills what it started and deletes everything it made, including the
# marker file in your home directory.
#
# Cast (all files under one temp dir, except the marker):
#   game/      the install directory: cheatsim (the game) and game.json.
#   vendor/    anticheat (a copy of cheatsim the manifest names as its
#              anti_cheat reader: the mock vendor), plus things for it to
#              run: tool (the same bytes, not named), fairplayctl, and
#              sh-attack.sh.
#   session 1  game and anti-cheat as root, on purpose (as in milestone 3):
#              kernel ptrace rules and Yama let root through, so every
#              memory block below is the LSM's, and prints a DENIED line.
#   session 2  game (started in your home directory, holding the marker
#              open) and anti-cheat as you: the file-system, /proc-link,
#              socket and hidepid tests, with the anti-cheat's data
#              directory created as you.
#   browser    `cheatsim game`, unprotected, as root: an ordinary program of
#              the same user (root, like session 1's anti-cheat).
# The mock vendor is `anticheat game --dlopen-stdin`, which takes commands
# on a pipe (attack, forkattack, become, poke, signal, hold, connect, dgram,
# read, ls, write, exec, syscalls: see cheatsim's --help).
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOCK="${M9B_SOCKET:-/run/fairplayd-m9btest.sock}"
OBJ="$REPO/crates/fairplay-ebpf/target/bpfel-unknown-none/release/fairplay"
NEW_ROOT=/run/fairplay-sandbox

[ "$(id -u)" -ne 0 ] || { echo "run as your normal user (it uses sudo where needed)" >&2; exit 2; }
for t in jq python3; do
  command -v "$t" >/dev/null || { echo "$t not found" >&2; exit 2; }
done
command -v bpftool >/dev/null || [ -x /usr/sbin/bpftool ] || { echo "bpftool not found" >&2; exit 2; }
ME_UID="$(id -u)"

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
jqt()       { jq -e "$@" >/dev/null; }
check()     { local label="$1"; shift; if "$@"; then ok "$label"; else bad "$label"; fi; }
check_not() { local label="$1"; shift; if "$@"; then bad "$label"; else ok "$label"; fi; }
step() { echo; echo "== $1"; }
indent() { sed 's/^/      /'; }

T="$(mktemp -d /tmp/fairplay-m9b.XXXXXX)"
chmod 755 "$T"
MARKER="$HOME/.fairplay-m9b-marker.$$"
DAEMON_PID=""; KILL_PIDS=()
# Everything this run starts names a file under $T on its command line (the
# games, the anti-cheats and what they exec, the browser, the listener,
# fairplayd), as root or as you, so a pattern on that path finds whatever
# the pid list missed. The dots are escaped, so the pattern doesn't match
# the command line of the sudo that runs pkill.
ours() { printf '%s/' "$1" | sed 's/[.]/\\./g'; }
kill_ours() { sudo pkill -KILL -f "$(ours "$1")" 2>/dev/null; }
cleanup() {
  trap - EXIT INT TERM HUP
  exec 3>&- 4>&- 5>&- 6>&-
  # By pid first: every game and anti-cheat start() launched, the browser,
  # the listener. SIGKILL: none of them gets to linger.
  for p in "${KILL_PIDS[@]}"; do sudo kill -KILL "$p" 2>/dev/null; done
  if [ -S "$SOCK" ]; then
    sudo "$T/bin/fairplayctl" --socket "$SOCK" list 2>/dev/null |
      jq -r '.ok.sessions[]? | (.game, .members[]) | select(.state=="running") | .pid' 2>/dev/null |
      while read -r p; do sudo kill -KILL "$p" 2>/dev/null; done
  fi
  kill_ours "$T"
  if [ -n "$DAEMON_PID" ]; then
    sudo kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
  fi
  kill_ours "$T"
  local left
  left="$(pgrep -af "$(ours "$T")")"
  [ -z "$left" ] || { echo "cleanup: still running:"; echo "$left" | indent; }
  sudo rm -f "$SOCK"
  rm -f "$MARKER"
  sudo rm -rf "$T"
}
trap cleanup EXIT
# Interrupted (Ctrl-C, kill): exit, which runs cleanup.
trap 'exit 130' INT TERM HUP

# A run killed outright (SIGKILL) can't clean up: do it for any earlier run
# now. Safe under the VM lock, which keeps runs from overlapping.
for old in /tmp/fairplay-m9b.*; do
  if [ ! -d "$old" ] || [ "$old" = "$T" ]; then continue; fi
  echo "removing what an earlier run left: $old"
  kill_ours "$old"
  sudo rm -rf "$old"
done
sudo pkill -KILL -f '/tmp/fairplay-m9b\.[A-Za-z0-9]{6}/' 2>/dev/null
rm -f "$HOME"/.fairplay-m9b-marker.*

wait_for()   { for _ in $(seq 100); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
wait_until() { for _ in $(seq 100); do "$@" && return 0; sleep 0.1; done; return 1; }
denied() { grep -c "^DENIED .*target=$1 hook=ptrace_access_check" "$T/daemon.out"; }
denied_at_least() { [ "$(denied "$1")" -ge "$2" ]; }
ctl() { sudo "$CTL" --socket "$SOCK" "$@"; }

# ask FD OUT COMMAND [PATTERN]: send a command to a cheatsim reading fd FD,
# wait for PATTERN (default: an EXEC- line) in what it adds to OUT, and print
# (and save to $T/last) what it added.
ask() {
  local fd="$1" out="$2" cmd="$3" pat="${4:-^(EXEC-|SPAWNED)}" before
  before="$(wc -l <"$out")"
  echo "$cmd" >&"$fd"
  for _ in $(seq 100); do
    tail -n +"$((before + 1))" "$out" | grep -qE "$pat" && break
    sleep 0.1
  done
  tail -n +"$((before + 1))" "$out" | tee "$T/last" | indent
}

# start NAME FD JSONVAR -- launch args...: launch a cheatsim game (as root,
# through fairplayctl) reading commands from a fresh pipe on FD; wait for
# its pid line. Sets <NAME>_PID, <NAME>_ADDR, <NAME>_SESSION.
start() {
  local name="$1" fd="$2"; shift 3
  mkfifo "$T/$name.cmd"
  eval "exec $fd<>\"\$T/\$name.cmd\""
  "$@" <"$T/$name.cmd" >"$T/$name.out" 2>&1
  local pid
  # Its pid is in the launch reply before the program prints anything.
  wait_for "$T/$name.out" '^{' || true
  local launched
  launched="$(grep '^{' "$T/$name.out" | jq -r '.ok.launched.pid // empty' 2>/dev/null)"
  [ -n "$launched" ] && KILL_PIDS+=("$launched")
  wait_for "$T/$name.out" '^pid=' || { bad "$name started"; indent <"$T/$name.out"; indent <"$T/daemon.err"; exit 1; }
  pid="$(grep '^{' "$T/$name.out" | jq -r '.ok.launched.pid')"
  KILL_PIDS+=("$pid")
  printf -v "${name}_PID" %s "$pid"
  printf -v "${name}_SESSION" %s "$(grep '^{' "$T/$name.out" | jq -r '.ok.launched.session')"
  printf -v "${name}_ADDR" %s "$(sed -n "s/^pid=$pid addr=//p" "$T/$name.out")"
}

step "build"
if [ -z "${M9B_SKIP_BUILD:-}" ]; then
  (cd "$REPO/crates/fairplay-ebpf" &&
    { [ -s src/vmlinux.rs ] || aya-tool generate task_struct > src/vmlinux.rs; } &&
    cargo build --release -q) || exit 2
  (cd "$REPO" && cargo build --release -q -p fairplayd -p fairplay-api -p cheatsim) || exit 2
fi
mkdir -p "$T/bin" "$T/game" "$T/vendor" "$T/xdg-root" "$T/xdg-me"
cp "$REPO"/target/release/{fairplayd,fairplayctl,cheatsim} "$T/bin/"
for f in game/cheatsim vendor/anticheat vendor/tool; do
  cp "$REPO/target/release/cheatsim" "$T/$f"
done
cp "$REPO/target/release/fairplayctl" "$T/vendor/fairplayctl"
CTL="$T/bin/fairplayctl"; CHEATSIM="$T/bin/cheatsim"; GAME="$T/game/cheatsim"; AC="$T/vendor/anticheat"
echo "secret-of-the-player" >"$MARKER"
echo "the game's own data" >"$T/game/level1.dat"

step "the vendor's key and manifest"
"$CTL" manifest keygen --out "$T/vendor.key" >"$T/vendor.pub" || exit 2
VENDOR_FP="$(jq -r .fingerprint "$T/vendor.pub")"
VENDOR_DIR="$(printf %s "$VENDOR_FP" | tr -c 'a-zA-Z0-9' '-')"
(cd "$T/game" && "$CTL" manifest new --key "$T/vendor.key" --name "M9B Test Game" \
  --launch cheatsim --anti-cheat "$AC" --out "$T/game/game.json") | indent

step "start fairplayd on $SOCK"
# A daemon killed outright leaves its socket file: wait for this one's.
sudo rm -f "$SOCK"
sudo "$T/bin/fairplayd" --obj "$OBJ" --socket "$SOCK" >"$T/daemon.out" 2>"$T/daemon.err" &
DAEMON_PID=$!
for _ in $(seq 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "fairplayd did not start:"; indent <"$T/daemon.err"; exit 2; }

step "session 1 (root): the game, and the vendor's anti-cheat joined to it"
start G1 3 -- sudo "$CTL" --socket "$SOCK" launch --run-as 0 --manifest "$T/game/game.json" -- "$GAME" game --dlopen-stdin
start AC1 4 -- sudo env XDG_DATA_HOME="$T/xdg-root" "$CTL" --socket "$SOCK" launch --run-as 0 \
  --join "$G1_SESSION" -- "$AC" game --dlopen-stdin
echo "      game pid=$G1_PID addr=$G1_ADDR session=$G1_SESSION; anti-cheat pid=$AC1_PID"
grep "pid $AC1_PID " "$T/daemon.err" | indent
check "fairplayd logged the anti-cheat as joined and sandboxed" \
  grep -q "pid $AC1_PID .*joined as a reader, sandboxed (data $T/xdg-root/fairplay/$VENDOR_DIR, read-only $T/game $T/vendor)" "$T/daemon.err"
ctl status "$G1_SESSION" >"$T/status1.json"
jq -c --argjson p "$AC1_PID" '.ok.status.session.members[] | select(.pid==$p)' "$T/status1.json" | indent
check "session_status: the anti-cheat is sandboxed, with its data dir and what it sees read-only" \
  jqt --argjson p "$AC1_PID" --arg d "$T/xdg-root/fairplay/$VENDOR_DIR" --arg g "$T/game" --arg v "$T/vendor" \
    '.ok.status.session | (.members[] | select(.pid==$p) | .sandbox | .data_dir==$d and .read_only==[$g,$v]) and (.game.sandbox==null)' \
    "$T/status1.json"
# A u32 map key as bpftool -j prints it: little-endian hex bytes.
key_json() { printf '["0x%02x","0x%02x","0x%02x","0x%02x"]' $(($1 & 255)) $(($1 >> 8 & 255)) $(($1 >> 16 & 255)) $(($1 >> 24 & 255)); }
sudo bpftool -j map dump name SANDBOXED >"$T/sandboxed.json" 2>/dev/null
check "the kernel marks it SANDBOXED, the game not" \
  jqt --argjson a "$(key_json "$AC1_PID")" --argjson g "$(key_json "$G1_PID")" \
    'any(.[]; .key == $a) and (any(.[]; .key == $g) | not)' "$T/sandboxed.json"

step "(a) the sandboxed anti-cheat reads the game"
ask 4 "$T/AC1.out" "attack $G1_PID $G1_ADDR"
check "process_vm_readv and /proc/<game>/mem read the secret" \
  sh -c "grep -q '^LEAKED  process_vm_readv' '$T/last' && grep -q '^LEAKED  /proc/<pid>/mem' '$T/last'"
check "ptrace itself is off in the sandbox (seccomp: EPERM)" grep -q '^BLOCKED ptrace attach.*EPERM' "$T/last"
ask 4 "$T/AC1.out" "read /proc/$G1_PID/maps"
check "it reads the game's module list (/proc/<game>/maps)" grep -q "^EXEC-READ /proc/$G1_PID/maps: .*cheatsim" "$T/last"
check "no DENIED lines for the game" test "$(denied "$G1_PID")" -eq 0

step "(1) it can read the game but not write to it or signal it"
ask 4 "$T/AC1.out" "poke $G1_PID $G1_ADDR"
check "process_vm_writev: EPERM (seccomp)" grep -q '^EXEC-POKE process_vm_writev: EPERM' "$T/last"
check "writing /proc/<game>/mem: refused at open" grep -q "/proc/$G1_PID/mem: Operation not permitted" "$T/last"
wait_for "$T/daemon.out" "^DENIED caller=$AC1_PID .*hook=proc_mem_write"
grep "^DENIED caller=$AC1_PID .*hook=proc_mem_write" "$T/daemon.out" | indent
check "a DENIED line for the mem write (proc_mem_write)" \
  test "$(grep -c "^DENIED caller=$AC1_PID .*hook=proc_mem_write .*file=mem" "$T/daemon.out")" -eq 1
ask 4 "$T/AC1.out" "attack $G1_PID $G1_ADDR"
check "the game's secret is intact" grep -q '^LEAKED  process_vm_readv: read 0x5ec2e71337c0de11' "$T/last"
ask 4 "$T/AC1.out" "signal $G1_PID 18"
check "a signal (SIGCONT) to the game: refused" grep -q "^EXEC-ERR signal $G1_PID 18: Operation not permitted" "$T/last"
wait_for "$T/daemon.out" "^DENIED caller=$AC1_PID .*target=$G1_PID hook=task_kill"
check "with a DENIED line (task_kill)" grep -q "^DENIED caller=$AC1_PID .*target=$G1_PID hook=task_kill mode=0x12" "$T/daemon.out"

step "(5) seccomp: no namespaces, mounts, keyrings or bpf, even as root"
# cheatsim's `syscalls` makes each call with arguments that fail harmlessly
# if it runs (a missing path, a bad fd); EPERM means seccomp refused it.
SECCOMP_DENIED="setns unshare unshare_none mount umount2 open_tree move_mount fsopen fsconfig fsmount fspick
  mount_setattr pivot_root chroot keyctl add_key request_key bpf io_uring_setup io_uring_enter perf_event_open
  userfaultfd clone_newuser clone_newns clone_newnet clone_newpid"
all_eperm() {
  local n
  for n in $SECCOMP_DENIED; do grep -qE "^EXEC-SYSCALLS .*\b$n=EPERM\b" "$1" || { echo "      $n: not EPERM"; return 1; }; done
  grep -qE '^EXEC-SYSCALLS .*\bclone3=ENOSYS\b' "$1" || { echo "      clone3: not ENOSYS"; return 1; }
}
ask 3 "$T/G1.out" "syscalls"
check "control: the game (root, not sandboxed) gets as far as the kernel's own checks (no EPERM, no ENOSYS)" \
  sh -c "grep -q '^EXEC-SYSCALLS ' '$T/last' && ! grep -qE '=(EPERM|ENOSYS)\b' '$T/last'"
ask 4 "$T/AC1.out" "syscalls"
check "the anti-cheat (root, sandboxed): EPERM for each, clone3 ENOSYS" all_eperm "$T/last"
# (Plain fork and exec still work in the sandbox: forkattack in (f), and
# (e) execs fairplayctl, whose spawn falls back from clone3 to clone.)

step "(6) a root anti-cheat keeps no root powers but CAP_SYS_PTRACE (it read the game in (a))"
# Capability sets in /proc/<pid>/status are hex masks; CAP_SYS_PTRACE is bit 19.
PTRACE_ONLY=0000000000080000
caps_are() {  # caps_are FILE EFF/PRM BND
  grep -qE "^CapEff:\s+$2$" "$1" && grep -qE "^CapPrm:\s+$2$" "$1" && grep -qE "^CapBnd:\s+$3$" "$1" &&
    grep -qE '^CapInh:\s+0{16}$' "$1" && grep -qE '^CapAmb:\s+0{16}$' "$1"
}
ask 3 "$T/G1.out" "read /proc/self/status" >/dev/null
grep -E '^Cap' "$T/last" | sed 's/^/control (game): /' | indent
check_not "control: the game (root, not sandboxed) has the full set" caps_are "$T/last" "$PTRACE_ONLY" "$PTRACE_ONLY"
ask 4 "$T/AC1.out" "read /proc/self/status" >/dev/null
grep -E '^Cap' "$T/last" | indent
check "the anti-cheat: effective, permitted and bounding sets are CAP_SYS_PTRACE only, none inheritable or ambient" \
  caps_are "$T/last" "$PTRACE_ONLY" "$PTRACE_ONLY"
ask 3 "$T/G1.out" "byhandle /usr"
check "control: the game opens /usr by its file handle (open_by_handle_at)" grep -q '^EXEC-BYHANDLE /usr: opened' "$T/last"
ask 4 "$T/AC1.out" "byhandle /usr"
check "the anti-cheat can't (no CAP_DAC_READ_SEARCH)" grep -q '^EXEC-ERR byhandle /usr: Operation not permitted' "$T/last"
RATELIMIT="$(cat /proc/sys/kernel/printk_ratelimit)"
ask 4 "$T/AC1.out" "read /proc/sys/kernel/ostype"
check "it still reads /proc/sys" grep -q '^EXEC-READ /proc/sys/kernel/ostype: Linux' "$T/last"
# Writing back the value it already has: harmless if the guard failed.
ask 4 "$T/AC1.out" "write /proc/sys/kernel/printk_ratelimit $RATELIMIT"
check "but can't write a sysctl, though uid 0 owns it (read-only)" \
  grep -q '^EXEC-ERR write /proc/sys/kernel/printk_ratelimit: Read-only file system' "$T/last"
# Zero bytes: does nothing even if the open got through.
ask 4 "$T/AC1.out" "write /proc/sysrq-trigger"
check "nor open /proc/sysrq-trigger for writing (read-only)" \
  grep -q '^EXEC-ERR write /proc/sysrq-trigger: Read-only file system' "$T/last"

step "(c) it can't read an ordinary program of the same user (the browser)"
sudo "$CHEATSIM" game >"$T/browser.out" 2>&1 &
disown   # cleanup kills it; no "Killed" notice
wait_for "$T/browser.out" '^pid=' || bad "browser started"
B_PID="$(sed -n 's/^pid=\([0-9]*\) .*/\1/p' "$T/browser.out")"
B_ADDR="$(sed -n "s/^pid=$B_PID addr=//p" "$T/browser.out")"
KILL_PIDS+=("$B_PID")
echo "      browser pid=$B_PID addr=$B_ADDR (unprotected, root)"
sudo "$CHEATSIM" attack --pid "$B_PID" --addr "$B_ADDR" >"$T/control.out" 2>&1
check "control: root outside the sandbox reads the browser (3/3)" grep -q '^3/3 paths leaked' "$T/control.out"
v_before="$(ctl status "$G1_SESSION" | jq '.ok.status.session.violations')"
ask 4 "$T/AC1.out" "attack $B_PID $B_ADDR"
check "0/3 paths leaked" grep -q '^0/3 paths leaked' "$T/last"
check "its /proc doesn't even have the browser (hidepid)" \
  grep -q '^BLOCKED /proc/<pid>/mem: open: No such file' "$T/last"
wait_until denied_at_least "$B_PID" 1
grep "^DENIED .*target=$B_PID " "$T/daemon.out" | indent
check "1 DENIED line (process_vm_readv; ptrace stops at seccomp, /proc at hidepid)" \
  test "$(grep -c "^DENIED caller=$AC1_PID .*target=$B_PID hook=ptrace_access_check mode=0x12" "$T/daemon.out")" -eq 1
for f in environ maps cmdline; do
  ask 4 "$T/AC1.out" "read /proc/$B_PID/$f"
  check "/proc/<browser>/$f: not there" grep -q "^EXEC-ERR read /proc/$B_PID/$f: No such file" "$T/last"
done
ask 4 "$T/AC1.out" "signal $B_PID 18"
check "a signal to the browser: refused" grep -q "^EXEC-ERR signal $B_PID 18: Operation not permitted" "$T/last"
v_after="$(ctl status "$G1_SESSION" | jq '.ok.status.session.violations')"
check "the attempts are filed under the anti-cheat's session (violations $v_before -> $v_after)" \
  test "$v_after" -eq $((v_before + 2))

step "(f) part A's untested cases: a reader's fork-only child, and a reader that execs /bin/sh"
before_g="$(denied "$G1_PID")"
ask 4 "$T/AC1.out" "forkattack $G1_PID $G1_ADDR"
CHILD="$(sed -n 's/^forked child pid=\([0-9]*\)/\1/p' "$T/last")"
check "a fork-only child of the reader (pid $CHILD): 0/3 paths leaked" grep -q '^0/3 paths leaked' "$T/last"
wait_until denied_at_least "$G1_PID" $((before_g + 1))
check "1 DENIED line from the child (process_vm_readv)" \
  test "$(grep -c "^DENIED caller=$CHILD .*target=$G1_PID " "$T/daemon.out")" -eq 1
cat >"$T/vendor/sh-attack.sh" <<EOF
#!/bin/sh
echo "sh pid=\$\$"
exec $T/vendor/tool attack --pid $G1_PID --addr $G1_ADDR
EOF
chmod 755 "$T/vendor/sh-attack.sh"
before_g="$(denied "$G1_PID")"
ask 4 "$T/AC1.out" "become /bin/sh $T/vendor/sh-attack.sh" 'paths leaked'
check "the reader itself execs /bin/sh (same pid $AC1_PID)" grep -q "^sh pid=$AC1_PID\$" "$T/last"
check "and is no longer a reader: 0/3 paths leaked" grep -q '^0/3 paths leaked' "$T/last"
wait_until denied_at_least "$G1_PID" $((before_g + 1))
check "1 DENIED line from that pid (process_vm_readv)" \
  test "$(grep -c "^DENIED caller=$AC1_PID .*target=$G1_PID hook=ptrace_access_check" "$T/daemon.out")" -eq 1

step "session 2 (you): the game (started in your home directory) and its anti-cheat run as uid $ME_UID"
start G2 5 -- sudo env -C "$HOME" "$CTL" --socket "$SOCK" launch --run-as "$ME_UID" \
  --manifest "$T/game/game.json" -- "$GAME" game --dlopen-stdin
start AC2 6 -- sudo env XDG_DATA_HOME="$T/xdg-me" "$CTL" --socket "$SOCK" launch --run-as "$ME_UID" \
  --join "$G2_SESSION" -- "$AC" game --dlopen-stdin
DATA="$(ctl status "$G2_SESSION" | jq -r --argjson p "$AC2_PID" '.ok.status.session.members[] | select(.pid==$p) | .sandbox.data_dir')"
echo "      game pid=$G2_PID session=$G2_SESSION; anti-cheat pid=$AC2_PID data=$DATA"
check "its data directory is \$XDG_DATA_HOME/fairplay/<signer fingerprint>" \
  test "$DATA" = "$T/xdg-me/fairplay/$VENDOR_DIR"
check "created as you, mode 0700" test "$(stat -c '%u %a' "$DATA" 2>/dev/null)" = "$ME_UID 700"
ask 5 "$T/G2.out" "hold $MARKER" >/dev/null
HELD_FD="$(sed -n 's/^EXEC-HELD .* fd=\([0-9]*\)$/\1/p' "$T/last")"
echo "      the game holds $MARKER open as fd $HELD_FD; its cwd is \$HOME"

step "(b) it can't see your home directory"
ask 6 "$T/AC2.out" "read $MARKER"
check "reading a file in \$HOME: no such file" grep -q "^EXEC-ERR read $MARKER: No such file" "$T/last"
ask 6 "$T/AC2.out" "ls $HOME"
check "ls \$HOME shows nothing of it" grep -q "^EXEC-ERR ls $HOME: No such file" "$T/last"
ask 6 "$T/AC2.out" "ls /"
check "its / holds only the sandbox's skeleton (no home, root, var, mnt, media)" \
  sh -c "grep -q '^EXEC-LS /: ' '$T/last' && ! grep -qwE 'home|root|var|mnt|media|srv|opt' '$T/last'"
ask 6 "$T/AC2.out" "ls /run"
check "/run holds only the fairplayd socket (no user runtime dir, no D-Bus)" \
  grep -q "^EXEC-LS /run: \[$(basename "$SOCK")\]$" "$T/last"
ask 6 "$T/AC2.out" "ls /dev"
ask 6 "$T/AC2.out" "ls /etc"
ask 6 "$T/AC2.out" "read $T/game/level1.dat"
check "it can read the game's install directory" grep -q "^EXEC-READ $T/game/level1.dat: the game's own data" "$T/last"
ask 6 "$T/AC2.out" "write $T/game/level1.dat cheat"
check "but not write it (read-only)" grep -q "^EXEC-ERR write $T/game/level1.dat: Read-only file system" "$T/last"
check "and the file is unchanged" grep -q "^the game's own data$" "$T/game/level1.dat"

step "(2) not through the game's /proc links either"
links_before="$(grep -c "^DENIED caller=$AC2_PID .*hook=proc_link" "$T/daemon.out")"
ask 6 "$T/AC2.out" "ls /proc/$G2_PID/root/home"
check "/proc/<game>/root/home: refused" grep -q "^EXEC-ERR ls /proc/$G2_PID/root/home: Operation not permitted" "$T/last"
ask 6 "$T/AC2.out" "read /proc/$G2_PID/cwd/$(basename "$MARKER")"
check "/proc/<game>/cwd/<marker> (the game's cwd is \$HOME): refused" \
  grep -q "^EXEC-ERR read /proc/$G2_PID/cwd/.*: Operation not permitted" "$T/last"
ask 6 "$T/AC2.out" "read /proc/$G2_PID/fd/$HELD_FD"
check "/proc/<game>/fd/$HELD_FD (the marker, held open by the game): refused" \
  grep -q "^EXEC-ERR read /proc/$G2_PID/fd/$HELD_FD: Operation not permitted" "$T/last"
ask 6 "$T/AC2.out" "read /proc/$G2_PID/task/$G2_PID/cwd/$(basename "$MARKER")"
check "the same under task/<tid>/: refused" grep -q "Operation not permitted" "$T/last"
wait_until sh -c "[ \$(grep -c '^DENIED caller=$AC2_PID .*hook=proc_link' '$T/daemon.out') -ge $((links_before + 4)) ]"
grep "^DENIED caller=$AC2_PID .*hook=proc_link" "$T/daemon.out" | indent
check "DENIED lines (proc_link) naming the game, one per attempt" \
  test "$(grep -c "^DENIED caller=$AC2_PID .*target=$G2_PID hook=proc_link" "$T/daemon.out")" -ge $((links_before + 4))
ask 6 "$T/AC2.out" "ls /proc/self/cwd"
check "its own links still work (/proc/self/cwd is its data directory)" grep -q "^EXEC-LS /proc/self/cwd: " "$T/last"
ask 6 "$T/AC2.out" "read /proc/$G2_PID/maps"
check "and the game's module list still reads" grep -q "^EXEC-READ /proc/$G2_PID/maps: .*cheatsim" "$T/last"

step "(3) no abstract Unix sockets (X11's @/tmp/.X11-unix/X0 is one)"
ABS="fairplay-m9b-$$"
cat >"$T/listener.py" <<'EOF'
import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.bind("\0" + sys.argv[1]); s.listen()
d = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); d.bind("\0" + sys.argv[1] + "-dg")
print("listening", flush=True); time.sleep(600)
EOF
python3 -I "$T/listener.py" "$ABS" >"$T/listener.out" 2>&1 &
KILL_PIDS+=("$!")
disown
wait_for "$T/listener.out" '^listening' || bad "listener started"
ask 5 "$T/G2.out" "connect $ABS"
check "control: the game (not sandboxed) connects to @$ABS" grep -q "^EXEC-CONNECTED @$ABS" "$T/last"
ask 6 "$T/AC2.out" "connect $ABS"
check "the anti-cheat's connect: refused" grep -q "^EXEC-ERR connect @$ABS: Operation not permitted" "$T/last"
ask 6 "$T/AC2.out" "dgram $ABS-dg"
check "a datagram sent to @$ABS-dg: refused" grep -q "^EXEC-ERR dgram @$ABS-dg: Operation not permitted" "$T/last"
wait_for "$T/daemon.out" "^DENIED caller=$AC2_PID .*hook=unix_abstract .*file=$ABS-dg"
grep "^DENIED caller=$AC2_PID .*hook=unix_abstract" "$T/daemon.out" | indent
check "2 DENIED lines (unix_abstract) naming the socket" \
  test "$(grep -cE "^DENIED caller=$AC2_PID .*hook=unix_abstract .*file=$ABS(-dg)?\$" "$T/daemon.out")" -eq 2

step "(4) its /proc shows only its own processes and the game"
d_before="$(grep -c '^DENIED' "$T/daemon.out")"
ask 6 "$T/AC2.out" "ls /proc"
PIDS="$(sed -n 's/^EXEC-LS \/proc: \[\(.*\)\]$/\1/p' "$T/last" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -n | tr '\n' ' ')"
echo "      pids in its /proc: $PIDS"
check "exactly the anti-cheat and the game ($AC2_PID $G2_PID)" \
  test "$PIDS" = "$(printf '%s\n' "$AC2_PID" "$G2_PID" | sort -n | tr '\n' ' ')"
sleep 0.5
check "the scan logged nothing ($(($(grep -c '^DENIED' "$T/daemon.out") - d_before)) new DENIED lines)" \
  test "$(grep -c '^DENIED' "$T/daemon.out")" -eq "$d_before"

step "(d) its own data directory is writable and persists"
ask 6 "$T/AC2.out" "write $DATA/hello.txt hi-from-the-vendor"
check "write: ok" grep -q "^EXEC-WROTE $DATA/hello.txt" "$T/last"
ask 6 "$T/AC2.out" "read $DATA/hello.txt"
check "read back: ok" grep -q "^EXEC-READ $DATA/hello.txt: hi-from-the-vendor" "$T/last"
check "the file is in the real per-vendor directory, owned by you" \
  sh -c "[ \"\$(cat '$T/xdg-me/fairplay/$VENDOR_DIR/hello.txt')\" = hi-from-the-vendor ] && [ \"\$(stat -c %u '$T/xdg-me/fairplay/$VENDOR_DIR/hello.txt')\" = $ME_UID ]"
PRIV="/tmp/fairplay-m9b-private.$$"
ask 6 "$T/AC2.out" "write $PRIV mine"
check "its /tmp is private: writable inside" grep -q "^EXEC-WROTE $PRIV" "$T/last"
check "and not on the host" test ! -e "$PRIV"

step "(e) it can reach the fairplayd socket"
ask 6 "$T/AC2.out" "exec $T/vendor/fairplayctl --socket $SOCK status $G2_SESSION"
grep '^{' "$T/last" | jq -c '.ok.status | {protected, session: .session.session, members: [.session.members[].pid]}' 2>/dev/null | indent
check "session_status from inside the sandbox answers for its session" \
  sh -c "grep '^{' '$T/last' | jq -e --argjson s $G2_SESSION '.ok.status.protected and .ok.status.session.session==\$s' >/dev/null"

ask 6 "$T/AC2.out" "syscalls"
check "as you, too: EPERM for each, clone3 ENOSYS" all_eperm "$T/last"
ask 6 "$T/AC2.out" "read /proc/self/status" >/dev/null
check "and no capabilities at all (bounding set: CAP_SYS_PTRACE only)" caps_are "$T/last" 0000000000000000 "$PTRACE_ONLY"

step "(g) the game itself is not sandboxed"
ask 5 "$T/G2.out" "read $MARKER"
check "the game reads a file in \$HOME" grep -q "^EXEC-READ $MARKER: secret-of-the-player" "$T/last"
ask 5 "$T/G2.out" "ls $HOME" >/dev/null   # (not printed: your home listing)
check "and sees it in ls \$HOME" grep -q "^EXEC-LS $HOME: .*$(basename "$MARKER")" "$T/last"
ask 5 "$T/G2.out" "read $T/game/level1.dat"
check "and reads its install directory" grep -q "^EXEC-READ $T/game/level1.dat: the game's own data" "$T/last"
check "session_status reports no sandbox for the game" \
  sh -c "'$CTL' --socket '$SOCK' status $G2_SESSION | jq -e '.ok.status.session.game.sandbox==null' >/dev/null"

step "nothing of the sandboxes shows on the host"
check "$NEW_ROOT is empty on the host" sh -c "[ -z \"\$(sudo ls -A $NEW_ROOT 2>/dev/null)\" ]"
check_not "no host mount under $NEW_ROOT" grep -q " $NEW_ROOT" /proc/self/mountinfo

step "stop fairplayd"
exec 3>&- 4>&- 5>&- 6>&-
sudo kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
check "socket removed" test ! -e "$SOCK"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
