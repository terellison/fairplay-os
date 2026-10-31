#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2024
# (SC2016: $names in single quotes are jq variables. SC2024: output from
# sudo commands is meant to land in files we own.)
# Milestone 8 exit test: the executable-mapping allowlist. A protected game
# can't load a library dropped after launch (cheatsim's injected library),
# can't load one swapped into its install directory after launch, and can't
# mprotect a file mapping executable, and a process it starts can't exec a
# binary dropped after launch (execve fails with EACCES); its own libraries,
# the system's, and an approved overlay still load, also in a process it
# started that outlives it. Every denial shows up as a DENIED line and in
# the vendor's violation stream. Run inside the VM, as your normal user (not
# root), from the repo root:  ./vm/test-milestone8.sh
#
# Needs sudo, BPF LSM (vm/check-milestone1.sh), bpftool, jq, python3 and cc.
# Builds what it uses, starts its own fairplayd on $M8_SOCKET, and on exit
# stops it, kills what it launched and deletes everything it made.
#
# Cast (all files under one temp dir):
#   game/      the install directory: cheatsim, lib_ok.so, lib_swap.so
#   overlay/   overlay.so, approved with fairplayd --overlay
#   drop/      cheat.so, written after the game starts (the injected library)
#   game       `cheatsim game --dlopen-stdin`, launched protected as you; it
#              dlopen()s (or mprotects) each path the test writes to its stdin.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOCK="${M8_SOCKET:-/run/fairplayd-m8test.sock}"
OBJ="$REPO/crates/fairplay-ebpf/target/bpfel-unknown-none/release/fairplay"

[ "$(id -u)" -ne 0 ] || { echo "run as your normal user (it uses sudo where needed)" >&2; exit 2; }
for t in bpftool jq python3 cc; do
  command -v "$t" >/dev/null || [ -x "/usr/sbin/$t" ] || { echo "$t not found" >&2; exit 2; }
done
BPFTOOL="$(command -v bpftool || echo /usr/sbin/bpftool)"
ME_UID="$(id -u)"

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
jqt()       { jq -e "$@" >/dev/null; }
check()     { local label="$1"; shift; if "$@"; then ok "$label"; else bad "$label"; fi; }
check_not() { local label="$1"; shift; if "$@"; then bad "$label"; else ok "$label"; fi; }
step() { echo; echo "== $1"; }
indent() { sed 's/^/      /'; }

T="$(mktemp -d /tmp/fairplay-m8.XXXXXX)"
chmod 755 "$T"
DAEMON_PID=""; STREAM_PID=""; ORPHAN_PID=""
cleanup() {
  exec 3>&-
  [ -n "$STREAM_PID" ] && sudo kill "$STREAM_PID" 2>/dev/null
  [ -n "$ORPHAN_PID" ] && kill "$ORPHAN_PID" 2>/dev/null
  if [ -S "$SOCK" ]; then
    sudo "$T/bin/fairplayctl" --socket "$SOCK" list 2>/dev/null |
      jq -r '.ok.sessions[]? | (.game, .members[]) | select(.state=="running") | .pid' 2>/dev/null |
      while read -r p; do sudo kill "$p" 2>/dev/null; done
  fi
  if [ -n "$DAEMON_PID" ]; then
    sudo kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
  fi
  sudo rm -f "$SOCK"
  rm -rf "$T"
}
trap cleanup EXIT

# Is <pid> a key in the PROTECTED map? Keys are u32 tgids, little-endian bytes.
in_protected() {
  local key
  key="$(printf '"0x%02x","0x%02x","0x%02x","0x%02x"' $(($1 & 255)) $((($1 >> 8) & 255)) $((($1 >> 16) & 255)) $((($1 >> 24) & 255)))"
  sudo "$BPFTOOL" -j map dump name PROTECTED 2>/dev/null | tr -d ' \n' | grep -q "\"key\":\[$key\]"
}
exec_entries() { sudo "$BPFTOOL" -j map dump name EXEC_ALLOWED 2>/dev/null | jq length; }

# Wait up to ~10s for a file to match a pattern.
wait_for() { for _ in $(seq 100); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

# Ask the game to do something; wait for its LOADED/BLOCKED/EXEC-/SPAWNED line.
ask() {
  local before
  before="$(grep -cE '^(LOADED|BLOCKED|MPROTECT-|EXEC-|SPAWNED)' "$T/game.out")"
  echo "$1" >&3
  for _ in $(seq 100); do
    [ "$(grep -cE '^(LOADED|BLOCKED|MPROTECT-|EXEC-|SPAWNED)' "$T/game.out")" -gt "$before" ] && break
    sleep 0.1
  done
  grep -E '^(LOADED|BLOCKED|MPROTECT-|EXEC-|SPAWNED)' "$T/game.out" | tail -1 | tee "$T/last" | indent
}

# A library whose cheatsim_marker() returns $2.
mklib() { printf 'int cheatsim_marker(void) { return %d; }\n' "$2" >"$T/lib$2.c" && cc -shared -fPIC -o "$1" "$T/lib$2.c"; }

step "build"
if [ -z "${M8_SKIP_BUILD:-}" ]; then
  (cd "$REPO/crates/fairplay-ebpf" &&
    { [ -s src/vmlinux.rs ] || aya-tool generate task_struct > src/vmlinux.rs; } &&
    cargo build --release -q) || exit 2
  (cd "$REPO" && cargo build --release -q -p fairplayd -p fairplay-api -p cheatsim) || exit 2
fi
mkdir -p "$T/bin" "$T/game" "$T/overlay" "$T/drop"
cp "$REPO"/target/release/{fairplayd,fairplayctl} "$T/bin/"
cp "$REPO/target/release/cheatsim" "$T/game/"
CTL="$T/bin/fairplayctl"; GAME="$T/game/cheatsim"
mklib "$T/game/lib_ok.so" 1 && mklib "$T/game/lib_swap.so" 2 && mklib "$T/overlay/overlay.so" 3 || exit 2
export FAIRPLAYD_SOCKET="$SOCK"
# Milestone 9: fairplayd launches only what a signed manifest names.
"$CTL" manifest keygen --out "$T/vendor.key" >/dev/null &&
  "$CTL" manifest new --key "$T/vendor.key" --name "M8 Test Game" \
    --launch "$GAME" --launch "$(readlink -f "$(command -v python3)")" \
    --out "$T/game.json" >/dev/null || exit 2
MANIFEST="$T/game.json"

step "start fairplayd on $SOCK with one approved overlay"
if sudo "$BPFTOOL" map show name EXEC_ALLOWED 2>/dev/null | grep -q .; then
  echo "note: another fairplay program is loaded; map checks look at every EXEC_ALLOWED map"
fi
sudo "$T/bin/fairplayd" --obj "$OBJ" --socket "$SOCK" --overlay "$T/overlay/overlay.so" \
  >"$T/daemon.out" 2>"$T/daemon.err" &
DAEMON_PID=$!
for _ in $(seq 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "fairplayd did not start:"; indent <"$T/daemon.err"; exit 2; }
indent <"$T/daemon.err"
check "the overlay is on the allowlist for every domain (1 entry)" test "$(exec_entries)" -eq 1

step "launch the game protected; it reads library paths from a pipe"
mkfifo "$T/cmd"
exec 3<>"$T/cmd"   # held open read-write, so neither side blocks or sees EOF
sudo "$CTL" --socket "$SOCK" launch --run-as "$ME_UID" --manifest "$MANIFEST" -- "$GAME" game --dlopen-stdin <"$T/cmd" >"$T/game.out" 2>&1
wait_for "$T/game.out" '^pid=' || { bad "game started"; indent <"$T/game.out"; indent <"$T/daemon.err"; exit 1; }
SESSION="$(grep '^{' "$T/game.out" | jq -r '.ok.launched.session')"
GPID="$(grep '^{' "$T/game.out" | jq -r '.ok.launched.pid')"
echo "      session=$SESSION pid=$GPID"
ok "the protected game started (its loader, libc and libraries mapped)"
check "the game's pid is in PROTECTED" in_protected "$GPID"
grep "session $SESSION: pid $GPID" "$T/daemon.err" | indent
check "its 3 code files (cheatsim, lib_ok.so, lib_swap.so) are on the allowlist" \
  grep -q "session $SESSION: pid $GPID .*; 3 code files from $T/game allowed" "$T/daemon.err"
check "EXEC_ALLOWED holds them plus the overlay (4 entries)" test "$(exec_entries)" -eq 4

sudo "$CTL" --socket "$SOCK" violations "$SESSION" --count 4 >"$T/events.jsonl" 2>&1 &
STREAM_PID=$!
wait_for "$T/events.jsonl" subscribed || bad "vendor stream subscribed"

step "(a) a library dropped in $T/drop after launch"
mklib "$T/drop/cheat.so" 66
ask "$T/drop/cheat.so"
check "BLOCKED" grep -q "^BLOCKED $T/drop/cheat.so" "$T/last"
check "fairplayd printed a DENIED line: hook=mmap_file file=cheat.so" \
  grep -q "^DENIED caller=$GPID .*target=$GPID hook=mmap_file .*file=cheat.so$" "$T/daemon.out"

step "(b) a library in the install directory at launch"
ask "$T/game/lib_ok.so"
check "LOADED (marker=1)" grep -q "^LOADED $T/game/lib_ok.so marker=1$" "$T/last"

step "(c) a library in the install directory replaced after launch"
mklib "$T/game/lib_swap.so.new" 22 && mv "$T/game/lib_swap.so.new" "$T/game/lib_swap.so"
ask "$T/game/lib_swap.so"
check "BLOCKED (new inode, same path)" grep -q "^BLOCKED $T/game/lib_swap.so" "$T/last"
check "DENIED line: hook=mmap_file file=lib_swap.so" \
  grep -q "^DENIED caller=$GPID .*hook=mmap_file .*file=lib_swap.so$" "$T/daemon.out"

step "(d) the approved overlay"
ask "$T/overlay/overlay.so"
check "LOADED (marker=3)" grep -q "^LOADED $T/overlay/overlay.so marker=3$" "$T/last"

step "(f) mprotect: map a file read-only, then ask for PROT_EXEC"
ask "mprotect $T/drop/cheat.so"
check "MPROTECT-BLOCKED for the dropped library" grep -q "^MPROTECT-BLOCKED $T/drop/cheat.so" "$T/last"
check "DENIED line: hook=file_mprotect file=cheat.so" \
  grep -q "^DENIED caller=$GPID .*hook=file_mprotect .*file=cheat.so$" "$T/daemon.out"
ask "mprotect $T/game/lib_ok.so"
check "MPROTECT-OK for an allowed library" grep -q "^MPROTECT-OK $T/game/lib_ok.so" "$T/last"

step "(g) exec: the game forks a child (in its domain since milestone 5) that execs a program"
ask "exec /usr/bin/true"
check "EXEC-OK for a system binary (/usr/bin/true)" grep -q "^EXEC-OK /usr/bin/true$" "$T/last"
cp /usr/bin/true "$T/drop/helper"   # same code, but yours and dropped after launch
ask "exec $T/drop/helper"
check "EXEC-BLOCKED for a binary dropped after launch: execve fails with EACCES (no SIGSEGV)" \
  grep -q "^EXEC-BLOCKED $T/drop/helper: execve failed: Permission denied" "$T/last"
check "DENIED line: hook=bprm_check_security file=helper, by the child (not the game)" \
  grep -qE "^DENIED caller=([0-9]+) .*target=\\1 hook=bprm_check_security .*file=helper$" "$T/daemon.out"
check "... exactly one for it (mmap_file never saw it)" \
  test "$(grep -c "^DENIED .*file=helper$" "$T/daemon.out")" -eq 1
check_not "... and the child's caller pid is not the game's" \
  grep -q "^DENIED caller=$GPID .*file=helper$" "$T/daemon.out"
printf '#!/bin/sh\nexit 0\n' >"$T/drop/script.sh" && chmod +x "$T/drop/script.sh"
ask "exec $T/drop/script.sh"
check "EXEC-OK for a dropped #! script: only its interpreter (/bin/sh, a system file) is mapped" \
  grep -q "^EXEC-OK $T/drop/script.sh$" "$T/last"

step "the vendor's stream"
for _ in $(seq 50); do kill -0 "$STREAM_PID" 2>/dev/null || break; sleep 0.1; done
grep '"violation"' "$T/events.jsonl" >"$T/v.jsonl"
jq -c '.event.violation | {caller, target, hook, file, mode}' "$T/v.jsonl" | indent
check "4 violation events: mmap_file cheat.so, mmap_file lib_swap.so, file_mprotect cheat.so, bprm_check_security helper" \
  jqt -s --argjson s "$SESSION" '[.[].event.violation] |
    length == 4 and all(.[]; .session==$s and .caller==.target)
    and ([.[] | [.hook, .file]] == [["mmap_file","cheat.so"],["mmap_file","lib_swap.so"],["file_mprotect","cheat.so"],["bprm_check_security","helper"]])' "$T/v.jsonl"
check "the first three came from the game itself" \
  jqt -s --argjson g "$GPID" '[.[].event.violation][0:3] | all(.[]; .caller==$g and .comm=="cheatsim")' "$T/v.jsonl"
check_not "no other DENIED lines (in particular none by fairplayd itself)" \
  grep -v -e "hook=mmap_file" -e "hook=file_mprotect" -e "hook=bprm_check_security" <(grep '^DENIED' "$T/daemon.out")
"$CTL" status "$SESSION" >"$T/status.json" 2>/dev/null || sudo "$CTL" --socket "$SOCK" status "$SESSION" >"$T/status.json"
check "session_status counts 4 violations" jqt '.ok.status.session.violations==4' "$T/status.json"

step "JIT-style code still works in a protected process"
cat >"$T/jit.py" <<'EOF'
# Anonymous executable memory (how JITs work) and an executable memfd.
import mmap, os
rwx = mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC
mmap.mmap(-1, 4096, prot=rwx)
fd = os.memfd_create("jit")
os.ftruncate(fd, 4096)
mmap.mmap(fd, 4096, prot=rwx)
print("JIT-OK", flush=True)
EOF
sudo "$CTL" --socket "$SOCK" launch --run-as "$ME_UID" --manifest "$MANIFEST" -- "$(command -v python3)" -I "$T/jit.py" >"$T/jit.out" 2>&1
wait_for "$T/jit.out" 'JIT-OK\|Error'
indent <"$T/jit.out"
check "anonymous RWX memory and an executable memfd map fine" grep -q '^JIT-OK' "$T/jit.out"
check "python3 and its modules (system files) needed no allowlist entries" \
  grep -q "pid .*python3.*; 0 code files from" "$T/daemon.err"

step "(e) the same dropped library in an unprotected game"
timeout 5 "$GAME" game --dlopen "$T/drop/cheat.so" >"$T/plain.out" 2>&1
grep -E '^(LOADED|BLOCKED)' "$T/plain.out" | indent
check "LOADED (marker=66): only protected processes are restricted" \
  grep -q "^LOADED $T/drop/cheat.so marker=66$" "$T/plain.out"

step "install_dir must be a real directory"
sudo "$CTL" --socket "$SOCK" launch --run-as "$ME_UID" --manifest "$MANIFEST" --install-dir /proc -- "$GAME" game >"$T/proc.out" 2>/dev/null
check "--install-dir /proc is refused (bad_request), nothing launched" \
  jqt '.error.code=="bad_request"' "$T/proc.out"

step "the game exits, leaving behind a process it started"
# The child (python3, a system file) waits for the go file, then loads one
# of the game's libraries and tries the dropped one.
cat >"$T/orphan.py" <<'EOF'
import ctypes, os, sys, time
go = sys.argv[1]
for _ in range(300):
    if os.path.exists(go):
        break
    time.sleep(0.1)
for name in sys.argv[2:]:
    try:
        print("ORPHAN-LOADED", name, "marker=%d" % ctypes.CDLL(name).cheatsim_marker(), flush=True)
    except OSError as e:
        print("ORPHAN-BLOCKED", name, e, flush=True)
EOF
ask "spawn $(readlink -f "$(command -v python3)") -I $T/orphan.py $T/go $T/game/lib_ok.so $T/drop/cheat.so"
ORPHAN_PID="$(sed -n 's/^SPAWNED \([0-9]*\) .*/\1/p' "$T/last")"
echo "      child=$ORPHAN_PID"
check "the child is in PROTECTED" in_protected "$ORPHAN_PID"
exec 3>&-
kill "$GPID"
for _ in $(seq 50); do in_protected "$GPID" || break; sleep 0.1; done
check_not "the game's pid is gone from PROTECTED" in_protected "$GPID"
check "the child is still in PROTECTED" in_protected "$ORPHAN_PID"
sleep 1.5   # past fairplayd's once-a-second check
check "the session's allowlist entries stay while the child runs (4 entries)" test "$(exec_entries)" -eq 4
touch "$T/go"
for _ in $(seq 100); do kill -0 "$ORPHAN_PID" 2>/dev/null || break; sleep 0.1; done
grep '^ORPHAN-' "$T/game.out" | indent
check "the child outliving the game can still map the game's library (marker=1)" \
  grep -q "^ORPHAN-LOADED $T/game/lib_ok.so marker=1$" "$T/game.out"
check "... and still can't map the dropped one" \
  grep -q "^ORPHAN-BLOCKED $T/drop/cheat.so" "$T/game.out"
check "DENIED line for it: caller=the child, hook=mmap_file file=cheat.so" \
  grep -q "^DENIED caller=$ORPHAN_PID .*hook=mmap_file .*file=cheat.so$" "$T/daemon.out"
for _ in $(seq 30); do [ "$(exec_entries)" -eq 1 ] && break; sleep 0.1; done
check "once the child is gone, its allowlist entries go; the overlay's stays (1 entry)" test "$(exec_entries)" -eq 1
check "fairplayd says the domain had no processes left" \
  grep -q "has no processes left; its allowlist entries are released" "$T/daemon.err"

step "stop fairplayd"
sudo kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
check "socket removed" test ! -e "$SOCK"
check_not "no mmap_file program left attached" sudo "$BPFTOOL" prog show name mmap_file
check_not "no file_mprotect program left attached" sudo "$BPFTOOL" prog show name file_mprotect
check_not "no bprm_check_security program left attached" sudo "$BPFTOOL" prog show name bprm_check_security

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
