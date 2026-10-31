#!/usr/bin/env bash
# shellcheck disable=SC2024
# (SC2024: output from sudo commands is meant to land in files we own.)
# Milestone 6 exit test: fairplayd protects itself from root. With
# --self-protect, root cannot kill or stop fairplayd, trace it or read its
# memory, read or write its BPF maps, detach its programs, or load a BPF
# program of its own, and every attempt prints a DENIED line. Without it
# (developer mode) root kills it as before. Run inside the VM, as your normal
# user (not root), from the repo root, under the shared VM lock:
#   flock /run/lock/fairplay-vm-tests ./vm/test-milestone6.sh
#
# Needs sudo, BPF LSM (vm/check-milestone1.sh) and bpftool. Builds what it
# uses and starts its own fairplayd on $M6_SOCKET with
# --self-protect-for $M6_PROTECT_SECS (default 60): even the test can't stop
# a self-protected fairplayd, so it waits for fairplayd to turn self-protection
# off and exit on its own, then checks nothing is left loaded. On failure the
# cleanup waits for that too (at most $M6_PROTECT_SECS), so the lock is never
# released with a self-protected fairplayd still running.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOCK="${M6_SOCKET:-/run/fairplayd-m6test.sock}"
PROTECT_SECS="${M6_PROTECT_SECS:-60}"
OBJ="$REPO/crates/fairplay-ebpf/target/bpfel-unknown-none/release/fairplay"

[ "$(id -u)" -ne 0 ] || { echo "run as your normal user (it uses sudo where needed)" >&2; exit 2; }
command -v bpftool >/dev/null || [ -x /usr/sbin/bpftool ] || { echo "bpftool not found" >&2; exit 2; }
BPFTOOL="$(command -v bpftool || echo /usr/sbin/bpftool)"

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
check()     { local label="$1"; shift; if "$@"; then ok "$label"; else bad "$label"; fi; }
check_not() { local label="$1"; shift; if "$@"; then bad "$label"; else ok "$label"; fi; }
step() { echo; echo "== $1"; }
indent() { sed 's/^/      /'; }
not() { ! "$@"; }

T="$(mktemp -d /tmp/fairplay-m6.XXXXXX)"
chmod 755 "$T"
DAEMON_PID=""; FPD=""
cleanup() {
  if [ -n "$DAEMON_PID" ]; then
    # Works on an unprotected fairplayd. A self-protected one refuses (and
    # says so with a DENIED line), so wait for its own deadline.
    [ -n "$FPD" ] && sudo kill -CONT "$FPD" 2>/dev/null
    sudo kill "$DAEMON_PID" 2>/dev/null
    [ -n "$FPD" ] && sudo kill "$FPD" 2>/dev/null
    echo "cleanup: waiting for fairplayd (pid ${FPD:-?}) to exit"
    wait "$DAEMON_PID" 2>/dev/null
  fi
  sudo rm -f "$SOCK"
  rm -rf "$T"
}
trap cleanup EXIT

# Wait up to ~10s for a command to succeed.
wait_until() { for _ in $(seq 100); do "$@" && return 0; sleep 0.1; done; return 1; }
alive() { sudo kill -0 "$1" 2>/dev/null; }
proc_state() { awk '$1=="State:" {print $2}' "/proc/$1/status" 2>/dev/null; }
# DENIED lines against fairplayd from <hook>, optionally with <mode>.
denied() { grep -c "^DENIED .* target=$FPD hook=$1 mode=${2:-}" "$T/daemon.out"; }
denied_more_than() { [ "$(denied "$1" "${3:-}")" -gt "$2" ]; }

# expect_denied <label> <hook> <mode> <command...>: the command (run as
# root) must fail, and fairplayd must print exactly one new DENIED line for
# <hook> with <mode>.
expect_denied() {
  local label="$1" hook="$2" mode="$3" before; shift 3
  before="$(denied "$hook" "$mode")"
  if sudo "$@" >"$T/attempt.out" 2>&1; then
    bad "$label: refused"
    indent <"$T/attempt.out"
  else
    ok "$label: refused ($(tail -n1 "$T/attempt.out" | cut -c1-90))"
  fi
  wait_until denied_more_than "$hook" "$before" "$mode"
  grep "^DENIED .* target=$FPD hook=$hook mode=$mode" "$T/daemon.out" | tail -n +$((before + 1)) | indent
  check "$label: one DENIED line (hook=$hook mode=$mode)" test "$(denied "$hook" "$mode")" -eq $((before + 1))
}

step "build"
if [ -z "${M6_SKIP_BUILD:-}" ]; then
  (cd "$REPO/crates/fairplay-ebpf" &&
    { [ -s src/vmlinux.rs ] || aya-tool generate task_struct > src/vmlinux.rs; } &&
    cargo build --release -q) || exit 2
  (cd "$REPO" && cargo build --release -q -p fairplayd -p fairplay-api -p cheatsim) || exit 2
fi
mkdir -p "$T/bin"
cp "$REPO"/target/release/{fairplayd,fairplayctl,cheatsim} "$T/bin/"
CTL="$T/bin/fairplayctl"; CHEATSIM="$T/bin/cheatsim"

# start_daemon <args...>: start fairplayd on $SOCK, set DAEMON_PID (sudo's
# pid) and FPD (fairplayd's).
start_daemon() {
  sudo rm -f "$SOCK"
  sudo "$T/bin/fairplayd" --obj "$OBJ" --socket "$SOCK" "$@" >"$T/daemon.out" 2>"$T/daemon.err" &
  DAEMON_PID=$!
  wait_until test -S "$SOCK" || { echo "fairplayd did not start:"; indent <"$T/daemon.err"; exit 2; }
  FPD="$(pgrep -P "$DAEMON_PID" -x fairplayd)"
  indent <"$T/daemon.err"
}

step "developer mode: no --self-protect, root can kill fairplayd"
start_daemon
check_not "no self-protection" grep -q 'self-protection on' "$T/daemon.err"
sudo kill -9 "$FPD"
wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
check "kill -9 as root ends it" not alive "$FPD"
check "no DENIED line" test "$(grep -c '^DENIED' "$T/daemon.out")" -eq 0
FPD=""

step "player mode: fairplayd --self-protect-for $PROTECT_SECS"
STARTED=$SECONDS
start_daemon --self-protect-for "$PROTECT_SECS"
ON="$(grep 'self-protection on for pid' "$T/daemon.err")"
check "self-protection on for fairplayd's pid ($FPD)" grep -q "self-protection on for pid $FPD:" <<<"$ON"
MAP_ID="$(grep -o ' PROTECTED=[0-9]*' <<<"$ON" | cut -d= -f2)"
SELF_ID="$(grep -o ' SELF_PROTECT=[0-9]*' <<<"$ON" | cut -d= -f2)"
PROG_ID="$(grep -o 'programs [0-9]*' <<<"$ON" | cut -d' ' -f2)"
LINK_ID="$(grep -o 'links [0-9]*' <<<"$ON" | cut -d' ' -f2)"
echo "      PROTECTED map id $MAP_ID, SELF_PROTECT map id $SELF_ID, a program $PROG_ID, a link $LINK_ID"
for v in MAP_ID SELF_ID PROG_ID LINK_ID; do
  [ -n "${!v}" ] || { bad "fairplayd listed its $v"; exit 1; }
done

step "signals, as root"
expect_denied "kill -9" task_kill 0x9 kill -9 "$FPD"
check "fairplayd is still running" alive "$FPD"
expect_denied "kill -STOP" task_kill 0x13 kill -STOP "$FPD"
check "fairplayd is not stopped (state $(proc_state "$FPD"))" not test "$(proc_state "$FPD")" = T
expect_denied "kill -TERM (to fairplayd, not its sudo)" task_kill 0xf kill -TERM "$FPD"
check "fairplayd is still running" alive "$FPD"

step "its maps, programs and links, as root with bpftool"
expect_denied "bpftool map dump PROTECTED" bpf_map "" "$BPFTOOL" map dump id "$MAP_ID"
expect_denied "bpftool map update PROTECTED (add pid 1)" bpf_map "" \
  "$BPFTOOL" map update id "$MAP_ID" key 1 0 0 0 value 1 0 0 0
expect_denied "bpftool map update SELF_PROTECT (turn it off)" bpf_map "" \
  "$BPFTOOL" map update id "$SELF_ID" key 0 0 0 0 value 0 0 0 0
expect_denied "bpftool prog dump of a fairplayd program" bpf_prog "" "$BPFTOOL" prog dump xlated id "$PROG_ID"
expect_denied "bpftool link detach" bpf 0x1e "$BPFTOOL" link detach id "$LINK_ID"

step "memory, file descriptors and BPF syscalls, as root with cheatsim self-attack"
before_ptrace="$(denied ptrace_access_check)"
before_bpf="$(denied bpf)"
before_prog="$(denied bpf_prog)"
if sudo "$CHEATSIM" self-attack --pid "$FPD" --prog-id "$PROG_ID" >"$T/self-attack.out" 2>&1; then
  ok "cheatsim self-attack: nothing got past"
else
  bad "cheatsim self-attack: nothing got past"
fi
indent <"$T/self-attack.out"
for a in "ptrace attach" process_vm_readv "open /proc/<pid>/mem" "pidfd_getfd" \
         "bpf(BPF_PROG_LOAD)" "bpf(BPF_LINK_DETACH)" "bpf(BPF_PROG_DETACH)" "bpf(BPF_PROG_GET_FD_BY_ID)"; do
  check "blocked: $a" grep -qF "BLOCKED $a" "$T/self-attack.out"
done
wait_until denied_more_than bpf_prog "$before_prog"
sleep 0.5 # the rest arrive in the same batch; give stragglers a moment
check "4 DENIED lines from ptrace_access_check (attach, process_vm_readv, /proc/<pid>/mem, pidfd_getfd)" \
  test "$(denied ptrace_access_check)" -eq $((before_ptrace + 4))
check "3 DENIED lines from bpf (PROG_LOAD 0x5, LINK_DETACH 0x22, PROG_DETACH 0x9)" \
  sh -c "[ $(denied bpf) -eq $((before_bpf + 3)) ] &&
         grep -q 'target=$FPD hook=bpf mode=0x5\$' '$T/daemon.out' &&
         grep -q 'target=$FPD hook=bpf mode=0x22\$' '$T/daemon.out' &&
         grep -q 'target=$FPD hook=bpf mode=0x9\$' '$T/daemon.out'"
check "1 DENIED line from bpf_prog (PROG_GET_FD_BY_ID)" test "$(denied bpf_prog)" -eq $((before_prog + 1))
grep "^DENIED .*comm=cheatsim .*target=$FPD " "$T/daemon.out" | indent

step "fairplayd still works while it protects itself"
check "the socket API answers root" sh -c "sudo '$CTL' --socket '$SOCK' list | grep -q '\"ok\"'"
"$CTL" manifest keygen --out "$T/vendor.key" >/dev/null
"$CTL" manifest new --key "$T/vendor.key" --name "M6 Test Game" --launch "$CHEATSIM" --out "$T/game.json" >/dev/null
sudo "$CTL" --socket "$SOCK" launch --run-as "$(id -u)" --manifest "$T/game.json" --install-dir "$T/bin" -- "$CHEATSIM" game >"$T/game.out" 2>&1
wait_until grep -q '^pid=' "$T/game.out" || { bad "a protected game started"; indent <"$T/game.out"; }
GPID="$(sed -n 's/^pid=\([0-9]*\) .*/\1/p' "$T/game.out")"
ADDR="$(sed -n 's/^pid=[0-9]* addr=//p' "$T/game.out")"
sudo "$CHEATSIM" attack --pid "$GPID" --addr "$ADDR" >"$T/attack.out" 2>&1
check "a game it launched is still protected: 0/3 leaked" grep -q '^0/3 paths leaked' "$T/attack.out"
# The game is fairplayd's child. Its exit reaches fairplayd through the
# kernel (SIGCHLD, waitid), which the task_kill hook doesn't see.
sudo kill "$GPID"
wait_until grep -q "pid $GPID exited" "$T/daemon.err"
check "fairplayd still sees its child exit (kernel-sent SIGCHLD and wait are untouched)" \
  grep -q "pid $GPID exited" "$T/daemon.err"
check "fairplayd is still running, after $((SECONDS - STARTED))s of $PROTECT_SECS" alive "$FPD"
TOTAL="$(grep -c '^DENIED' "$T/daemon.out")"
echo "      $TOTAL DENIED lines in all"

step "fairplayd turns self-protection off and exits on its own"
echo "      waiting up to $((PROTECT_SECS + 15))s"
for _ in $(seq $(((PROTECT_SECS + 15) * 10))); do alive "$FPD" || break; sleep 0.1; done
check "fairplayd exited by itself" not alive "$FPD"
wait "$DAEMON_PID"; status=$?; DAEMON_PID=""
grep -E 'time is up|self-protection off|stopping' "$T/daemon.err" | indent
check "it turned self-protection off first" grep -q 'self-protection off' "$T/daemon.err"
check "and exited cleanly (status $status)" test "$status" -eq 0
check "socket removed" test ! -e "$SOCK"
any_loaded() {
  local n
  for n in ptrace_access_check task_kill bpf bpf_map bpf_prog follow_fork unfollow_exit; do
    sudo "$BPFTOOL" prog show name "$n" 2>/dev/null | grep -q . && return 0
  done
  return 1
}
# Tracing programs are freed after an RCU grace period, not at once.
wait_until not any_loaded
check_not "no fairplay program left loaded" any_loaded
FPD=""

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
