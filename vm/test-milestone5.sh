#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2024
# (SC2016: $names in single quotes are jq variables. SC2024: output from
# sudo commands is meant to land in files we own.)
# Milestone 5 exit test: the protection domain follows the game. Every
# process a protected game starts joins its domain in the kernel, at fork,
# and leaves it when it exits, before its PID can be reused. The launch
# environment drops Wine's DLL variables as well as LD_*. Run inside the VM,
# as your normal user (not root), from the repo root:
#   flock /run/lock/fairplay-vm-tests ./vm/test-milestone5.sh
#
# Needs sudo, BPF LSM (vm/check-milestone1.sh), bpftool, jq and setpriv.
# Builds what it uses, starts its own fairplayd on $M5_SOCKET, and on exit
# stops it, kills what it started and deletes everything it made (including
# the fairplay-launcher group, if it had to create it).
#
# Cast:
#   launcher  you, plus the fairplay-launcher group (via setpriv; your
#             account isn't changed).
#   game      `cheatsim game --depth 2`, launched protected: the game forks a
#             child, which forks a grandchild that holds the secret. Like a
#             Proton game (proton -> wine -> game.exe), only the first
#             process is launched by fairplayd.
#   attacker  `cheatsim attack`, run as root on purpose.
#   manifest  game.json, signed with a throwaway key (milestone 9): names
#             cheatsim and /bin/sh as launch executables, and cat as an
#             anti_cheat reader (it reads the grandchild's environment).
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOCK="${M5_SOCKET:-/run/fairplayd-m5test.sock}"
GROUP=fairplay-launcher
OBJ="$REPO/crates/fairplay-ebpf/target/bpfel-unknown-none/release/fairplay"
MAP_MAX=1024 # PROTECTED's max_entries (crates/fairplay-ebpf/src/maps.rs)

[ "$(id -u)" -ne 0 ] || { echo "run as your normal user (it uses sudo where needed)" >&2; exit 2; }
for t in bpftool jq setpriv; do
  command -v "$t" >/dev/null || [ -x "/usr/sbin/$t" ] || { echo "$t not found" >&2; exit 2; }
done
BPFTOOL="$(command -v bpftool || echo /usr/sbin/bpftool)"
ME_UID="$(id -u)"; ME_GID="$(id -g)"; ME_GROUPS="$(id -G | tr ' ' ,)"

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
jqt()       { jq -e "$@" >/dev/null; }
check()     { local label="$1"; shift; if "$@"; then ok "$label"; else bad "$label"; fi; }
check_not() { local label="$1"; shift; if "$@"; then bad "$label"; else ok "$label"; fi; }
step() { echo; echo "== $1"; }
indent() { sed 's/^/      /'; }

T="$(mktemp -d /tmp/fairplay-m5.XXXXXX)"
chmod 755 "$T"
DAEMON_PID=""; CREATED_GROUP=""; MAP_ID=""; KILL_PIDS=()
cleanup() {
  for p in "${KILL_PIDS[@]}"; do kill -CONT "$p" 2>/dev/null; kill "$p" 2>/dev/null; done
  # Everything launched through the daemon is in a session we can list.
  if [ -S "$SOCK" ]; then
    sudo "$T/bin/fairplayctl" --socket "$SOCK" list 2>/dev/null |
      jq -r '.ok.sessions[]? | (.game, .members[]) | select(.state=="running") | .pid' 2>/dev/null |
      while read -r p; do sudo kill "$p" 2>/dev/null; done
  fi
  # Filler entries from the map-full step, if it stopped halfway.
  [ -n "$MAP_ID" ] && [ -s "$T/unfill.batch" ] && sudo "$BPFTOOL" batch file "$T/unfill.batch" >/dev/null 2>&1
  if [ -n "$DAEMON_PID" ]; then
    sudo kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
  fi
  [ -n "$CREATED_GROUP" ] && sudo groupdel "$GROUP"
  sudo rm -f "$SOCK"
  rm -rf "$T"
}
trap cleanup EXIT

# A u32 as the four little-endian bytes bpftool takes.
le32() { printf '0x%02x 0x%02x 0x%02x 0x%02x' $(($1 & 255)) $((($1 >> 8) & 255)) $((($1 >> 16) & 255)) $((($1 >> 24) & 255)); }
# <pid>'s protection domain in our fairplayd's PROTECTED map; fails if absent.
domain_of() {
  local v
  # shellcheck disable=SC2046 # le32 is four words on purpose
  v="$(sudo "$BPFTOOL" -j map lookup id "$MAP_ID" key $(le32 "$1") 2>/dev/null)" || return 1
  jq -r '.value | map(ltrimstr("0x")) | reverse | join("")' <<<"$v" | { read -r hex && echo $((16#$hex)); }
}
in_protected() { domain_of "$1" >/dev/null; }
map_count() { sudo "$BPFTOOL" -j map dump id "$MAP_ID" | jq length; }
proc_field() { awk -v f="$2:" '$1==f {print $2}' "/proc/$1/status" 2>/dev/null; }
is_zombie() { [ "$(proc_field "$1" State)" = Z ]; }
denied() { grep -c "^DENIED .*target=$1 " "$T/daemon.out"; }
denied_at_least() { [ "$(denied "$1")" -ge "$2" ]; }

# Run a command as you plus the launcher group.
as_launcher() {
  sudo setpriv --reuid="$ME_UID" --regid="$ME_GID" --groups="$ME_GROUPS,$LAUNCHER_GID" -- \
    env HOME="$HOME" PATH="$PATH" FAIRPLAYD_SOCKET="$SOCK" XDG_DATA_HOME="$T/xdg" "$@"
}

# Wait up to ~10s for a file to match a pattern, or a command to succeed.
wait_for()   { for _ in $(seq 100); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
wait_until() { for _ in $(seq 100); do "$@" && return 0; sleep 0.1; done; return 1; }
not() { ! "$@"; }

step "build"
if [ -z "${M5_SKIP_BUILD:-}" ]; then
  (cd "$REPO/crates/fairplay-ebpf" &&
    { [ -s src/vmlinux.rs ] || aya-tool generate task_struct > src/vmlinux.rs; } &&
    cargo build --release -q) || exit 2
  (cd "$REPO" && cargo build --release -q -p fairplayd -p fairplay-api -p cheatsim) || exit 2
fi
# Copies under /tmp, so every user (and the game, running as you) can run them.
mkdir -p "$T/bin"
cp "$REPO"/target/release/{fairplayd,fairplayctl,cheatsim} "$T/bin/"
CTL="$T/bin/fairplayctl"; CHEATSIM="$T/bin/cheatsim"
export FAIRPLAYD_SOCKET="$SOCK"
"$CTL" manifest keygen --out "$T/vendor.key" >/dev/null &&
  "$CTL" manifest new --key "$T/vendor.key" --name "M5 Test Game" \
    --launch "$CHEATSIM" --launch "$(readlink -f /bin/sh)" --anti-cheat "$(readlink -f /usr/bin/cat)" \
    --out "$T/game.json" >/dev/null || exit 2
MANIFEST="$T/game.json"

step "start fairplayd on $SOCK"
if ! getent group "$GROUP" >/dev/null; then
  sudo groupadd --system "$GROUP" && CREATED_GROUP=1
fi
LAUNCHER_GID="$(getent group "$GROUP" | cut -d: -f3)"
sudo "$T/bin/fairplayd" --obj "$OBJ" --socket "$SOCK" >"$T/daemon.out" 2>"$T/daemon.err" &
DAEMON_PID=$!
for _ in $(seq 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "fairplayd did not start:"; indent <"$T/daemon.err"; exit 2; }
indent <"$T/daemon.err"
FPD="$(pgrep -P "$DAEMON_PID" -x fairplayd)"
# Our daemon's own map, from the map fds it holds: another fairplayd may be
# loaded too.
MAP_ID=""
for id in $(sudo sh -c "cat /proc/$FPD/fdinfo/*" 2>/dev/null | awk '$1=="map_id:" {print $2}' | sort -un); do
  if sudo "$BPFTOOL" -j map show id "$id" | jqt '.name=="PROTECTED"'; then MAP_ID="$id"; fi
done
[ -n "$MAP_ID" ] || { echo "no PROTECTED map held by fairplayd pid $FPD" >&2; exit 2; }
echo "      fairplayd pid $FPD, PROTECTED is map id $MAP_ID"
check "fork and exit tracing programs attached" \
  sh -c "sudo '$BPFTOOL' prog show name follow_fork | grep -q tracing &&
         sudo '$BPFTOOL' prog show name unfollow_exit | grep -q tracing"

step "launch a game that starts a grandchild, with code-injecting variables set"
as_launcher env WINEDLLOVERRIDES='dxgi=n,b' WINEDLLPATH="$T/cheat-dlls" LD_PRELOAD="$T/cheat.so" \
  FAIRPLAY_M5_MARK=kept "$CTL" launch --manifest "$MANIFEST" -- "$CHEATSIM" game --depth 2 >"$T/game.out" 2>&1
wait_for "$T/game.out" '^pid=' || { bad "game started"; indent <"$T/game.out"; exit 1; }
SESSION="$(grep '^{' "$T/game.out" | jq -r '.ok.launched.session')"
GPID="$(grep '^{' "$T/game.out" | jq -r '.ok.launched.pid')"
GC="$(sed -n 's/^pid=\([0-9]*\) .*/\1/p' "$T/game.out")"
ADDR="$(sed -n 's/^pid=[0-9]* addr=//p' "$T/game.out")"
CHILD="$(proc_field "$GC" PPid)"
grep -v '^{' "$T/game.out" | indent
echo "      session=$SESSION game=$GPID child=$CHILD grandchild=$GC addr=$ADDR"
check "the secret is in a grandchild: game -> child -> grandchild" \
  test "$(proc_field "$CHILD" PPid)" = "$GPID" -a "$GC" != "$CHILD" -a "$CHILD" != "$GPID"
GDOM="$(domain_of "$GPID")"
check "the game is in PROTECTED (domain $GDOM)" test -n "$GDOM"
check "the child joined the game's domain" test "$(domain_of "$CHILD")" = "$GDOM"
check "the grandchild joined the game's domain" test "$(domain_of "$GC")" = "$GDOM"
check "PROTECTED holds those three and nothing else" test "$(map_count)" -eq 3

step "attack the grandchild as root"
sudo "$CHEATSIM" attack --pid "$GC" --addr "$ADDR" | tee "$T/attack.out" | indent
check "0/3 paths leaked" grep -q '^0/3 paths leaked' "$T/attack.out"
wait_until denied_at_least "$GC" 3
grep "^DENIED .*target=$GC " "$T/daemon.out" | indent
check "fairplayd printed 3 DENIED lines for the grandchild" test "$(denied "$GC")" -eq 3
"$CTL" status "$SESSION" >"$T/status.json"
check "session_status files them under the game's session (3 violations, not degraded)" \
  jqt '.ok.status.session | .violations==3 and (.protection_degraded|not) and .unprotected_children==0' "$T/status.json"

step "the launch environment"
grep "session $SESSION: pid $GPID" "$T/daemon.err" | indent
for v in WINEDLLOVERRIDES WINEDLLPATH LD_PRELOAD; do
  check "fairplayd logged dropping $v" grep -q "session $SESSION: pid $GPID .*dropped env .*\"$v\"" "$T/daemon.err"
done
# Read the grandchild's environment as the session's anti_cheat reader
# (milestone 9: being in the domain isn't enough): as root from outside,
# the read itself would be denied.
as_launcher "$CTL" launch --join "$SESSION" -- /usr/bin/cat "/proc/$GC/environ" >"$T/environ.raw" 2>&1
wait_for "$T/environ.raw" 'FAIRPLAY_M5_MARK'
tr '\0' '\n' <"$T/environ.raw" | grep -v '^{' >"$T/environ"
check "the anti_cheat reader can read the grandchild (its environment)" grep -q '^FAIRPLAY_M5_MARK=kept$' "$T/environ"
for v in WINEDLLOVERRIDES WINEDLLPATH LD_PRELOAD; do
  check_not "$v doesn't reach the grandchild" grep -q "^$v=" "$T/environ"
done
check "no DENIED line for the reader's read" test "$(denied "$GC")" -eq 3

step "a descendant leaves PROTECTED when it exits, before its PID is freed"
# Stop the child so it can't reap the grandchild: the grandchild's PID stays
# taken (a zombie) until the child resumes.
KILL_PIDS=("$CHILD")
kill -STOP "$CHILD"
kill -TERM "$GC"
wait_until is_zombie "$GC"
check "the grandchild is a zombie (exited, PID not yet free)" is_zombie "$GC"
check_not "and already gone from PROTECTED" in_protected "$GC"
check "the child is still protected" test "$(domain_of "$CHILD")" = "$GDOM"
kill -CONT "$CHILD"
KILL_PIDS=()
wait_until not test -e "/proc/$GPID"
check "the chain exits: child, then game" not test -e "/proc/$CHILD" -o -e "/proc/$GPID"
check_not "the child's entry is gone" in_protected "$CHILD"
wait_until not in_protected "$GPID"
check_not "the game's entry is gone" in_protected "$GPID"
wait_until grep -q "pid $GPID exited.*removed from PROTECTED" "$T/daemon.err"
check "fairplayd still logs removing the game it launched" \
  grep -q "pid $GPID exited.*removed from PROTECTED" "$T/daemon.err"

step "control: the same game started without fairplayd"
"$CHEATSIM" game --depth 2 >"$T/plain.out" 2>&1 &
PLAIN=$!
KILL_PIDS=("$PLAIN")
wait_for "$T/plain.out" '^pid=' || bad "unprotected game started"
PGC="$(sed -n 's/^pid=\([0-9]*\) .*/\1/p' "$T/plain.out")"
PADDR="$(sed -n 's/^pid=[0-9]* addr=//p' "$T/plain.out")"
check_not "its grandchild ($PGC) is not in PROTECTED" in_protected "$PGC"
sudo "$CHEATSIM" attack --pid "$PGC" --addr "$PADDR" | tee "$T/plain-attack.out" | indent
check "3/3 paths leaked" grep -q '^3/3 paths leaked' "$T/plain-attack.out"
kill "$PLAIN"; wait "$PLAIN" 2>/dev/null; KILL_PIDS=()

step "PROTECTED full: the child runs unprotected and the session says so"
# A protected shell that waits on a FIFO (no forks while waiting), then
# becomes a game that forks once. Fill the map while it waits. The game's
# code is in $T/bin, not next to /bin/sh: say so, or the executable-mapping
# allowlist (milestone 8) stops the exec.
mkfifo "$T/go"
as_launcher "$CTL" launch --manifest "$MANIFEST" --install-dir "$T/bin" -- /bin/sh -c "read x <'$T/go'; exec '$CHEATSIM' game --depth 1" >"$T/full.out" 2>&1
FSESSION="$(grep '^{' "$T/full.out" | jq -r '.ok.launched.session')"
FGAME="$(grep '^{' "$T/full.out" | jq -r '.ok.launched.pid')"
FDOM="$(domain_of "$FGAME")"
# Filler keys are above pid_max, so no real process ever has one.
: >"$T/fill.batch"; : >"$T/unfill.batch"
for i in $(seq "$MAP_MAX"); do
  echo "map update id $MAP_ID key $(le32 $((0x40000000 + i))) value $(le32 0) noexist" >>"$T/fill.batch"
  echo "map delete id $MAP_ID key $(le32 $((0x40000000 + i)))" >>"$T/unfill.batch"
done
sudo "$BPFTOOL" batch file "$T/fill.batch" >/dev/null 2>&1 # stops at the first refusal: full
check "PROTECTED is full ($MAP_MAX entries)" test "$(map_count)" -eq "$MAP_MAX"
echo go >"$T/go"
wait_for "$T/full.out" '^pid=' || { bad "full-map game started"; indent <"$T/full.out"; }
FCHILD="$(sed -n 's/^pid=\([0-9]*\) .*/\1/p' "$T/full.out")"
FADDR="$(sed -n 's/^pid=[0-9]* addr=//p' "$T/full.out")"
check "the game's child ($FCHILD) could not be added" not in_protected "$FCHILD"
"$CTL" status "$FSESSION" >"$T/full-status.json"
jq -c '.ok.status | {protected, degraded: .session.protection_degraded, unprotected: .session.unprotected_children}' "$T/full-status.json" | indent
check "session_status: still protected, but protection_degraded with >= 1 unprotected child" \
  jqt '.ok.status | .protected and .session.protection_degraded and .session.unprotected_children >= 1' "$T/full-status.json"
check "the other session isn't marked degraded" \
  sh -c "'$CTL' status '$SESSION' | jq -e '.ok.status.session.protection_degraded | not' >/dev/null"
# The kernel still treats a child of a protected process as protected
# (the same rule that covers the moment between fork and registration).
sudo "$CHEATSIM" attack --pid "$FCHILD" --addr "$FADDR" | tee "$T/full-attack.out" | indent
check "the unregistered child is still shielded by its parent: 0/3 leaked" \
  grep -q '^0/3 paths leaked' "$T/full-attack.out"
sudo "$BPFTOOL" batch file "$T/unfill.batch" >/dev/null 2>&1; : >"$T/unfill.batch"
check "filler entries removed" test "$(map_count)" -lt 10
kill "$FGAME"
wait_until not in_protected "$FGAME"
check_not "the full-map game left PROTECTED" in_protected "$FGAME"
test -n "$FDOM" || bad "full-map game had a domain"

step "stop fairplayd"
sudo kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
check "socket removed" test ! -e "$SOCK"
any_loaded() {
  local n
  for n in follow_fork unfollow_exit ptrace_access_check; do
    sudo "$BPFTOOL" prog show name "$n" 2>/dev/null | grep -q . && return 0
  done
  return 1
}
# Tracing programs are freed after an RCU grace period, not at once.
wait_until not any_loaded
check_not "no fairplay program left loaded" any_loaded

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
