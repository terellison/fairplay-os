#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2024
# (SC2016: $names in single quotes are jq variables. SC2024: output from
# sudo commands is meant to land in files we own.)
# Milestone 9 exit test, part B: the vendor's anti-cheat sees the game and
# nothing else. A signed mock vendor, joined to a game's session, can read
# the game's memory, its install directory, its own data directory and the
# fairplayd socket, and nothing else: not the user's home directory, not
# another program's memory. Run inside the VM, as your normal user (not
# root), from the repo root, under the shared VM lock:
#   flock /run/lock/fairplay-vm-tests ./vm/test-milestone9b.sh
#
# Needs sudo, BPF LSM (vm/check-milestone1.sh) and jq. Builds what
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
#   session 2  game and anti-cheat as you: the file-system tests, with the
#              anti-cheat's data directory created as you.
#   browser    `cheatsim game`, unprotected, as root: an ordinary program of
#              the same user (root, like session 1's anti-cheat).
# The mock vendor is `anticheat game --dlopen-stdin`, which takes commands
# on a pipe (attack, forkattack, become, read, ls, write, exec: see
# cheatsim's --help).
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOCK="${M9B_SOCKET:-/run/fairplayd-m9btest.sock}"
OBJ="$REPO/crates/fairplay-ebpf/target/bpfel-unknown-none/release/fairplay"
NEW_ROOT=/run/fairplay-sandbox

[ "$(id -u)" -ne 0 ] || { echo "run as your normal user (it uses sudo where needed)" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq not found" >&2; exit 2; }
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
cleanup() {
  exec 3>&- 4>&- 5>&- 6>&-
  for p in "${KILL_PIDS[@]}"; do sudo kill "$p" 2>/dev/null; done
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
  rm -f "$MARKER"
  sudo rm -rf "$T"
}
trap cleanup EXIT

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
  wait_for "$T/$name.out" '^pid=' || { bad "$name started"; indent <"$T/$name.out"; indent <"$T/daemon.err"; exit 1; }
  pid="$(grep '^{' "$T/$name.out" | jq -r '.ok.launched.pid')"
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

step "(a) the sandboxed anti-cheat reads the game"
ask 4 "$T/AC1.out" "attack $G1_PID $G1_ADDR"
check "3/3 paths leaked: the reader can read the game from inside its sandbox" grep -q '^3/3 paths leaked' "$T/last"
check "no DENIED lines for the game" test "$(denied "$G1_PID")" -eq 0

step "(c) it can't read an ordinary program of the same user (the browser)"
sudo "$CHEATSIM" game >"$T/browser.out" 2>&1 &
wait_for "$T/browser.out" '^pid=' || bad "browser started"
B_PID="$(sed -n 's/^pid=\([0-9]*\) .*/\1/p' "$T/browser.out")"
B_ADDR="$(sed -n "s/^pid=$B_PID addr=//p" "$T/browser.out")"
KILL_PIDS+=("$B_PID")
echo "      browser pid=$B_PID addr=$B_ADDR (unprotected, root)"
sudo "$CHEATSIM" attack --pid "$B_PID" --addr "$B_ADDR" >"$T/control.out" 2>&1
check "control: root outside the sandbox reads the browser (3/3)" grep -q '^3/3 paths leaked' "$T/control.out"
v_before="$(jq '.ok.status.session.violations' "$T/status1.json")"
ask 4 "$T/AC1.out" "attack $B_PID $B_ADDR"
check "0/3 paths leaked" grep -q '^0/3 paths leaked' "$T/last"
wait_until denied_at_least "$B_PID" 3
grep "^DENIED .*target=$B_PID " "$T/daemon.out" | indent
check "3 DENIED lines, caller the anti-cheat" \
  test "$(grep -c "^DENIED caller=$AC1_PID .*target=$B_PID hook=ptrace_access_check" "$T/daemon.out")" -eq 3
ask 4 "$T/AC1.out" "read /proc/$B_PID/environ"
check "/proc/<browser>/environ: denied" grep -q "^EXEC-ERR read /proc/$B_PID/environ: Permission denied" "$T/last"
ask 4 "$T/AC1.out" "read /proc/$B_PID/maps"
check "/proc/<browser>/maps: denied" grep -q "^EXEC-ERR read /proc/$B_PID/maps: Permission denied" "$T/last"
echo "      (documented, still visible: the pid list, /proc/<pid>/cmdline, comm, status)"
ask 4 "$T/AC1.out" "read /proc/$B_PID/cmdline"
v_after="$(ctl status "$G1_SESSION" | jq '.ok.status.session.violations')"
check "the attempts are filed under the anti-cheat's session (violations $v_before -> $v_after)" \
  test "$v_after" -ge $((v_before + 5))

step "(f) part A's untested cases: a reader's fork-only child, and a reader that execs /bin/sh"
before_g="$(denied "$G1_PID")"
ask 4 "$T/AC1.out" "forkattack $G1_PID $G1_ADDR"
CHILD="$(sed -n 's/^forked child pid=\([0-9]*\)/\1/p' "$T/last")"
check "a fork-only child of the reader (pid $CHILD): 0/3 paths leaked" grep -q '^0/3 paths leaked' "$T/last"
wait_until denied_at_least "$G1_PID" $((before_g + 3))
check "3 DENIED lines from the child" \
  test "$(grep -c "^DENIED caller=$CHILD .*target=$G1_PID " "$T/daemon.out")" -eq 3
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
wait_until denied_at_least "$G1_PID" $((before_g + 3))
check "3 DENIED lines from that pid" \
  test "$(grep -c "^DENIED caller=$AC1_PID .*target=$G1_PID " "$T/daemon.out")" -eq 3

step "session 2 (you): the game and its anti-cheat run as uid $ME_UID"
start G2 5 -- sudo "$CTL" --socket "$SOCK" launch --run-as "$ME_UID" --manifest "$T/game/game.json" -- "$GAME" game --dlopen-stdin
start AC2 6 -- sudo env XDG_DATA_HOME="$T/xdg-me" "$CTL" --socket "$SOCK" launch --run-as "$ME_UID" \
  --join "$G2_SESSION" -- "$AC" game --dlopen-stdin
DATA="$(ctl status "$G2_SESSION" | jq -r --argjson p "$AC2_PID" '.ok.status.session.members[] | select(.pid==$p) | .sandbox.data_dir')"
echo "      game pid=$G2_PID session=$G2_SESSION; anti-cheat pid=$AC2_PID data=$DATA"
check "its data directory is \$XDG_DATA_HOME/fairplay/<signer fingerprint>" \
  test "$DATA" = "$T/xdg-me/fairplay/$VENDOR_DIR"
check "created as you, mode 0700" test "$(stat -c '%u %a' "$DATA" 2>/dev/null)" = "$ME_UID 700"

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
