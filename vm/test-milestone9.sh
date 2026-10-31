#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2024
# (SC2016: $names in single quotes are jq variables. SC2024: output from
# sudo commands is meant to land in files we own.)
# Milestone 9 exit test, part A: the game manifest, and protected members vs
# readers. fairplayd launches only what a signed manifest names, protected
# processes can't read each other, and only the readers the manifest names
# (the vendor's anti-cheat, runtime helpers like wineserver) may read the
# game. Run inside the VM, as your normal user (not root), from the repo
# root, under the shared VM lock:
#   flock /run/lock/fairplay-vm-tests ./vm/test-milestone9.sh
#
# Needs sudo, BPF LSM (vm/check-milestone1.sh), bpftool, jq, python3,
# setpriv and sha256sum. Builds what it uses, starts its own fairplayd on
# $M9_SOCKET, and on exit stops it, kills what it started and deletes
# everything it made (including the fairplay-launcher group, if it had to
# create it).
#
# Cast (all files under one temp dir):
#   vendor.key  the game vendor's signing key; other.key, a cheater's.
#   game/       the install directory: cheatsim (the game), rt-helper (a copy
#               the manifest names as a runtime_helper reader, like
#               wineserver), unnamed-helper (the same bytes, not named),
#               wrapper.py, and game.json (+ .sig), signed by vendor.key.
#   vendor/     anticheat, a copy of cheatsim the manifest names as its
#               anti_cheat reader (the mock vendor).
#   wrap.json   a manifest the cheater signed, whose launch executable is
#               python3: the wrapper attack.
#   launcher    root, running everything as root (--run-as 0) on purpose:
#               kernel ptrace rules (and Yama) let root through, so every
#               block is the LSM's, and prints a DENIED line. The refusals in
#               (f) come from you plus the fairplay-launcher group (setpriv),
#               so fairplayd opens the files with your permissions.
#   attacker    every read is `cheatsim attack`, whoever runs it.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOCK="${M9_SOCKET:-/run/fairplayd-m9test.sock}"
GROUP=fairplay-launcher
OBJ="$REPO/crates/fairplay-ebpf/target/bpfel-unknown-none/release/fairplay"

[ "$(id -u)" -ne 0 ] || { echo "run as your normal user (it uses sudo where needed)" >&2; exit 2; }
for t in bpftool jq python3 setpriv sha256sum; do
  command -v "$t" >/dev/null || [ -x "/usr/sbin/$t" ] || { echo "$t not found" >&2; exit 2; }
done
BPFTOOL="$(command -v bpftool || echo /usr/sbin/bpftool)"
ME_UID="$(id -u)"; ME_GID="$(id -g)"; ME_GROUPS="$(id -G | tr ' ' ,)"
PYTHON="$(readlink -f "$(command -v python3)")"

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
jqt()       { jq -e "$@" >/dev/null; }
check()     { local label="$1"; shift; if "$@"; then ok "$label"; else bad "$label"; fi; }
check_not() { local label="$1"; shift; if "$@"; then bad "$label"; else ok "$label"; fi; }
step() { echo; echo "== $1"; }
indent() { sed 's/^/      /'; }

T="$(mktemp -d /tmp/fairplay-m9.XXXXXX)"
chmod 755 "$T"
DAEMON_PID=""; CREATED_GROUP=""; KILL_PIDS=()
cleanup() {
  exec 3>&-
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
  [ -n "$CREATED_GROUP" ] && sudo groupdel "$GROUP"
  sudo rm -f "$SOCK"
  rm -rf "$T"
}
trap cleanup EXIT

# Run a command as you plus the launcher group.
as_launcher() {
  sudo setpriv --reuid="$ME_UID" --regid="$ME_GID" --groups="$ME_GROUPS,$LAUNCHER_GID" -- \
    env HOME="$HOME" PATH="$PATH" FAIRPLAYD_SOCKET="$SOCK" "$@"
}

# Wait up to ~10s for a file to match a pattern, or a command to succeed.
wait_for()   { for _ in $(seq 100); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
wait_until() { for _ in $(seq 100); do "$@" && return 0; sleep 0.1; done; return 1; }
denied() { grep -c "^DENIED .*target=$1 hook=ptrace_access_check" "$T/daemon.out"; }
denied_at_least() { [ "$(denied "$1")" -ge "$2" ]; }
# fairplayctl as root (launches, joins and status of root's sessions).
ctl() { sudo "$CTL" --socket "$SOCK" "$@"; }
sessions() { ctl list | jq '.ok.sessions | length'; }
reader_files() { sudo "$BPFTOOL" -j map dump name READER_FILES 2>/dev/null | jq length; }

# Ask the game (reading commands on fd 3) to do something; wait for its
# EXEC-/SPAWNED line, and print what the command added to game.out.
ask() {
  local before
  before="$(wc -l <"$T/game.out")"
  echo "$1" >&3
  for _ in $(seq 100); do
    tail -n +"$((before + 1))" "$T/game.out" | grep -qE '^(EXEC-|SPAWNED)' && break
    sleep 0.1
  done
  tail -n +"$((before + 1))" "$T/game.out" | tee "$T/last" | indent
}

step "build"
if [ -z "${M9_SKIP_BUILD:-}" ]; then
  (cd "$REPO/crates/fairplay-ebpf" &&
    { [ -s src/vmlinux.rs ] || aya-tool generate task_struct > src/vmlinux.rs; } &&
    cargo build --release -q) || exit 2
  (cd "$REPO" && cargo build --release -q -p fairplayd -p fairplay-api -p cheatsim) || exit 2
fi
mkdir -p "$T/bin" "$T/game" "$T/vendor"
cp "$REPO"/target/release/{fairplayd,fairplayctl,cheatsim} "$T/bin/"
for f in game/cheatsim game/rt-helper game/unnamed-helper vendor/anticheat; do
  cp "$REPO/target/release/cheatsim" "$T/$f"
done
CTL="$T/bin/fairplayctl"; CHEATSIM="$T/bin/cheatsim"; GAME="$T/game/cheatsim"
export FAIRPLAYD_SOCKET="$SOCK"

step "keys and manifests (fairplayctl manifest ...)"
"$CTL" manifest keygen --out "$T/vendor.key" >"$T/vendor.pub" || exit 2
"$CTL" manifest keygen --out "$T/other.key" >"$T/other.pub" || exit 2
VENDOR_FP="$(jq -r .fingerprint "$T/vendor.pub")"
OTHER_FP="$(jq -r .fingerprint "$T/other.pub")"
echo "      vendor key $VENDOR_FP"
echo "      cheater key $OTHER_FP"
(cd "$T/game" && "$CTL" manifest new --key "$T/vendor.key" --name "M9 Test Game" \
  --launch cheatsim --anti-cheat "$T/vendor/anticheat" --runtime-helper rt-helper \
  --out "$T/game/game.json") | indent
jq -c '{name, launch: [.launch[].path], readers: [.readers[] | [.role, .path]]}' "$T/game/game.json" | indent
check "the vendor's manifest verifies (signature and every file's hash)" \
  sh -c "'$CTL' manifest verify '$T/game/game.json' | jq -e '.signature==\"ok\" and (.file_problems|length)==0' >/dev/null"
cat >"$T/game/wrapper.py" <<'EOF'
# The wrapper attack: start the real game as a child, then read it, as the
# wrapper itself (the game's parent and the domain's launch root) and from a
# second child (the game's sibling).
import re, subprocess, sys
cheatsim = sys.argv[1]
game = subprocess.Popen([cheatsim, "game"], stdout=subprocess.PIPE, text=True)
pid, addr = re.match(r"pid=(\d+) addr=(0x[0-9a-f]+)", game.stdout.readline()).groups()
print(f"wrapper: game pid={pid} addr={addr}", flush=True)
try:
    with open(f"/proc/{pid}/mem", "rb") as f:
        f.seek(int(addr, 16))
        v = int.from_bytes(f.read(8), "little")
    print("WRAPPER-LEAKED" if v == 0x5EC2E71337C0DE11 else f"WRAPPER-READ {v:#x}", flush=True)
except OSError as e:
    print(f"WRAPPER-BLOCKED /proc/{pid}/mem: {e}", flush=True)
r = subprocess.run([cheatsim, "attack", "--pid", pid, "--addr", addr], capture_output=True, text=True)
print(r.stdout, end="", flush=True)
game.kill()
print("WRAPPER-DONE", flush=True)
EOF
"$CTL" manifest new --key "$T/other.key" --name "Not The Vendor" --launch "$PYTHON" \
  --out "$T/wrap.json" | indent

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
check "the exec tracing program (readers) is attached" \
  sh -c "sudo '$BPFTOOL' prog show name reader_exec | grep -q tracing"

step "control: the wrapper without fairplayd, as root"
sudo python3 -I "$T/game/wrapper.py" "$GAME" >"$T/plain-wrap.out" 2>&1
indent <"$T/plain-wrap.out"
check "unprotected, the wrapper reads the game it started, and so does its sibling (3/3)" \
  sh -c "grep -q '^WRAPPER-LEAKED' '$T/plain-wrap.out' && grep -q '^3/3 paths leaked' '$T/plain-wrap.out'"

step "(a) the wrapper attack: a cheater-signed manifest launches python3 wrapper.py"
ctl launch --run-as 0 --manifest "$T/wrap.json" --install-dir "$T/game" -- \
  python3 -I "$T/game/wrapper.py" "$GAME" >"$T/wrap.out" 2>&1
wait_for "$T/wrap.out" '^WRAPPER-DONE' || bad "the wrapper finished"
indent <"$T/wrap.out"
WSESSION="$(grep '^{' "$T/wrap.out" | jq -r '.ok.launched.session')"
WGAME="$(sed -n 's/^wrapper: game pid=\([0-9]*\) .*/\1/p' "$T/wrap.out")"
check "fairplayd launched it (the OS doesn't judge the signer)" test -n "$WSESSION" -a "$WSESSION" != null
check "the wrapper (the game's parent) can't read the game" grep -q '^WRAPPER-BLOCKED' "$T/wrap.out"
check "its sibling can't either: 0/3 paths leaked" grep -q '^0/3 paths leaked' "$T/wrap.out"
wait_until denied_at_least "$WGAME" 4
grep "^DENIED .*target=$WGAME " "$T/daemon.out" | indent
check "4 DENIED lines (the wrapper's /proc read, 3 from the sibling)" test "$(denied "$WGAME")" -eq 4
ctl status "$WSESSION" >"$T/wrap-status.json"
check "(g) session_status names the cheater's key as the signer, for the server to reject" \
  jqt --arg fp "$OTHER_FP" '.ok.status.session.manifest | .signer_fingerprint==$fp and .name=="Not The Vendor"' "$T/wrap-status.json"

step "launch the vendor's game; it takes commands on a pipe"
mkfifo "$T/cmd"
exec 3<>"$T/cmd"   # held open read-write, so neither side blocks or sees EOF
ctl launch --run-as 0 --manifest "$T/game/game.json" -- "$GAME" game --dlopen-stdin <"$T/cmd" >"$T/game.out" 2>&1
wait_for "$T/game.out" '^pid=' || { bad "game started"; indent <"$T/game.out"; indent <"$T/daemon.err"; exit 1; }
SESSION="$(grep '^{' "$T/game.out" | jq -r '.ok.launched.session')"
GPID="$(grep '^{' "$T/game.out" | jq -r '.ok.launched.pid')"
ADDR="$(sed -n "s/^pid=$GPID addr=//p" "$T/game.out")"
echo "      session=$SESSION pid=$GPID addr=$ADDR"
grep "session $SESSION: pid $GPID" "$T/daemon.err" | indent
check "fairplayd logged the manifest and its signer" \
  grep -q "session $SESSION: pid $GPID .*manifest \"M9 Test Game\" sha256 [0-9a-f]\\{64\\} signer $VENDOR_FP; 1 reader file(s)" "$T/daemon.err"
check "READER_FILES holds the runtime helper (1 entry)" test "$(reader_files)" -eq 1

step "(b) a protected child can't read its parent or its sibling"
ask "exec $GAME attack --pid $GPID --addr $ADDR"
check "child -> parent (the game): 0/3 paths leaked" grep -q '^0/3 paths leaked' "$T/last"
ask "spawn $GAME game"
SIB="$(sed -n 's/^SPAWNED \([0-9]*\) .*/\1/p' "$T/last")"
[ -n "$SIB" ] && KILL_PIDS+=("$SIB")
wait_for "$T/game.out" "^pid=$SIB " || bad "sibling started"
SADDR="$(sed -n "s/^pid=$SIB addr=//p" "$T/game.out")"
echo "      sibling pid=$SIB addr=$SADDR"
ask "exec $GAME attack --pid $SIB --addr $SADDR"
check "child -> sibling: 0/3 paths leaked" grep -q '^0/3 paths leaked' "$T/last"
wait_until denied_at_least "$SIB" 3
check "3 DENIED lines for each (parent $(denied "$GPID"), sibling $(denied "$SIB"))" \
  test "$(denied "$GPID")" -eq 3 -a "$(denied "$SIB")" -eq 3

step "(c) the vendor's anti-cheat joins as a reader and reads the game"
ctl launch --run-as 0 --join "$SESSION" -- "$T/vendor/anticheat" attack --pid "$GPID" --addr "$ADDR" >"$T/ac.out" 2>&1
wait_for "$T/ac.out" 'paths leaked'
indent <"$T/ac.out"
check "3/3 paths leaked: the reader can read the game" grep -q '^3/3 paths leaked' "$T/ac.out"
check "no new DENIED lines for the game" test "$(denied "$GPID")" -eq 3
check "READER_FILES gained the anti-cheat's file (2 entries)" test "$(reader_files)" -eq 2

step "(d) a helper the game execs: the named runtime_helper reads, an unnamed copy doesn't"
ask "exec $T/game/rt-helper attack --pid $GPID --addr $ADDR"
check "rt-helper (named runtime_helper): 3/3 paths leaked" grep -q '^3/3 paths leaked' "$T/last"
ask "exec $T/game/unnamed-helper attack --pid $GPID --addr $ADDR"
check "unnamed-helper (same bytes, not named): 0/3 paths leaked" grep -q '^0/3 paths leaked' "$T/last"
check "3 more DENIED lines, from unnamed-helper" \
  sh -c "[ $(denied "$GPID") -eq 6 ] && [ \$(grep -c '^DENIED .*comm=unnamed-helper .*target=$GPID ' '$T/daemon.out') -eq 3 ]"

step "(e) a binary the manifest doesn't name can't join"
before="$(ctl status "$SESSION" | jq '.ok.status.session.members | length')"
ctl launch --run-as 0 --no-stdio --join "$SESSION" -- "$CHEATSIM" attack --pid "$GPID" --addr "$ADDR" >"$T/join-bad.out" 2>/dev/null
indent <"$T/join-bad.out"
check "an unnamed binary: forbidden" jqt '.error.code=="forbidden"' "$T/join-bad.out"
ctl launch --run-as 0 --no-stdio --join "$SESSION" -- "$T/game/rt-helper" attack --pid "$GPID" --addr "$ADDR" >"$T/join-rt.out" 2>/dev/null
check "a runtime_helper (named, but not an anti_cheat reader): forbidden" jqt '.error.code=="forbidden"' "$T/join-rt.out"
check "nothing joined the session" \
  test "$(ctl status "$SESSION" | jq '.ok.status.session.members | length')" -eq "$before"

step "(f) bad manifests are refused, and nothing is launched (asked by you, a launcher)"
cp "$REPO/target/release/cheatsim" "$T/game/changed"
(cd "$T/game" && "$CTL" manifest new --key "$T/vendor.key" --name "Changed" --launch changed \
  --out "$T/game/changed.json") >/dev/null
printf 'x' >>"$T/game/changed"     # the exe changes after the vendor signed
sed 's/M9 Test Game/M9 Test Gamf/' "$T/game/game.json" >"$T/game/tampered.json"
cp "$T/game/game.json.sig" "$T/game/tampered.json.sig"
sed "s|$(jq -r .public_key "$T/vendor.pub")|$(jq -r .public_key "$T/other.pub")|" "$T/game/game.json" >"$T/game/wrongkey.json"
cp "$T/game/game.json.sig" "$T/game/wrongkey.json.sig"
n_before="$(sessions)"
for m in tampered wrongkey changed; do
  exe="$GAME"; [ "$m" = changed ] && exe="$T/game/changed"
  as_launcher "$CTL" launch --no-stdio --manifest "$T/game/$m.json" -- "$exe" game >"$T/$m.out" 2>/dev/null
  indent <"$T/$m.out"
done
check "a tampered manifest: forbidden (signature)" \
  jqt '.error.code=="forbidden" and (.error.message|test("signature"))' "$T/tampered.out"
check "a signature by another key: forbidden (signature)" \
  jqt '.error.code=="forbidden" and (.error.message|test("signature"))' "$T/wrongkey.out"
check "an exe whose hash doesn't match: forbidden (sha256)" \
  jqt '.error.code=="forbidden" and (.error.message|test("sha256"))' "$T/changed.out"
check "no session was created" test "$(sessions)" -eq "$n_before"
check_not "fairplayctl manifest verify also refuses the tampered one" \
  "$CTL" manifest verify "$T/game/tampered.json"

step "(g) session_status reports the manifest and its signer"
ctl status "$SESSION" >"$T/status.json"
jq -c '.ok.status.session.manifest' "$T/status.json" | indent
check "the vendor's key fingerprint, and the manifest's sha256" \
  jqt --arg fp "$VENDOR_FP" --arg sha "$(sha256sum "$T/game/game.json" | cut -d' ' -f1)" \
    '.ok.status.session.manifest | .signer_fingerprint==$fp and .sha256==$sha and .name=="M9 Test Game"' "$T/status.json"

step "(h) a manifest that asks for block_virtual_input gets it (milestone 7)"
(cd "$T/game" && "$CTL" manifest new --key "$T/vendor.key" --name "Strict" --launch cheatsim \
  --block-virtual-input --out "$T/game/strict.json") >/dev/null
ctl launch --no-stdio --run-as 0 --manifest "$T/game/strict.json" -- "$GAME" game >"$T/strict.out" 2>/dev/null
SPID="$(jq -r '.ok.launched.pid' "$T/strict.out")"
check "fairplayd blocks virtual input for that session" \
  grep -q "pid $SPID .*, blocking virtual input" "$T/daemon.err"
sudo kill "$SPID" 2>/dev/null

step "the game exits"
exec 3>&-
sudo kill "$GPID" "$SIB" 2>/dev/null
KILL_PIDS=()
no_reader_files() { [ "$(reader_files)" -eq 0 ]; }
wait_until no_reader_files
check "its READER_FILES entries are gone" test "$(reader_files)" -eq 0
check_not "no READERS entry is left" \
  sh -c "sudo '$BPFTOOL' -j map dump name READERS | jq -e 'length > 0' >/dev/null"

step "stop fairplayd"
sudo kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
check "socket removed" test ! -e "$SOCK"
any_loaded() {
  local n
  for n in reader_exec ptrace_access_check; do
    sudo "$BPFTOOL" prog show name "$n" 2>/dev/null | grep -q . && return 0
  done
  return 1
}
not() { ! "$@"; }
wait_until not any_loaded
check_not "no fairplay program left loaded" any_loaded

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
