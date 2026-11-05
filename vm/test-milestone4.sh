#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2024
# (SC2016: $names in single quotes are jq variables. SC2024: output from
# sudo commands is meant to land in files we own.)
# Milestone 4 exit test: fairplayd serves the four calls of the design doc's
# vendor-facing API, and a mock vendor client sees each cheatsim attempt in
# the violation stream. Run inside the VM, as your normal user (not root),
# from the repo root:  ./vm/test-milestone4.sh
#
# Needs sudo, BPF LSM (vm/check-milestone1.sh), bpftool, jq, python3 and
# setpriv. Builds what it uses, starts its own fairplayd on $M4_SOCKET, and
# on exit stops it, kills what it launched and deletes everything it made
# (including the fairplay-launcher group, if it had to create it).
#
# Cast:
#   launcher  you, plus the fairplay-launcher group (via setpriv; your
#             account isn't changed). Starts the game and the anti-cheat.
#   manifest  game.json, signed with a throwaway key (milestone 9): names
#             cheatsim as the launch executable, and python3 and a copy of
#             cheatsim (vendor/cheatsim) as anti_cheat readers.
#   game      `cheatsim game`, launched protected; runs as you.
#   vendor    a mock anti-cheat in Python, speaking raw JSON to the socket,
#             joined to the game's session as its anti_cheat reader. It asks
#             session_status about "my session", then subscribes to
#             violations and prints each event.
#   attacker  `cheatsim attack`, run as root on purpose.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOCK="${M4_SOCKET:-/run/fairplayd-m4test.sock}"
GROUP=fairplay-launcher
OBJ="$REPO/crates/fairplay-ebpf/target/bpfel-unknown-none/release/fairplay"

[ "$(id -u)" -ne 0 ] || { echo "run as your normal user (it uses sudo where needed)" >&2; exit 2; }
for t in bpftool jq python3 setpriv; do
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

T="$(mktemp -d /tmp/fairplay-m4.XXXXXX)"
chmod 755 "$T"
DAEMON_PID=""; CREATED_GROUP=""
cleanup() {
  # Everything launched through the daemon is in a session we can list.
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
  sudo rm -rf "$T"
}
trap cleanup EXIT

# Is <pid> a key in the PROTECTED map? Keys are u32 tgids, little-endian bytes.
in_protected() {
  local key
  key="$(printf '"0x%02x","0x%02x","0x%02x","0x%02x"' $(($1 & 255)) $((($1 >> 8) & 255)) $((($1 >> 16) & 255)) $((($1 >> 24) & 255)))"
  sudo "$BPFTOOL" -j map dump name PROTECTED 2>/dev/null | tr -d ' \n' | grep -q "\"key\":\[$key\]"
}

# Run a command as you plus the launcher group.
as_launcher() {
  sudo setpriv --reuid="$ME_UID" --regid="$ME_GID" --groups="$ME_GROUPS,$LAUNCHER_GID" -- \
    env HOME="$HOME" PATH="$PATH" FAIRPLAYD_SOCKET="$SOCK" XDG_DATA_HOME="$T/xdg" "$@"
}

# Wait up to ~10s for a file to match a pattern.
wait_for() { for _ in $(seq 100); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

step "build"
if [ -z "${M4_SKIP_BUILD:-}" ]; then
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
mkdir -p "$T/vendor" && cp "$CHEATSIM" "$T/vendor/cheatsim"
"$CTL" manifest keygen --out "$T/vendor.key" >/dev/null &&
  "$CTL" manifest new --key "$T/vendor.key" --name "M4 Test Game" --launch "$CHEATSIM" \
    --anti-cheat "$(readlink -f "$(command -v python3)")" --anti-cheat "$T/vendor/cheatsim" \
    --out "$T/game.json" >/dev/null || exit 2
MANIFEST="$T/game.json"

step "start fairplayd on $SOCK"
if ! getent group "$GROUP" >/dev/null; then
  sudo groupadd --system "$GROUP" && CREATED_GROUP=1
fi
LAUNCHER_GID="$(getent group "$GROUP" | cut -d: -f3)"
if sudo "$BPFTOOL" map show name PROTECTED 2>/dev/null | grep -q .; then
  echo "note: another fairplay program is loaded; map checks look at every PROTECTED map"
fi
sudo "$T/bin/fairplayd" --obj "$OBJ" --socket "$SOCK" >"$T/daemon.out" 2>"$T/daemon.err" &
DAEMON_PID=$!
for _ in $(seq 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "fairplayd did not start:"; indent <"$T/daemon.err"; exit 2; }
indent <"$T/daemon.err"

step "launch_protected: launchers only, never root by default"
"$CTL" launch --no-stdio --manifest "$MANIFEST" -- "$CHEATSIM" game >"$T/plain.out" 2>/dev/null
check "a user outside $GROUP is refused (forbidden)" \
  jqt '.error.code=="forbidden"' "$T/plain.out"
sudo FAIRPLAYD_SOCKET="$SOCK" "$CTL" launch --no-stdio --manifest "$MANIFEST" -- "$CHEATSIM" game >"$T/root.out" 2>/dev/null
check "root without --run-as is refused (bad_request)" \
  jqt '.error.code=="bad_request"' "$T/root.out"

step "launch the game as the launcher"
as_launcher "$CTL" launch --manifest "$MANIFEST" -- "$CHEATSIM" game >"$T/game.out" 2>&1
wait_for "$T/game.out" '^pid=' || { bad "game started"; indent <"$T/game.out"; exit 1; }
SESSION="$(grep '^{' "$T/game.out" | jq -r '.ok.launched.session')"
GPID="$(grep '^{' "$T/game.out" | jq -r '.ok.launched.pid')"
ADDR="$(sed -n 's/^pid=[0-9]* addr=//p' "$T/game.out")"
echo "      session=$SESSION pid=$GPID addr=$ADDR"
check "the pid fairplayd registered is the pid that runs the game" \
  grep -q "^pid=$GPID " "$T/game.out"
check "the game's pid is in PROTECTED" in_protected "$GPID"
check "the game runs as you (uid $ME_UID), not root" \
  test "$(awk '/^Uid:/{print $2 $3 $4 $5}' "/proc/$GPID/status")" = "$ME_UID$ME_UID$ME_UID$ME_UID"
check_not "the game doesn't keep the launcher group" \
  grep -qE "^Groups:.*\\b$LAUNCHER_GID\\b" "/proc/$GPID/status"
check "the game has no_new_privs set" grep -q '^NoNewPrivs:[[:space:]]*1' "/proc/$GPID/status"

step "mock vendor joins the game's session as its anti_cheat reader and subscribes"
# In the vendor's install directory: the anti-cheat is sandboxed (milestone 9,
# part B) and sees only that, the game's, its data directory and the socket.
cat >"$T/vendor/vendor.py" <<'EOF'
# A stand-in anti-cheat client: plain sockets and JSON, no fairplay code.
import json, os, socket, sys
want = int(sys.argv[1])
s = socket.socket(socket.AF_UNIX)
s.connect(os.environ["FAIRPLAYD_SOCKET"])
f = s.makefile("rw")
def call(req):
    f.write(json.dumps(req) + "\n"); f.flush()
    return json.loads(f.readline())
print("status", json.dumps(call({"op": "session_status"})), flush=True)
print("subscribe", json.dumps(call({"op": "violations"})), flush=True)
seen = 0
while seen < want:
    msg = json.loads(f.readline())
    print("event", json.dumps(msg), flush=True)
    seen += "violation" in msg.get("event", {})
EOF
as_launcher "$CTL" launch --join "$SESSION" --install-dir "$T/vendor" -- \
  python3 -I "$T/vendor/vendor.py" 3 >"$T/vendor.out" 2>&1
wait_for "$T/vendor.out" '^subscribe' || { bad "vendor subscribed"; indent <"$T/vendor.out"; }
VPID="$(grep '^{' "$T/vendor.out" | jq -r '.ok.launched.pid')"
VSTATUS="$(sed -n 's/^status //p' "$T/vendor.out")"
check "vendor's pid is in PROTECTED too" in_protected "$VPID"
check "session_status (no session given) finds the vendor's own session, protected" \
  jqt --argjson s "$SESSION" '.ok.status.protected and .ok.status.session.session==$s' <<<"$VSTATUS"
check "violations (no session given) subscribes to that session" \
  jqt --argjson s "$SESSION" '.ok.subscribed.session==$s' <(sed -n 's/^subscribe //p' "$T/vendor.out")

step "attack the game as root"
sudo "$CHEATSIM" attack --pid "$GPID" --addr "$ADDR" | tee "$T/attack.out" | indent
check "0/3 paths leaked" grep -q '^0/3 paths leaked' "$T/attack.out"

step "the vendor's stream"
for _ in $(seq 100); do kill -0 "$VPID" 2>/dev/null || break; sleep 0.1; done
sed -n 's/^event //p' "$T/vendor.out" >"$T/events.jsonl"
jq -c '.event.violation | {caller, comm, exe, exe_path, hook, target}' "$T/events.jsonl" | indent
check "vendor received exactly 3 violation events" \
  test "$(jq -s '[.[] | select(.event.violation)] | length' "$T/events.jsonl")" -eq 3
check "each names the process, the executable and the hook" \
  jqt -s --argjson s "$SESSION" --argjson g "$GPID" 'length == 3 and all(.[].event.violation;
    .session==$s and .target==$g and .caller > 0 and .comm=="cheatsim" and .exe=="cheatsim"
    and .hook=="ptrace_access_check")' "$T/events.jsonl"
check "fairplayd printed 3 DENIED lines for the game" \
  test "$(grep -c "^DENIED .*target=$GPID " "$T/daemon.out")" -eq 3

step "session_status"
"$CTL" status "$SESSION" >"$T/status.json"
jq -c '.ok.status | {protected, lockdown, virtual_input_devices, game: .session.game, members: [.session.members[].pid], violations: .session.violations}' "$T/status.json" | indent
check "protected, game running, 3 violations, vendor listed as a member" \
  jqt --argjson g "$GPID" --argjson v "$VPID" '.ok.status | .protected and .session.game.pid==$g
    and .session.game.state=="running" and .session.violations==3
    and any(.session.members[]; .pid==$v)' "$T/status.json"
check "reports lockdown state and virtual input devices" \
  jqt '.ok.status | (.lockdown|type)=="string" and (.virtual_input_devices|type)=="array"' "$T/status.json"
sudo -u nobody "$CTL" --socket "$SOCK" status "$SESSION" >"$T/nobody.out" 2>/dev/null
check "another user can't see the session (not_found)" \
  jqt '.error.code=="not_found"' "$T/nobody.out"

step "the anti_cheat reader may read the game (the anti-cheat's privilege)"
sudo FAIRPLAYD_SOCKET="$SOCK" XDG_DATA_HOME="$T/xdg-root" "$CTL" launch --run-as 0 --join "$SESSION" -- \
  "$T/vendor/cheatsim" attack --pid "$GPID" --addr "$ADDR" >"$T/member.out" 2>&1
wait_for "$T/member.out" 'paths leaked'
grep -E 'LEAKED|BLOCKED|paths' "$T/member.out" | indent
# The game runs as you and this anti-cheat as root, which keeps only
# CAP_SYS_PTRACE in its sandbox: not CAP_DAC_OVERRIDE, which opening your
# game's mode-0600 /proc/<pid>/mem as another user would take.
check "the manifest's anti_cheat reader reads the game (process_vm_readv; ptrace is off in its sandbox)" \
  grep -q '^LEAKED  process_vm_readv' "$T/member.out"
check "a root anti-cheat can't open another user's /proc/<pid>/mem (no CAP_DAC_OVERRIDE in the sandbox)" \
  grep -q '^BLOCKED /proc/<pid>/mem: open: Permission denied' "$T/member.out"
sudo FAIRPLAYD_SOCKET="$SOCK" XDG_DATA_HOME="$T/xdg-root" "$CTL" launch --no-stdio --run-as 0 --join "$SESSION" -- \
  "$CHEATSIM" attack --pid "$GPID" --addr "$ADDR" >"$T/unnamed.out" 2>/dev/null
check "a program the manifest doesn't name can't join (forbidden)" \
  jqt '.error.code=="forbidden"' "$T/unnamed.out"

step "attest"
"$CTL" attest --nonce 00ff11 >"$T/attest.out" 2>/dev/null
indent <"$T/attest.out"
check "attest says unavailable (no TPM) and echoes the nonce" \
  jqt '.error.code=="unavailable" and .error.nonce=="00ff11"' "$T/attest.out"

step "the game exits"
kill "$GPID"
for _ in $(seq 50); do
  "$CTL" status "$SESSION" | jq -e '.ok.status.session.game.state=="exited"' >/dev/null && break
  sleep 0.1
done
"$CTL" status "$SESSION" >"$T/status2.json"
jq -c '.ok.status | {protected, game: .session.game}' "$T/status2.json" | indent
check "session_status: not protected, game exited by signal 15" \
  jqt '.ok.status | (.protected|not) and .session.game.state=="exited" and .session.game.signal==15' "$T/status2.json"
check_not "the game's pid is gone from PROTECTED" in_protected "$GPID"
check "fairplayd logged the removal" grep -q "pid $GPID exited.*removed from PROTECTED" "$T/daemon.err"

step "stop fairplayd"
sudo kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
check "socket removed" test ! -e "$SOCK"
check_not "no fairplay program left attached" \
  sudo "$BPFTOOL" prog show name ptrace_access_check

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
