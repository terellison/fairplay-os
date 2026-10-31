#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2024
# (SC2016: $names in single quotes are jq variables. SC2024: output from
# sudo commands is meant to land in files we own.)
# Milestone 7 exit test: virtual input is reported with who made it. During
# a protected session, a uinput clicker (cheatsim, run as root) shows up in
# session_status with its executable, not allowlisted, and in the vendor's
# violation stream as a REPORTED (not denied) event; an allowlisted remapper
# (fairplayd --input-allow) shows as allowlisted and is never reported. A
# write into an existing /dev/input/event* node and a uhid device are
# reported the same way. A session launched with block_virtual_input makes
# the kernel refuse, while it runs, non-allowlisted creation and input
# through virtual devices made earlier (a clicker started before the match
# goes silent, then clicks again after; a uhid fd written to before the match
# still can't create its device), while an allowlisted clicker keeps
# clicking. With no session running, nothing is reported. Run inside the VM, as your normal
# user (not root), from the repo root:  ./vm/test-milestone7.sh
#
# Needs sudo, BPF LSM (vm/check-milestone1.sh), bpftool and jq, and the
# kernel's uinput driver (/dev/uinput; built in on Ubuntu). uhid is a module
# (`modprobe uhid`); on Ubuntu it ships in linux-modules-extra-$(uname -r).
# Without it the uhid steps print SKIP and the rest still runs. The evdev
# step writes one SYN_REPORT (a no-op event) into $M7_EVDEV (default: the
# first /dev/input/event* node). Builds what it uses, starts its own
# fairplayd on $M7_SOCKET, and on exit stops it, kills everything it started
# and deletes everything it made.
#
# Cast (all under one temp dir):
#   bin/cheatsim     the cheat: `clicker`, `uhid`, `inject`, run as root
#   tools/remapper   a copy of cheatsim, allowlisted with --input-allow: a
#                    remapper or accessibility tool (same code, other inode)
#   game/cheatsim    `cheatsim game`, launched protected as you
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOCK="${M7_SOCKET:-/run/fairplayd-m7test.sock}"
OBJ="$REPO/crates/fairplay-ebpf/target/bpfel-unknown-none/release/fairplay"

[ "$(id -u)" -ne 0 ] || { echo "run as your normal user (it uses sudo where needed)" >&2; exit 2; }
for t in bpftool jq; do
  command -v "$t" >/dev/null || [ -x "/usr/sbin/$t" ] || { echo "$t not found" >&2; exit 2; }
done
BPFTOOL="$(command -v bpftool || echo /usr/sbin/bpftool)"
ME_UID="$(id -u)"

pass=0; fail=0; skip=0
ok()   { echo "PASS  $1"; pass=$((pass+1)); }
bad()  { echo "FAIL  $1"; fail=$((fail+1)); }
skip() { echo "SKIP  $1"; skip=$((skip+1)); }
jqt()       { jq -e "$@" >/dev/null; }
check()     { local label="$1"; shift; if "$@"; then ok "$label"; else bad "$label"; fi; }
check_not() { local label="$1"; shift; if "$@"; then bad "$label"; else ok "$label"; fi; }
step() { echo; echo "== $1"; }
indent() { sed 's/^/      /'; }

T="$(mktemp -d /tmp/fairplay-m7.XXXXXX)"
chmod 755 "$T"
DAEMON_PID=""; STREAM_PID=""
# Everything we start as root runs one of these two programs.
ours() { sudo pkill -f "^$T/(bin/cheatsim|tools/remapper) (clicker|uhid|inject)" 2>/dev/null; }
cleanup() {
  exec 4>&-
  ours
  [ -n "$STREAM_PID" ] && sudo kill "$STREAM_PID" 2>/dev/null
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

# Wait up to ~10s for a file to match a pattern.
wait_for() { for _ in $(seq 100); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

# run <tag> <program> <args...>: start it as root in the background, output
# in $T/<tag>.out, and wait for its first CREATED / BLOCKED / INJECTED line.
run() {
  local tag="$1"; shift
  sudo "$@" >"$T/$tag.out" 2>&1 &
  wait_for "$T/$tag.out" '^(CREATED|CREATE-BLOCKED|INJECTED|INJECT-BLOCKED)'
  head -1 "$T/$tag.out" | indent
}

# fairplayd has handled the kernel's record of <name> once one of its lines
# names it: a REPORTED/DENIED line on stdout or a "not reported" one on stderr.
handled() { wait_for "$T/daemon.out" "file=$1\$" || wait_for "$T/daemon.err" "file=$1 not reported"; }

status() { sudo "$CTL" --socket "$SOCK" status "$1" >"$T/status.json"; }
# device <name>: its session_status entry (compact JSON), or nothing.
device() { jq -c --arg n "$1" '.ok.status.virtual_input_devices[] | select(.name==$n)' "$T/status.json"; }

step "build"
if [ -z "${M7_SKIP_BUILD:-}" ]; then
  (cd "$REPO/crates/fairplay-ebpf" &&
    { [ -s src/vmlinux.rs ] || aya-tool generate task_struct > src/vmlinux.rs; } &&
    cargo build --release -q) || exit 2
  (cd "$REPO" && cargo build --release -q -p fairplayd -p fairplay-api -p cheatsim) || exit 2
fi
mkdir -p "$T/bin" "$T/tools" "$T/game"
cp "$REPO"/target/release/{fairplayd,fairplayctl,cheatsim} "$T/bin/"
cp "$REPO/target/release/cheatsim" "$T/tools/remapper"
cp "$REPO/target/release/cheatsim" "$T/game/"
CTL="$T/bin/fairplayctl"; CHEAT="$T/bin/cheatsim"; REMAP="$T/tools/remapper"
export FAIRPLAYD_SOCKET="$SOCK"
# Milestone 9: fairplayd launches only what a signed manifest names.
"$CTL" manifest keygen --out "$T/vendor.key" >/dev/null &&
  "$CTL" manifest new --key "$T/vendor.key" --name "M7 Test Game" --launch "$T/game/cheatsim" \
    --out "$T/game/game.json" >/dev/null || exit 2

step "input drivers"
sudo modprobe uinput 2>/dev/null   # built in on Ubuntu; a module elsewhere
check "/dev/uinput exists" test -c /dev/uinput || exit 2
HAVE_UHID=1
if ! { sudo modprobe uhid 2>/dev/null; test -c /dev/uhid; }; then
  HAVE_UHID=0
  echo "      /dev/uhid missing and 'modprobe uhid' failed (Ubuntu: install linux-modules-extra-$(uname -r)); uhid steps skipped"
fi
EVDEV="${M7_EVDEV:-$(find /dev/input -maxdepth 1 -name 'event*' -print -quit)}"
[ -c "$EVDEV" ] || { echo "no /dev/input/event* node to write to" >&2; exit 2; }
echo "      evdev node for the write test: $EVDEV"
EVNAME="$(basename "$EVDEV")"

step "start fairplayd on $SOCK; $REMAP is allowlisted"
sudo "$T/bin/fairplayd" --obj "$OBJ" --socket "$SOCK" --input-allow "$REMAP" \
  >"$T/daemon.out" 2>"$T/daemon.err" &
DAEMON_PID=$!
for _ in $(seq 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "fairplayd did not start:"; indent <"$T/daemon.err"; exit 2; }
indent <"$T/daemon.err"
check "1 allowlisted input executable" grep -q "virtual input: .* 1 allowlisted executable" "$T/daemon.err"
check_not "every input hook attached (no warning)" grep -q "warning: no" "$T/daemon.err"

step "no session: a clicker is recorded but not reported"
run idle "$CHEAT" clicker --name "m7 idle"
check "CREATED" grep -q "^CREATED uinput m7 idle$" "$T/idle.out"
check "fairplayd saw it: 'not reported (no session running)'" handled "m7 idle"
check_not "no REPORTED or DENIED line" grep -qE '^(REPORTED|DENIED)' "$T/daemon.out"
sudo "$CTL" --socket "$SOCK" status >"$T/status.json"
device "m7 idle" | indent
check "session_status still says who made it: cheatsim, not allowlisted" \
  jqt --arg n "m7 idle" '.ok.status.virtual_input_devices[] | select(.name==$n)
    | .kind=="uinput" and .created_by.exe=="cheatsim" and .allowlisted==false' "$T/status.json"
sudo pkill -f "^$CHEAT clicker --name m7 idle"

step "launch the game protected; subscribe to its violations"
sudo "$CTL" --socket "$SOCK" launch --no-stdio --run-as "$ME_UID" --manifest "$T/game/game.json" -- "$T/game/cheatsim" game >"$T/game.out" 2>&1
SESSION="$(jq -r '.ok.launched.session' "$T/game.out")"
GPID="$(jq -r '.ok.launched.pid' "$T/game.out")"
[ "$SESSION" != null ] || { bad "game launched"; indent <"$T/game.out"; exit 1; }
echo "      session=$SESSION pid=$GPID"
sudo "$CTL" --socket "$SOCK" violations "$SESSION" >"$T/events.jsonl" 2>&1 &
STREAM_PID=$!
wait_for "$T/events.jsonl" subscribed || bad "vendor stream subscribed"

step "(a) a uinput clicker started mid-match"
run clicker "$CHEAT" clicker --name "m7 clicker"
check "CREATED and clicked" wait_for "$T/clicker.out" "^CLICKED 3$"
check "REPORTED line: hook=uinput_create, exe cheatsim, device name" \
  wait_for "$T/daemon.out" "^REPORTED caller=[0-9]+ comm=cheatsim exe=$CHEAT target=0 hook=uinput_create .*file=m7 clicker$"
status "$SESSION"; device "m7 clicker" | indent
check "session_status lists it: kind uinput, created by cheatsim ($CHEAT), not allowlisted" \
  jqt --arg n "m7 clicker" --arg p "$CHEAT" '.ok.status.virtual_input_devices[] | select(.name==$n)
    | .kind=="uinput" and .device!="" and .created_by.exe=="cheatsim" and .created_by.exe_path==$p
      and .allowlisted==false and (.ambiguous|not)' "$T/status.json"
CLICKER_PID="$(device "m7 clicker" | jq -r .created_by.pid)"

step "(b) the allowlisted remapper"
run remap "$REMAP" clicker --name "m7 remapper"
check "CREATED" grep -q "^CREATED uinput m7 remapper$" "$T/remap.out"
check "fairplayd: 'not reported (allowlisted)'" wait_for "$T/daemon.err" "file=m7 remapper not reported \(allowlisted\)"
check_not "no REPORTED line for it" grep -q "exe=$REMAP" "$T/daemon.out"
status "$SESSION"; device "m7 remapper" | indent
check "session_status lists it: created by remapper, allowlisted" \
  jqt --arg n "m7 remapper" '.ok.status.virtual_input_devices[] | select(.name==$n)
    | .created_by.exe=="remapper" and .allowlisted==true' "$T/status.json"

step "(c) an event written into $EVDEV"
run inject "$CHEAT" inject --device "$EVDEV"
check "INJECTED" grep -q "^INJECTED $EVDEV$" "$T/inject.out"
check "REPORTED line: hook=evdev_write file=$EVNAME" \
  wait_for "$T/daemon.out" "^REPORTED .*exe=$CHEAT target=0 hook=evdev_write .*file=$EVNAME$"

step "(d) a uhid device"
if [ "$HAVE_UHID" = 1 ]; then
  run uhid "$CHEAT" uhid --name "m7 uhid"
  check "CREATED" grep -q "^CREATED uhid m7 uhid$" "$T/uhid.out"
  check "and moved (input through its own fd)" wait_for "$T/uhid.out" "^MOVED 3$"
  check "REPORTED line: hook=uhid_create file=uhid" \
    wait_for "$T/daemon.out" "^REPORTED .*exe=$CHEAT target=0 hook=uhid_create .*file=uhid$"
  for _ in $(seq 30); do status "$SESSION"; [ -n "$(device "m7 uhid")" ] && break; sleep 0.1; done
  device "m7 uhid" | indent
  check "session_status lists it: kind uhid, created by cheatsim, not allowlisted" \
    jqt --arg n "m7 uhid" '.ok.status.virtual_input_devices[] | select(.name==$n)
      | .kind=="uhid" and .created_by.exe=="cheatsim" and .allowlisted==false' "$T/status.json"
else
  skip "uhid (no /dev/uhid)"
fi

step "(e) a second session asks for block_virtual_input"
# Made before it, still sending input when it starts: a non-allowlisted
# clicker (must go silent) and an allowlisted one (must keep clicking).
run pre "$CHEAT" clicker --name "m7 pre" --clicks 100000 --interval-ms 50
check "a non-allowlisted clicker, made before blocking" grep -q "^CREATED uinput m7 pre$" "$T/pre.out"
run live "$REMAP" clicker --name "m7 remapper live" --clicks 100000 --interval-ms 50
check "an allowlisted clicker, made before blocking" grep -q "^CREATED uinput m7 remapper live$" "$T/live.out"
if [ "$HAVE_UHID" = 1 ]; then
  # The ordering trick: write something harmless to /dev/uhid before the
  # match, create the device during it.
  mkfifo "$T/uhidcmd"
  exec 4<>"$T/uhidcmd"
  sudo "$CHEAT" uhid --name "m7 uhid late" --bogus-first --wait-stdin <"$T/uhidcmd" >"$T/late-uhid.out" 2>&1 &
  check "a uhid fd written to (bogus event) before blocking" wait_for "$T/late-uhid.out" "^BOGUS-WRITTEN"
fi
sudo "$CTL" --socket "$SOCK" launch --no-stdio --block-virtual-input --run-as "$ME_UID" --manifest "$T/game/game.json" -- "$T/game/cheatsim" game >"$T/game2.out" 2>&1
SESSION2="$(jq -r '.ok.launched.session' "$T/game2.out")"
GPID2="$(jq -r '.ok.launched.pid' "$T/game2.out")"
echo "      session=$SESSION2 pid=$GPID2"
check "fairplayd: blocking on" grep -q "is now denied" "$T/daemon.err"
check "the clicker made before blocking can't click: EPERM on write" \
  wait_for "$T/pre.out" "^CLICK-BLOCKED: Operation not permitted"
check "DENIED line: hook=uinput_write file=uinput" \
  wait_for "$T/daemon.out" "^DENIED .*exe=($CHEAT|cheatsim) target=0 hook=uinput_write .*file=uinput$"
run blocked "$CHEAT" clicker --name "m7 blocked"
check "a new clicker can't create its device: EPERM" \
  grep -q "^CREATE-BLOCKED uinput m7 blocked: UI_DEV_CREATE: Operation not permitted" "$T/blocked.out"
check "DENIED line: hook=uinput_create file=m7 blocked" \
  wait_for "$T/daemon.out" "^DENIED .*exe=($CHEAT|cheatsim) target=0 hook=uinput_create .*file=m7 blocked$"
run remap2 "$REMAP" clicker --name "m7 remapper 2"
check "the allowlisted remapper can still create one" grep -q "^CREATED uinput m7 remapper 2$" "$T/remap2.out"
check "... and click with it" wait_for "$T/remap2.out" "^CLICKED 3$"
run inject2 "$CHEAT" inject --device "$EVDEV"
check "the evdev write is refused: EPERM" grep -q "^INJECT-BLOCKED $EVDEV: Operation not permitted" "$T/inject2.out"
check "DENIED line: hook=evdev_write" \
  wait_for "$T/daemon.out" "^DENIED .*exe=($CHEAT|cheatsim) target=0 hook=evdev_write .*file=$EVNAME$"
if [ "$HAVE_UHID" = 1 ]; then
  run uhid2 "$CHEAT" uhid --name "m7 uhid blocked"
  check "a uhid device can't be created: EPERM" \
    grep -q "^CREATE-BLOCKED uhid m7 uhid blocked: UHID_CREATE2: Operation not permitted" "$T/uhid2.out"
  echo go >&4
  check "nor one whose fd was written to before blocking: EPERM" \
    wait_for "$T/late-uhid.out" "^CREATE-BLOCKED uhid m7 uhid late: UHID_CREATE2: Operation not permitted"
  exec 4>&-
else
  skip "uhid blocking (no /dev/uhid)"
fi
sleep 1   # a few more refused clicks from m7 pre
check "the pre-made clicker was reported once, not once per click" \
  test "$(grep -c '^DENIED .*hook=uinput_write' "$T/daemon.out")" -eq 1
check_not "the allowlisted clicker made before blocking was never refused" grep -q "CLICK-BLOCKED" "$T/live.out"
status "$SESSION"
check "the clicker made before blocking is still listed" test -n "$(device "m7 pre")"
sudo "$CTL" --socket "$SOCK" status "$SESSION2" >"$T/status2.json"
check "the blocking session has its own violations (the attempts above)" \
  jqt '.ok.status.session.violations >= 3' "$T/status2.json"

step "(f) the blocking session ends: reported, not denied, again"
kill "$GPID2"
check "fairplayd: blocking off" wait_for "$T/daemon.err" "is now reported only"
check "the pre-made clicker clicks again" wait_for "$T/pre.out" "^CLICK-RESUMED$"
run after "$CHEAT" clicker --name "m7 after"
check "CREATED" grep -q "^CREATED uinput m7 after$" "$T/after.out"
check "REPORTED line" wait_for "$T/daemon.out" "^REPORTED .*hook=uinput_create .*file=m7 after$"

step "the vendor's stream for session $SESSION"
sleep 0.3
grep '"violation"' "$T/events.jsonl" >"$T/v.jsonl"
jq -c '.event.violation | {caller, exe, target, hook, outcome, file}' "$T/v.jsonl" | indent
# Order across processes depends on timing, so compare as sorted lists.
WANT='[["uinput_create","reported","m7 clicker"],["evdev_write","reported",$ev],
       ["uinput_create","reported","m7 pre"],
       ["uinput_write","denied","uinput"],["uinput_create","denied","m7 blocked"],["evdev_write","denied",$ev],
       ["uinput_create","reported","m7 after"]]'
if [ "$HAVE_UHID" = 1 ]; then
  WANT="$WANT"' + [["uhid_create","reported","uhid"],["uhid_create","reported","uhid"],
                   ["uhid_create","denied","uhid"],["uhid_create","denied","uhid"]]'
fi
check "one event per attempt (or per refused fd), each marked reported or denied" \
  jqt -s --arg ev "$EVNAME" "([.[].event.violation | [.hook, .outcome, .file]] | sort) == ($WANT | sort)" "$T/v.jsonl"
check "all from cheatsim, against no process (target 0), filed under session $SESSION" \
  jqt -s --argjson s "$SESSION" 'all(.[].event.violation; .exe=="cheatsim" and .target==0 and .session==$s)' "$T/v.jsonl"
check "the clicker's event names the process session_status named ($CLICKER_PID)" \
  jqt -s --argjson p "$CLICKER_PID" '.[0].event.violation.caller==$p' "$T/v.jsonl"
check_not "nothing from the remapper" grep -q remapper "$T/v.jsonl"
check_not "nothing from before the session (m7 idle)" grep -q "m7 idle" "$T/v.jsonl"

step "no session running: nothing is reported"
kill "$GPID"
for _ in $(seq 50); do sudo "$CTL" --socket "$SOCK" status "$SESSION" | jqt '.ok.status.protected==false' && break; sleep 0.1; done
lines_before="$(grep -cE '^(REPORTED|DENIED)' "$T/daemon.out")"
run late "$CHEAT" clicker --name "m7 late"
check "CREATED" grep -q "^CREATED uinput m7 late$" "$T/late.out"
check "fairplayd: 'not reported (no session running)'" \
  wait_for "$T/daemon.err" "file=m7 late not reported \(no session running\)"
check "no new REPORTED or DENIED lines" test "$(grep -cE '^(REPORTED|DENIED)' "$T/daemon.out")" -eq "$lines_before"

step "stop fairplayd"
ours
sudo kill "$STREAM_PID" 2>/dev/null; STREAM_PID=""
sudo kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
check "socket removed" test ! -e "$SOCK"
for p in file_ioctl file_ioctl_compat file_permission; do
  check_not "no $p program left attached" sudo "$BPFTOOL" prog show name "$p"
done
run free "$CHEAT" clicker --name "m7 free" --hold 0
check "without fairplayd, uinput works as usual" grep -q "^CREATED uinput m7 free$" "$T/free.out"

echo
echo "$pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
