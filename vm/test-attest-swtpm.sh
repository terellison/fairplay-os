#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2024
# (SC2016: $names in single quotes are jq variables. SC2024: output from
# sudo commands is meant to land in files we own.)
# Attestation end to end against a software TPM (milestone 10 groundwork):
# fairplayd answers `attest` with a TPM quote, and the server-side verifier
# (`fairplayctl verify-evidence`) accepts it, reads the boot mode from the
# mode PCR, and rejects a replayed nonce, a tampered PCR value, and a mode
# PCR that root extended after boot. The VM has no TPM, so the TPM is
# swtpm; the AK is trusted as reported (AK enrollment doesn't exist yet).
#
# Run inside the VM, as your normal user, from the repo root, under the
# shared lock (it loads fairplayd's BPF programs):
#   flock -o /run/lock/fairplay-vm-tests ./vm/test-attest-swtpm.sh
#
# Needs sudo, BPF LSM (vm/check-milestone1.sh), swtpm, tpm2-tools, jq,
# python3. Starts its own swtpm and fairplayd, and on exit stops both and
# deletes everything it made.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOCK="${ATTEST_SOCKET:-/run/fairplayd-attesttest.sock}"
OBJ="$REPO/crates/fairplay-ebpf/target/bpfel-unknown-none/release/fairplay"
# Must match fairplay_attest::MODE_PCR and mode_event (provisional).
MODE_PCR=13

[ "$(id -u)" -ne 0 ] || { echo "run as your normal user (it uses sudo where needed)" >&2; exit 2; }
for t in swtpm tpm2_pcrextend jq python3 sha256sum; do
  command -v "$t" >/dev/null || { echo "$t not found" >&2; exit 2; }
done

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
jqt()       { jq -e "$@" >/dev/null; }
check()     { local label="$1"; shift; if "$@"; then ok "$label"; else bad "$label"; fi; }
check_not() { local label="$1"; shift; if "$@"; then bad "$label"; else ok "$label"; fi; }
step() { echo; echo "== $1"; }
indent() { sed 's/^/      /'; }

T="$(mktemp -d /tmp/fairplay-attest.XXXXXX)"
chmod 755 "$T"
DAEMON_PID=""; SWTPM_PID=""
stop_swtpm() {
  if [ -n "$SWTPM_PID" ]; then
    kill "$SWTPM_PID" 2>/dev/null
    wait "$SWTPM_PID" 2>/dev/null
    SWTPM_PID=""
  fi
}
cleanup() {
  if [ -n "$DAEMON_PID" ]; then
    sudo kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
  fi
  stop_swtpm
  sudo rm -f "$SOCK"
  rm -rf "$T"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Two consecutive free ports (swtpm's TCTI uses port + 1 for control).
PORT="$(python3 -c '
import socket
for _ in range(100):
    a = socket.socket(); a.bind(("127.0.0.1", 0)); p = a.getsockname()[1]
    b = socket.socket()
    try:
        b.bind(("127.0.0.1", p + 1)); print(p); break
    except OSError:
        pass
    finally:
        a.close(); b.close()
')"
TCTI="swtpm:host=127.0.0.1,port=$PORT"

# Start (or restart) swtpm: a fresh boot, every PCR at its reset value.
# The state directory persists, so the TPM, and its AK, stay the same.
start_swtpm() {
  mkdir -p "$T/tpm"
  swtpm socket --tpm2 --flags not-need-init,startup-clear --tpmstate "dir=$T/tpm" \
    --server "type=tcp,bindaddr=127.0.0.1,port=$PORT" \
    --ctrl "type=tcp,bindaddr=127.0.0.1,port=$((PORT + 1))" >/dev/null 2>"$T/swtpm.err" &
  SWTPM_PID=$!
  for _ in $(seq 100); do
    python3 -c "import socket,sys; socket.create_connection(('127.0.0.1', $PORT), 1)" 2>/dev/null && return 0
    sleep 0.1
  done
  echo "swtpm did not start:"; indent <"$T/swtpm.err"; exit 2
}
mode_event() { printf 'fairplay-os/mode/v1:%s' "$1" | sha256sum | cut -d' ' -f1; }
extend_mode() { TPM2TOOLS_TCTI="$TCTI" tpm2_pcrextend "$MODE_PCR:sha256=$(mode_event "$1")"; }

step "build"
if [ -z "${ATTEST_SKIP_BUILD:-}" ]; then
  (cd "$REPO/crates/fairplay-ebpf" &&
    { [ -s src/vmlinux.rs ] || aya-tool generate task_struct > src/vmlinux.rs; } &&
    cargo build --release -q) || exit 2
  (cd "$REPO" && cargo build --release -q -p fairplayd -p fairplay-api) || exit 2
fi
mkdir -p "$T/bin"
cp "$REPO"/target/release/{fairplayd,fairplayctl} "$T/bin/"
CTL="$T/bin/fairplayctl"
export FAIRPLAYD_SOCKET="$SOCK"

step "a player-mode boot: swtpm on port $PORT, mode PCR $MODE_PCR extended with \"player\""
start_swtpm
extend_mode player || exit 2

step "start fairplayd on $SOCK with --tpm-tcti $TCTI"
# No IMA log: the kernel's log describes this VM's PCR 10, not swtpm's.
sudo "$T/bin/fairplayd" --obj "$OBJ" --socket "$SOCK" --tpm-tcti "$TCTI" --no-ima-log \
  >"$T/daemon.out" 2>"$T/daemon.err" &
DAEMON_PID=$!
for _ in $(seq 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "fairplayd did not start:"; indent <"$T/daemon.err"; exit 2; }

N1=5e7e2c0ffee0123456789abcdef0
verify() { "$CTL" verify-evidence --trust-reported-ak "$@"; }

step "attest, as an ordinary user, and verify"
"$CTL" attest --nonce "$N1" >"$T/player.json" 2>"$T/player.err"
jq -c '.ok.evidence | {version, nonce, pcrs: (.pcrs|keys), ima_log: has("ima_log")}' "$T/player.json" 2>/dev/null | indent
check "the reply is version-1 evidence for our nonce" \
  jqt --arg n "$N1" '.ok.evidence | .version==1 and .nonce==$n' "$T/player.json"
verify --nonce "$N1" "$T/player.json" >"$T/player.verdict" 2>/dev/null
jq -c '{verified, mode, ima_log_verified}' "$T/player.verdict" 2>/dev/null | indent
check "the verifier accepts it and reads player mode" \
  jqt '.verified and .mode=="player"' "$T/player.verdict"

step "what the verifier must refuse"
verify --nonce 00112233 "$T/player.json" >"$T/replay.verdict" 2>/dev/null
jq -c . "$T/replay.verdict" 2>/dev/null | indent
check "the same evidence for a different nonce (a replay)" \
  jqt '(.verified|not) and (.rejection|test("nonce"))' "$T/replay.verdict"
DEV_PCR="$(python3 -c "
import hashlib, sys
print(hashlib.sha256(bytes(32) + bytes.fromhex('$(mode_event developer)')).hexdigest())")"
jq --arg p "$MODE_PCR" --arg v "$DEV_PCR" '.ok.evidence.pcrs[$p] = $v' "$T/player.json" >"$T/forged.json"
verify --nonce "$N1" "$T/forged.json" >"$T/forged.verdict" 2>/dev/null
jq -c . "$T/forged.verdict" 2>/dev/null | indent
check "a reported PCR value the quote doesn't cover" \
  jqt '(.verified|not) and (.rejection|test("digest"))' "$T/forged.verdict"
jq '.ok.evidence.version = 2' "$T/player.json" >"$T/v2.json"
verify --nonce "$N1" "$T/v2.json" >/dev/null 2>"$T/v2.err"
indent <"$T/v2.err"
check "an evidence version this verifier doesn't know" grep -q "version 2 is not supported" "$T/v2.err"

step "root extends the mode PCR after boot"
extend_mode player || exit 2
"$CTL" attest --nonce "$N1" >"$T/twice.json" 2>/dev/null
verify --nonce "$N1" "$T/twice.json" >"$T/twice.verdict" 2>/dev/null
jq -c '{verified, mode}' "$T/twice.verdict" 2>/dev/null | indent
check "still a valid quote, but the mode is unrecognized, not player" \
  jqt '.verified and .mode=="unrecognized"' "$T/twice.verdict"

step "a developer-mode boot (swtpm restarted), then root tries \"player\""
stop_swtpm
start_swtpm
extend_mode developer || exit 2
"$CTL" attest --nonce "$N1" >"$T/dev.json" 2>/dev/null
verify --nonce "$N1" "$T/dev.json" >"$T/dev.verdict" 2>/dev/null
jq -c '{verified, mode}' "$T/dev.verdict" 2>/dev/null | indent
check "the verifier reads developer mode" jqt '.verified and .mode=="developer"' "$T/dev.verdict"
check "the same TPM, so the same AK" \
  sh -c "[ \"\$(jq -r .ok.evidence.ak_public '$T/dev.json')\" = \"\$(jq -r .ok.evidence.ak_public '$T/player.json')\" ]"
extend_mode player || exit 2
"$CTL" attest --nonce "$N1" >"$T/upgrade.json" 2>/dev/null
verify --nonce "$N1" "$T/upgrade.json" >"$T/upgrade.verdict" 2>/dev/null
check "extending \"player\" on a developer boot doesn't make it player" \
  jqt '.verified and .mode=="unrecognized"' "$T/upgrade.verdict"

step "the TPM goes away"
stop_swtpm
"$CTL" attest --nonce "$N1" >"$T/gone.json" 2>/dev/null
indent <"$T/gone.json"
check "attest says unavailable and echoes the nonce; no evidence is made up" \
  jqt --arg n "$N1" '.error.code=="unavailable" and .error.nonce==$n' "$T/gone.json"

step "stop fairplayd"
sudo kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
check "socket removed" test ! -e "$SOCK"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
