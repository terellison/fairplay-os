#!/usr/bin/env bash
# Milestone 1 exit check. Run inside the VM after provisioning and a reboot.
set -uo pipefail
# shellcheck disable=SC2016  # single-quoted checks run in a child bash on purpose

pass=0; fail=0; skip=0
skip() { echo "SKIP  $1 ($2)"; skip=$((skip+1)); }
check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "PASS  $name"; pass=$((pass+1));
  else echo "FAIL  $name"; fail=$((fail+1)); fi
}


check "kernel is 6.x or newer"     bash -c '[ "$(uname -r | cut -d. -f1)" -ge 6 ]'
check "BPF LSM active"             grep -qw bpf /sys/kernel/security/lsm
check "kernel BTF available"       test -r /sys/kernel/btf/vmlinux
if [ -e /dev/tpmrm0 ]; then
  check "TPM 2.0 device present"   test -e /dev/tpmrm0
  check "TPM answers PCR read"     sudo tpm2_pcrread sha256:0,4,7,10
else
  skip "TPM 2.0 device present" "no TPM; VM booted with TPM=off"
  skip "TPM answers PCR read" "no TPM"
fi
check "IMA policy on cmdline"      grep -qw ima_policy=tcb /proc/cmdline
# securityfs files report size 0, so read a line instead of using test -s
check "IMA measuring"              bash -c '[ "$(sudo head -n 5 /sys/kernel/security/ima/ascii_runtime_measurements | wc -l)" -ge 2 ]'
check "btrfs workspace mounted"    bash -c 'findmnt -n -o FSTYPE /work | grep -q btrfs'
check "workspace is a subvolume"   sudo btrfs subvolume show /work/ws
check "nightly + rust-src"         bash -c 'rustup component list --toolchain nightly --installed | grep -q rust-src'
check "bpf-linker installed"       command -v bpf-linker
check "aya-tool installed"         command -v aya-tool
check "bindgen installed (aya-tool needs it)" command -v bindgen

echo "Secure Boot: $(sudo mokutil --sb-state 2>/dev/null || echo 'not available (expected on arm64 QEMU; see README)')"
echo "$pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
