#!/usr/bin/env bash
# Boot the VM headless. SSH in from another terminal:  ssh -p 2222 <you>@localhost
# Quit QEMU with Ctrl-A then X (or `sudo poweroff` inside the guest).
#
# TPM=on   (default) software TPM 2.0 via swtpm
# TPM=off  boot without a TPM; fine for milestones 1-5
#   e.g.  TPM=off ./vm/macos/run-vm.sh
set -euo pipefail

DIR="${VM_DIR:-$HOME/fairplay-vm}"
CPUS="${CPUS:-4}"
MEM="${MEM:-8G}"
TPM="${TPM:-on}"
cd "$DIR"

TPM_ARGS=()
if [ "$TPM" = "on" ]; then
  # Software TPM 2.0. State persists in ./tpm, so keys survive reboots.
  swtpm socket --tpm2 \
    --tpmstate dir="$DIR/tpm" \
    --ctrl type=unixio,path="$DIR/tpm/swtpm.sock" \
    --flags startup-clear \
    --daemon
  trap 'pkill -f "swtpm socket --tpm2 --tpmstate dir=$DIR/tpm" || true' EXIT
  TPM_ARGS=(
    -chardev socket,id=chrtpm,path="$DIR/tpm/swtpm.sock"
    -tpmdev emulator,id=tpm0,chardev=chrtpm
    -device tpm-tis-device,tpmdev=tpm0
  )
else
  echo "run-vm: booting without a TPM (TPM=off)"
fi

qemu-system-aarch64 \
  -machine virt,highmem=on -accel hvf -cpu host \
  -smp "$CPUS" -m "$MEM" \
  -drive if=pflash,format=raw,readonly=on,file=efi-code.fd \
  -drive if=pflash,format=raw,file=efi-vars.fd \
  -drive if=virtio,format=qcow2,file=root.qcow2 \
  -drive if=virtio,format=qcow2,file=work.qcow2 \
  -drive if=virtio,format=raw,media=cdrom,file=seed.iso \
  ${TPM_ARGS[@]+"${TPM_ARGS[@]}"} \
  -nic user,model=virtio-net-pci,hostfwd=tcp::2222-:22 \
  -nographic
