# Setting up the gaming PC

Milestones 10, 11 and 12 need real x86 hardware: a real **TPM** (the chip that signs a report of
what booted), **Secure Boot** (firmware that only starts signed boot files), an NVIDIA GPU and
**Proton** (Valve's layer that runs Windows games on Linux). This page is the owner's checklist for
turning a Windows gaming PC into a dual-boot test machine. Agents do everything after step 7.

Target machine: x86_64, NVIDIA RTX 40-series, firmware TPM, Windows 11 already installed.

## Before you start (in Windows)

1. **Save your BitLocker recovery key**, if Windows uses BitLocker (drive encryption):
   <https://aka.ms/myrecoverykey>. Changing boot settings can make Windows ask for it.
2. **Turn off Fast Startup:** Control Panel → Power Options → "Choose what the power buttons do"
   → untick "Turn on fast startup". With it on, Windows only half shuts down and leaves its disks
   locked.
3. **Pick a disk for Linux.** A separate SSD of 256 GB or more is best: Windows stays untouched
   and you can pull the drive to undo everything. Otherwise, shrink the Windows partition in
   Disk Management (right-click the C: partition → Shrink Volume) to free about 256 GB.

## In the firmware (BIOS/UEFI setup)

4. **Keep Secure Boot on, with the standard keys.** Don't clear or replace the keys. The RTX 40
   card's own firmware is signed with Microsoft's key, and without that key the screen stays
   black at boot. Linux boots through **shim**, a small loader that Microsoft signs, so it works
   with the standard keys.
5. **Check the TPM is on.** It's usually called **fTPM** (AMD) or **PTT** (Intel). If Windows 11
   runs, it's already on.

## Install Linux

6. **Install Ubuntu 24.04 LTS Desktop (x86_64)** from a USB stick, onto the Linux disk.
   - Choose "Install third-party software for graphics" so the NVIDIA driver comes with it.
   - If the installer asks for a **Secure Boot (MOK) password**, set one you'll remember. On the
     next boot a blue screen appears: choose "Enroll MOK" and type that password. (MOK, the
     Machine Owner Key, is how shim learns to trust a key you add.)
   - **Don't mount the Windows drives in Linux.** Agents get root on the Linux side; keeping
     Windows unmounted keeps it out of their reach.
7. **Check the hardware.** Open a terminal, run this and send the output to the lead agent:
   ```
   ls /dev/tpmrm0; mokutil --sb-state; nvidia-smi | head -15; cat /sys/kernel/security/lsm
   ```
   You want: `/dev/tpmrm0` exists, `SecureBoot enabled`, `nvidia-smi` names your card. The last
   line lists the kernel's security modules; agents add `bpf` to it later, so it's fine if `bpf`
   is missing now.

## Give agents access

8. Install `git`, Rust's toolchain installer and Claude Code:
   ```
   sudo apt install -y git curl build-essential
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
   Then install Claude Code and clone `terellison/fairplay-os`.
9. **Copy the two GitHub App configs** from the VM to the PC, directly between your machines:
   ```
   scp -r <vm>:~/.config/fairplay-agents <vm>:~/.config/fairplay-lead ~/.config/
   chmod 700 ~/.config/fairplay-agents ~/.config/fairplay-lead
   chmod 600 ~/.config/fairplay-agents/*.pem ~/.config/fairplay-lead/*.pem
   ```
   These hold the Apps' private keys. Never paste them into chat, an issue or the repo. Edit the
   key paths in each `app.env` if your home directory differs from the VM's.
10. **Steam is optional for now.** Milestone 12's first test uses a standalone Proton build and our
    own Windows test program, with no Steam login. Real games come later, and you sign in to Steam
    yourself; agents never handle your Steam password.

## What agents do next

- Turn on the BPF security module (add `bpf` to the kernel's `lsm=` boot setting).
- Build and rerun milestones 1–9 on real hardware, then milestone 10 against the real TPM.
- Build the player-mode image (milestone 11) and run a Windows program under Proton, protected
  (milestone 12).

## Decisions still open for the owner

These don't block setup, but milestone 11 needs the first one.

1. **Base for the player-mode image.** The lead recommends Ubuntu 24.04 built with **mkosi** (a
   tool for building system images): it matches the VM, and Canonical signs Ubuntu's NVIDIA
   modules, so they load under Secure Boot and lockdown without extra steps. The alternative is
   Fedora built with **bootc** (the image-based approach Bazzite uses).
2. **When `fairplayd` exits mid-game.** Today the game keeps running unprotected. In player mode,
   should the session end, or keep running and be reported as unprotected?
3. **Approved game files rewritten in place.** Fixing this means checking file hashes (fs-verity
   or IMA appraisal) instead of file identity. That's a design change.

## Undoing it

With a separate disk: remove the Linux disk, or pick Windows Boot Manager first in the firmware's
boot order. With a shrunk partition: in Windows, delete the Linux partitions in Disk Management
and extend C:, then remove the `ubuntu` boot entry (`bcdedit /enum firmware`, then
`bcdedit /delete {id}` from an administrator prompt).
