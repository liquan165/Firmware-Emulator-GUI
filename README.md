# Firmware Emulator GUI (Windows)
自用版本的IOT、车联网固件仿真工具
A Windows-friendly Python GUI for firmware/rootfs analysis workflows.  
It provides a QEMU launcher, embedded noVNC display, NAT port forwarding, and an SSH-key based upload + chroot workflow for extracted rootfs directories.

> Focus: filesystem-level analysis (extract/upload/mount/chroot), not full device emulation.

---

## Features

- **QEMU launcher** (multi-arch targets)
  - x86_64, i386, aarch64, arm, mips/mipsel/mips64/mips64el, riscv64, ppc/ppc64 (depending on your installed QEMU)
  - Built-in **MIPS Malta compatibility** defaults:
    - disk attachment uses `-hda` (IDE) rather than virtio
- **Embedded VM display**
  - QEMU uses VNC output
  - GUI embeds **noVNC** via **websockify**
- **Network**
  - Default: `-netdev user` (NAT) + configurable port forwarding (e.g., host 2222 -> guest 22)
  - Bridge/TAP mode is exposed (advanced; requires TAP setup on Windows)
- **SSH-key workflow**
  - **SSH Key Wizard (first-run)**:
    - Generates a Windows OpenSSH RSA key (`id_rsa`) if missing
    - Injects the public key into the guest’s `authorized_keys`
  - **Upload rootfs folder**:
    - Packs folder to tar
    - Uploads via Windows `scp.exe`
    - Extracts to `/opt/fw/rootfs`
  - **One-click chroot**:
    - mounts `/dev`, `/proc`, `/sys`
    - opens an interactive chroot shell in a new terminal
  - **Umount** helper

---

## Requirements

### OS
- Windows 10/11

### Python
- Python 3.10+ recommended

### External Tools
- **QEMU for Windows**
  - Ensure `qemu-system-*.exe` targets exist (or select the path in GUI)
  - `qemu-img.exe` recommended (usually ships with QEMU)
- **Windows OpenSSH Client** (built-in optional feature)
  - `C:\Windows\System32\OpenSSH\ssh.exe`
  - `C:\Windows\System32\OpenSSH\scp.exe`
  - `C:\Windows\System32\OpenSSH\ssh-keygen.exe`

> The GUI intentionally uses **Windows System32 OpenSSH** to avoid Cygwin/MSYS path/key permission issues.

---

## Installation

```bash
pip install -r requirements.txt
python main.py
