# Firmware Emulator GUI (Windows)
自用版本的IOT、车联网固件仿真工具

##A Windows-friendly Python GUI for firmware/rootfs analysis workflows.  
It provides a QEMU launcher, embedded noVNC display, NAT port forwarding, and an SSH-key based upload + chroot workflow for extracted rootfs directories.
支持多架构的友好虚拟机，并且可一键上传目录，一键mount固件进程、设备等达到物联网、车联网固件仿真效果。

> Focus: filesystem-level analysis (extract/upload/mount/chroot), not full device emulation.

---

## Features

- **QEMU launcher** (multi-arch targets)
  - x86_64, i386, aarch64, arm, mips/mipsel/mips64/mips64el, riscv64, ppc/ppc64 (depending on your installed QEMU)
  - Built-in **MIPS Malta compatibility** defaults:
    - disk attachment uses `-hda` (IDE) rather than virtio
  <img width="642" height="396" alt="image" src="https://github.com/user-attachments/assets/abcee3f9-2d6e-47a8-85ff-a11d541ba8e3" />
<img width="275" height="352" alt="image" src="https://github.com/user-attachments/assets/e2ac82d3-2abe-412d-8801-f6e2484303fe" />

- **Embedded VM display**
  - QEMU uses VNC output
  - GUI embeds **noVNC** via **websockify**
    <img width="394" height="37" alt="image" src="https://github.com/user-attachments/assets/87b2deb5-857a-477a-ac58-58403fd9b1c6" />
<img width="877" height="718" alt="image" src="https://github.com/user-attachments/assets/6cd61226-0a07-4034-ad1c-dbd9e42aee1c" />

- **Network**
  - Default: `-netdev user` (NAT) + configurable port forwarding (e.g., host 2222 -> guest 22)
  - Bridge/TAP mode is exposed (advanced; requires TAP setup on Windows)
 
  <img width="655" height="255" alt="image" src="https://github.com/user-attachments/assets/d6bdcb3f-23ee-4c59-b000-ad2f98bf5ab9" />

- **SSH-key workflow**
  - **SSH Key Wizard (first-run)**:
    - Generates a Windows OpenSSH RSA key (`id_rsa`) if missing
    - Injects the public key into the guest’s `authorized_keys`
    - 自动链接目标机器并打包固件为tar
    - 上传到opt目录下并自动mount dev proc等
      <img width="651" height="279" alt="image" src="https://github.com/user-attachments/assets/d96425ea-7ca8-4154-b0bc-04be0c606f9b" />
      
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
<img width="1499" height="1013" alt="image" src="https://github.com/user-attachments/assets/4d766786-629d-490b-90fb-7e8832a2008c" />

## Installation

```bash
pip install -r requirements.txt
python main.py
