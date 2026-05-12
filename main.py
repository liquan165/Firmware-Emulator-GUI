from __future__ import annotations

import os
import sys
import time
import shutil
import socket
import hashlib
import zipfile
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# WebEngine GPU 兼容
os.environ.setdefault(
    "QTWEBENGINE_CHROMIUM_FLAGS",
    "--disable-gpu --disable-gpu-compositing --disable-software-rasterizer"
)
os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")

import requests
import psutil

from PySide6.QtCore import QUrl, Qt
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFileDialog,
    QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QLabel,
    QTextEdit, QGroupBox, QComboBox, QMessageBox,
    QFormLayout, QSplitter, QSpinBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QCheckBox, QStackedWidget
)
from PySide6.QtWebEngineWidgets import QWebEngineView


# ----------------------------
# Paths / constants
# ----------------------------
APP_DIR = Path(__file__).resolve().parent
TOOLS_DIR = APP_DIR / "tools"
NOVNC_DIR = TOOLS_DIR / "novnc"
WORK_DIR = APP_DIR / "workspace"
WORK_DIR.mkdir(exist_ok=True)
TOOLS_DIR.mkdir(exist_ok=True)

NOVNC_VERSION = "v1.5.0"
NOVNC_ZIP_URL = f"https://github.com/novnc/noVNC/archive/refs/tags/{NOVNC_VERSION}.zip"

# noVNC zip SHA256
NOVNC_ZIP_SHA256 = "e93303cf02c41657b9fd4248cf0696614c03e2ffb1f2195c0a83c7e020828134"

REMOTE_BASE = "/opt/fw"
REMOTE_ROOTFS = f"{REMOTE_BASE}/rootfs"
REMOTE_TAR = "/tmp/rootfs.tar"

QEMU_TARGETS: dict[str, list[str]] = {
    "x86_64":  ["qemu-system-x86_64.exe", "qemu-system-x86_64"],
    "i386":    ["qemu-system-i386.exe", "qemu-system-i386"],
    "aarch64": ["qemu-system-aarch64.exe", "qemu-system-aarch64"],
    "arm":     ["qemu-system-arm.exe", "qemu-system-arm"],
    "mips":    ["qemu-system-mips.exe", "qemu-system-mips"],
    "mipsel":  ["qemu-system-mipsel.exe", "qemu-system-mipsel"],
    "mips64":  ["qemu-system-mips64.exe", "qemu-system-mips64"],
    "mips64el":["qemu-system-mips64el.exe", "qemu-system-mips64el"],
    "riscv64": ["qemu-system-riscv64.exe", "qemu-system-riscv64"],
    "ppc":     ["qemu-system-ppc.exe", "qemu-system-ppc"],
    "ppc64":   ["qemu-system-ppc64.exe", "qemu-system-ppc64"],
}


# ----------------------------
# Utils
# ----------------------------
def which_any(names: list[str]) -> Optional[str]:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def shlex_quote(s: str) -> str:
    # POSIX shell 安全引用：用单引号包裹，内部单引号特殊处理
    return "'" + s.replace("'", "'\"'\"'") + "'"


def run_first_line(cmd: list[str], timeout=6) -> Optional[str]:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        lines = (out or "").strip().splitlines()
        return lines[0] if lines else ""
    except Exception:
        return None


def port_in_use(port: int, host="127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.25)
        return s.connect_ex((host, port)) == 0


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def guess_disk_format(path: str) -> str:
    ext = Path(path).suffix.lower()
    if ext == ".qcow2":
        return "qcow2"
    return "raw"


def make_tar_of_dir(src_dir: str, tar_path: str):
    src = Path(src_dir)
    if not src.exists() or not src.is_dir():
        raise RuntimeError("选择的固件目录无效。")
    with tarfile.open(tar_path, "w") as tar:
        for p in src.rglob("*"):
            tar.add(p, arcname=str(p.relative_to(src)))


def windows_openssh_paths():
    win = Path(os.environ.get("WINDIR", r"C:\Windows"))
    base = win / "System32" / "OpenSSH"
    return {
        "ssh": base / "ssh.exe",
        "scp": base / "scp.exe",
        "ssh-keygen": base / "ssh-keygen.exe",
    }


def userprofile_ssh_dir() -> Path:
    # 强制用 Windows USERPROFILE
    return Path(os.environ["USERPROFILE"]) / ".ssh"


def pick_identity_files_prefer_rsa():
    """
    Debian squeeze 老 sshd 可能不支持 ed25519，所以优先 RSA
    返回：private_key_path, public_key_path（可能为 None）
    """
    d = userprofile_ssh_dir()
    rsa = d / "id_rsa"
    rsa_pub = d / "id_rsa.pub"
    ed = d / "id_ed25519"
    ed_pub = d / "id_ed25519.pub"

    if rsa.exists() and rsa_pub.exists():
        return rsa, rsa_pub
    if ed.exists() and ed_pub.exists():
        return ed, ed_pub
    # 只要 private 存在也返回
    if rsa.exists():
        return rsa, rsa_pub
    if ed.exists():
        return ed, ed_pub
    return None, None


# ----------------------------
# Data models
# ----------------------------
@dataclass
class PortForward:
    proto: str
    host_port: int
    guest_port: int


@dataclass
class LaunchConfig:
    arch: str
    qemu_path: str
    qemu_img_path: Optional[str]
    kernel_path: str
    disk_path: str
    disk_format: str
    memory_mb: int
    vnc_display: int
    ws_port: int
    net_mode: str          # nat|bridge
    tap_ifname: str
    port_forwards: list[PortForward]
    ssh_forward_port: int


# ----------------------------
# Environment manager
# ----------------------------
def ensure_websockify(log_cb):
    ok = run_first_line([sys.executable, "-m", "websockify", "--help"])
    if ok:
        log_cb("websockify 已可用。")
        return
    log_cb("websockify 缺失，尝试 pip 安装/升级...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-U", "websockify"])
    ok2 = run_first_line([sys.executable, "-m", "websockify", "--help"])
    if not ok2:
        raise RuntimeError("websockify 安装后仍不可用，请检查 Python 环境。")
    log_cb("websockify 安装完成。")


def ensure_novnc(log_cb):
    vnc_html = NOVNC_DIR / "vnc.html"
    if vnc_html.exists():
        log_cb(f"noVNC 已存在：{vnc_html}")
        return

    if not NOVNC_ZIP_SHA256:
        raise RuntimeError("NOVNC_ZIP_SHA256 为空，无法下载校验 noVNC。")

    TOOLS_DIR.mkdir(exist_ok=True)
    zip_path = TOOLS_DIR / f"noVNC-{NOVNC_VERSION}.zip"

    log_cb(f"下载 noVNC: {NOVNC_ZIP_URL}")
    r = requests.get(NOVNC_ZIP_URL, stream=True, timeout=60)
    r.raise_for_status()
    with zip_path.open("wb") as f:
        for chunk in r.iter_content(chunk_size=1024 * 256):
            if chunk:
                f.write(chunk)

    got = sha256_file(zip_path)
    log_cb(f"noVNC zip sha256 = {got}")
    if got.lower() != NOVNC_ZIP_SHA256.lower():
        zip_path.unlink(missing_ok=True)
        raise RuntimeError("noVNC 校验失败：SHA256 不匹配，已删除下载文件。")

    tmp_dir = TOOLS_DIR / f"_tmp_novnc_{int(time.time())}"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(tmp_dir)

    extracted = next(tmp_dir.iterdir())
    if NOVNC_DIR.exists():
        shutil.rmtree(NOVNC_DIR, ignore_errors=True)
    shutil.move(str(extracted), str(NOVNC_DIR))
    shutil.rmtree(tmp_dir, ignore_errors=True)

    if not (NOVNC_DIR / "vnc.html").exists():
        raise RuntimeError("noVNC 解压后未找到 vnc.html，版本结构可能变化。")
    log_cb(f"noVNC 已安装到：{NOVNC_DIR}")


def check_base_env(cfg: LaunchConfig) -> list[str]:
    errs: list[str] = []

    if not cfg.qemu_path or not Path(cfg.qemu_path).exists():
        errs.append("未找到 QEMU：请指定 qemu-system-*.exe 路径，或将其加入 PATH。")
    else:
        v = run_first_line([cfg.qemu_path, "--version"])
        if not v:
            errs.append("QEMU 无法执行：请检查路径是否正确、文件是否被安全软件拦截。")

    if not cfg.qemu_img_path:
        errs.append("未找到 qemu-img：镜像信息检测会受限（建议安装完整 QEMU 并将 qemu-img 加入 PATH）。")

    if not cfg.kernel_path or not Path(cfg.kernel_path).exists():
        errs.append("Kernel 路径无效。")
    if not cfg.disk_path or not Path(cfg.disk_path).exists():
        errs.append("Disk 路径无效。")

    vnc_port = 5900 + cfg.vnc_display
    if port_in_use(cfg.ws_port):
        errs.append(f"noVNC websocket 端口 {cfg.ws_port} 已被占用。")
    if port_in_use(vnc_port):
        errs.append(f"VNC 端口 {vnc_port} 已被占用（display :{cfg.vnc_display}）。")

    if cfg.net_mode == "nat":
        for pf in cfg.port_forwards:
            if port_in_use(pf.host_port):
                errs.append(f"端口转发占用：{pf.proto} host {pf.host_port} 已被占用。")
    else:
        if not cfg.tap_ifname.strip():
            errs.append("Bridge 模式：TAP 网卡名称不能为空（ifname）。")

    if not (NOVNC_DIR / "vnc.html").exists():
        errs.append("noVNC 未安装：请先点击“环境检测/安装”。")

    ok = run_first_line([sys.executable, "-m", "websockify", "--help"])
    if not ok:
        errs.append("websockify 不可用：请先点击“环境检测/安装”。")

    # System32 OpenSSH tools
    paths = windows_openssh_paths()
    for k in ("ssh", "scp", "ssh-keygen"):
        if not paths[k].exists():
            errs.append(f"未找到 Windows OpenSSH: {paths[k]}")

    return errs


# ----------------------------
# Main UI
# ----------------------------
class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firmware Emulator GUI (QEMU + noVNC + OpenSSH-key Upload/Chroot)")

        self.qemu_proc: Optional[subprocess.Popen] = None
        self.ws_proc: Optional[subprocess.Popen] = None

        root = QWidget()
        self.setCentralWidget(root)
        splitter = QSplitter(Qt.Horizontal)
        layout = QHBoxLayout(root)
        layout.addWidget(splitter)

        left = QWidget()
        lyt = QVBoxLayout(left)
        splitter.addWidget(left)
        left.setMinimumWidth(620)
        left.setMaximumWidth(620)

        right = QWidget()
        rlyt = QVBoxLayout(right)
        splitter.addWidget(right)

        # --- Arch + QEMU selection
        gb_arch = QGroupBox("CPU / QEMU 目标")
        arch_form = QFormLayout(gb_arch)

        self.cb_arch = QComboBox()
        self.cb_arch.addItems(list(QEMU_TARGETS.keys()))
        self.cb_arch.setCurrentText("mips")
        self.cb_arch.currentTextChanged.connect(self.autofill_qemu_for_arch)
        arch_form.addRow(QLabel("Arch"), self.cb_arch)

        self.ed_qemu = QLineEdit()
        btn_qemu = QPushButton("选择 qemu-system-*.exe")
        btn_qemu.clicked.connect(self.pick_qemu)
        row_qemu = QWidget()
        row_qemu_lyt = QHBoxLayout(row_qemu)
        row_qemu_lyt.setContentsMargins(0, 0, 0, 0)
        row_qemu_lyt.addWidget(self.ed_qemu, 1)
        row_qemu_lyt.addWidget(btn_qemu)
        arch_form.addRow(QLabel("QEMU"), row_qemu)

        self.lb_qemu_detect = QLabel("自动探测：未探测")
        arch_form.addRow(QLabel("状态"), self.lb_qemu_detect)

        lyt.addWidget(gb_arch)

        # --- Boot inputs
        gb_boot = QGroupBox("启动参数（kernel + disk）")
        boot_form = QFormLayout(gb_boot)

        self.ed_kernel = QLineEdit()
        btn_kernel = QPushButton("选择 Kernel")
        btn_kernel.clicked.connect(self.pick_kernel)
        row_k = QWidget()
        row_k_lyt = QHBoxLayout(row_k)
        row_k_lyt.setContentsMargins(0, 0, 0, 0)
        row_k_lyt.addWidget(self.ed_kernel, 1)
        row_k_lyt.addWidget(btn_kernel)
        boot_form.addRow(QLabel("Kernel"), row_k)

        self.ed_disk = QLineEdit()
        btn_disk = QPushButton("选择 Disk")
        btn_disk.clicked.connect(self.pick_disk)
        row_d = QWidget()
        row_d_lyt = QHBoxLayout(row_d)
        row_d_lyt.setContentsMargins(0, 0, 0, 0)
        row_d_lyt.addWidget(self.ed_disk, 1)
        row_d_lyt.addWidget(btn_disk)
        boot_form.addRow(QLabel("Disk"), row_d)

        self.sp_mem = QSpinBox()
        self.sp_mem.setRange(128, 65536)
        self.sp_mem.setValue(1024)
        boot_form.addRow(QLabel("内存(MB)"), self.sp_mem)

        self.sp_vnc_display = QSpinBox()
        self.sp_vnc_display.setRange(0, 99)
        self.sp_vnc_display.setValue(1)
        boot_form.addRow(QLabel("VNC display (:N)"), self.sp_vnc_display)

        self.sp_ws_port = QSpinBox()
        self.sp_ws_port.setRange(1024, 65535)
        self.sp_ws_port.setValue(6080)
        boot_form.addRow(QLabel("noVNC WS 端口"), self.sp_ws_port)

        self.ed_kernel_append = QLineEdit("console=tty0 root=/dev/sda1 rw")
        boot_form.addRow(QLabel("Kernel append"), self.ed_kernel_append)

        self.chk_nographic = QCheckBox("nographic（串口输出到控制台）")
        self.chk_nographic.setChecked(True)
        boot_form.addRow(QLabel("输出"), self.chk_nographic)

        lyt.addWidget(gb_boot)

        # --- Network module
        gb_net = QGroupBox("网络管理")
        net_lyt = QVBoxLayout(gb_net)

        net_mode_row = QHBoxLayout()
        self.cb_net_mode = QComboBox()
        self.cb_net_mode.addItems(["nat", "bridge"])
        self.cb_net_mode.currentTextChanged.connect(self.on_net_mode_changed)
        net_mode_row.addWidget(QLabel("模式"))
        net_mode_row.addWidget(self.cb_net_mode, 1)
        net_lyt.addLayout(net_mode_row)

        self.tbl_pf = QTableWidget(0, 3)
        self.tbl_pf.setHorizontalHeaderLabels(["Proto", "HostPort", "GuestPort"])
        self.tbl_pf.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_pf.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_pf.setEditTriggers(QAbstractItemView.DoubleClicked | QAbstractItemView.EditKeyPressed)

        btn_pf_add = QPushButton("添加转发")
        btn_pf_del = QPushButton("删除选中")
        btn_pf_add.clicked.connect(self.pf_add)
        btn_pf_del.clicked.connect(self.pf_del)

        net_lyt.addWidget(QLabel("NAT 端口转发（nat 模式生效）"))
        net_lyt.addWidget(self.tbl_pf)
        pf_btns = QHBoxLayout()
        pf_btns.addWidget(btn_pf_add)
        pf_btns.addWidget(btn_pf_del)
        net_lyt.addLayout(pf_btns)

        self.pf_add(default=("tcp", "2222", "22"))

        bridge_form = QFormLayout()
        self.ed_tap = QLineEdit()
        bridge_form.addRow(QLabel("TAP ifname"), self.ed_tap)
        net_lyt.addLayout(bridge_form)

        self.lb_bridge_tip = QLabel("Bridge 模式：需系统已有 TAP；必要时你要在 Windows 网络里把 TAP 与物理网卡桥接。")
        self.lb_bridge_tip.setWordWrap(True)
        net_lyt.addWidget(self.lb_bridge_tip)

        lyt.addWidget(gb_net)

        # --- SSH / Upload / Chroot module
        gb_ssh = QGroupBox("SSH / 上传 / Chroot（Windows OpenSSH Key；不检测）")
        ssh_lyt = QVBoxLayout(gb_ssh)

        self.lb_ssh_status = QLabel("SSH 状态：不检测（ssh/scp BatchMode；未注入 key 会失败）")
        ssh_lyt.addWidget(self.lb_ssh_status)

        ssh_form = QFormLayout()
        self.ed_ssh_host = QLineEdit("127.0.0.1")
        self.ed_ssh_port = QLineEdit("2222")
        self.ed_ssh_user = QLineEdit("root")
        ssh_form.addRow("Host", self.ed_ssh_host)
        ssh_form.addRow("Port(显示用)", self.ed_ssh_port)
        ssh_form.addRow("User", self.ed_ssh_user)
        ssh_lyt.addLayout(ssh_form)

        btns_ssh = QHBoxLayout()
        self.btn_upload = QPushButton(f"上传固件目录到 {REMOTE_ROOTFS}")
        self.btn_chroot = QPushButton("一键 chroot（mount + 进入）")
        self.btn_umount = QPushButton(f"卸载 {REMOTE_ROOTFS} 挂载")
        self.btn_key_wizard = QPushButton("SSH Key 向导(首次)")

        self.btn_upload.clicked.connect(self.upload_clicked)
        self.btn_chroot.clicked.connect(self.chroot_clicked)
        self.btn_umount.clicked.connect(self.umount_clicked)
        self.btn_key_wizard.clicked.connect(self.ssh_key_wizard_clicked)

        btns_ssh.addWidget(self.btn_upload)
        btns_ssh.addWidget(self.btn_chroot)
        btns_ssh.addWidget(self.btn_umount)
        btns_ssh.addWidget(self.btn_key_wizard)
        ssh_lyt.addLayout(btns_ssh)

        lyt.addWidget(gb_ssh)

        # --- Controls
        btn_row = QHBoxLayout()
        self.btn_env = QPushButton("环境检测/安装")
        self.btn_env.clicked.connect(self.env_check_clicked)
        self.btn_start = QPushButton("启动")
        self.btn_start.clicked.connect(self.start_clicked)
        self.btn_stop = QPushButton("停止")
        self.btn_stop.clicked.connect(self.stop_clicked)
        btn_row.addWidget(self.btn_env)
        btn_row.addWidget(self.btn_start)
        btn_row.addWidget(self.btn_stop)
        lyt.addLayout(btn_row)

        # --- Host IP status
        ip_row = QHBoxLayout()
        self.lb_ip = QLabel("宿主 IP：未刷新")
        btn_ip = QPushButton("刷新 IP")
        btn_ip.clicked.connect(self.refresh_host_ip)
        ip_row.addWidget(self.lb_ip, 1)
        ip_row.addWidget(btn_ip)
        lyt.addLayout(ip_row)

        # --- Log
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        lyt.addWidget(self.log, 1)

        # --- Right: stable web view
        self.right_stack = QStackedWidget()
        rlyt.addWidget(self.right_stack, 1)

        self.right_placeholder = QLabel("未启动 / 未加载 noVNC")
        self.right_placeholder.setAlignment(Qt.AlignCenter)

        self.web = QWebEngineView()
        self.right_stack.addWidget(self.right_placeholder)
        self.right_stack.addWidget(self.web)
        self.right_stack.setCurrentWidget(self.right_placeholder)

        self.append_log("流程：环境检测/安装 -> 启动 -> 上传/chroot/卸载；首次请先点 SSH Key 向导注入公钥")
        self.autofill_qemu_for_arch(self.cb_arch.currentText())
        self.on_net_mode_changed(self.cb_net_mode.currentText())

        # 按钮直接点亮
        self.set_ssh_actions_enabled(True)

    # ---- UI helpers
    def append_log(self, s: str):
        self.log.append(s)

    def set_ssh_actions_enabled(self, enabled: bool):
        self.btn_upload.setEnabled(enabled)
        self.btn_chroot.setEnabled(enabled)
        self.btn_umount.setEnabled(enabled)
        self.btn_key_wizard.setEnabled(enabled)

    def ssh_conf(self):
        host = self.ed_ssh_host.text().strip() or "127.0.0.1"
        user = self.ed_ssh_user.text().strip() or "root"
        return host, user

    # ---- SSH Key Wizard
    def ssh_key_wizard_clicked(self):
        """
        使用 Windows System32 OpenSSH 生成/读取 RSA 公钥，并注入到 guest 的 authorized_keys。
        由于第一次没有 key，需要在新弹出的 ssh 窗口里手动输入一次密码。
        """
        try:
            cfg = self.build_config()
            self._require_nat(cfg)

            paths = windows_openssh_paths()
            ssh = paths["ssh"]
            ssh_keygen = paths["ssh-keygen"]
            if not ssh.exists():
                raise RuntimeError(f"未找到 {ssh}")
            if not ssh_keygen.exists():
                raise RuntimeError(f"未找到 {ssh_keygen}")

            host, user = self.ssh_conf()
            port = cfg.ssh_forward_port

            ssh_dir = userprofile_ssh_dir()
            ssh_dir.mkdir(parents=True, exist_ok=True)

            # 优先 RSA（squeeze 更兼容）
            priv, pub = pick_identity_files_prefer_rsa()
            if pub is None or not pub.exists():
                self.append_log("未发现可用的 Windows OpenSSH key，将自动生成 RSA key: id_rsa")
                # 生成 RSA key（默认位置：%USERPROFILE%\.ssh\id_rsa）
                # -N ""：空口令；-f 指定文件
                target = ssh_dir / "id_rsa"
                cmd = [str(ssh_keygen), "-t", "rsa", "-b", "2048", "-N", "", "-f", str(target)]
                self.append_log("ssh-keygen: " + " ".join(cmd))
                p = subprocess.run(cmd, capture_output=True, text=True)
                if p.returncode != 0:
                    raise RuntimeError(f"ssh-keygen 失败:\n{p.stderr or p.stdout}")
                priv, pub = target, Path(str(target) + ".pub")

            if not pub.exists():
                raise RuntimeError(f"未找到公钥文件：{pub}")

            pub_key = pub.read_text(encoding="utf-8", errors="ignore").strip()
            if not (pub_key.startswith("ssh-rsa ") or pub_key.startswith("ssh-ed25519 ")):
                raise RuntimeError(f"公钥格式异常：{pub}，内容开头不是 ssh-rsa/ssh-ed25519")

            self.append_log(f"使用公钥：{pub}")

            # 远端命令：原样追加公钥到 authorized_keys（不额外拼 ssh-rsa，避免重复）
            safe_key = shlex_quote(pub_key)
            inner = (
                'set -e; '
                'H="${HOME:-/root}"; '
                'mkdir -p "$H/.ssh"; '
                'chmod 700 "$H/.ssh"; '
                f'printf "%s\\n" {safe_key} >> "$H/.ssh/authorized_keys"; '
                'chmod 600 "$H/.ssh/authorized_keys"; '
                'echo OK'
            )
            remote_cmd = "sh -lc " + shlex_quote(inner)

            common = [
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=NUL",
                "-o", "HostKeyAlgorithms=+ssh-rsa",
                "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
            ]
            cmd = [str(ssh), "-p", str(port)] + common + [f"{user}@{host}", remote_cmd]

            self.append_log("将打开新窗口，请输入一次 SSH 密码完成公钥注入；看到 OK 即成功。")
            subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)

        except Exception as e:
            QMessageBox.critical(self, "SSH Key 向导失败", str(e))

    # ---- OpenSSH helpers (key login) - Always use Windows System32 OpenSSH
    def _ssh_args_common(self, cfg: LaunchConfig):
        host, user = self.ssh_conf()
        port = cfg.ssh_forward_port

        paths = windows_openssh_paths()
        ssh = paths["ssh"]
        scp = paths["scp"]
        if not ssh.exists():
            raise RuntimeError(f"未找到 {ssh}")
        if not scp.exists():
            raise RuntimeError(f"未找到 {scp}")

        priv, _pub = pick_identity_files_prefer_rsa()
        if not priv or not priv.exists():
            raise RuntimeError("未找到 Windows OpenSSH 私钥：%USERPROFILE%\\.ssh\\id_rsa（建议先点 SSH Key 向导生成/注入）")

        common = [
            "-i", str(priv),
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=NUL",
            "-o", "HostKeyAlgorithms=+ssh-rsa",
            "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
            "-o", "ConnectTimeout=5",
            "-o", "BatchMode=yes",
            "-o", "PreferredAuthentications=publickey",
        ]
        return str(ssh), str(scp), host, port, user, common

    def _require_nat(self, cfg: LaunchConfig):
        if cfg.net_mode != "nat":
            raise RuntimeError("当前为 Bridge 模式：上传/chroot 仅支持 NAT(127.0.0.1 端口转发)。")

    def _run_ssh(self, cfg: LaunchConfig, remote_cmd: str, timeout=180) -> str:
        self._require_nat(cfg)
        ssh, _, host, port, user, common = self._ssh_args_common(cfg)
        cmd = [ssh, "-p", str(port)] + common + [f"{user}@{host}", remote_cmd]
        self.append_log("SSH: " + " ".join(cmd))
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            raise RuntimeError(f"ssh 执行失败:\n{p.stderr or p.stdout}")
        return p.stdout

    def _run_scp_put(self, cfg: LaunchConfig, local_path: str, remote_path: str, timeout=300):
        self._require_nat(cfg)
        _, scp, host, port, user, common = self._ssh_args_common(cfg)
        cmd = [scp, "-P", str(port)] + common + [local_path, f"{user}@{host}:{remote_path}"]
        self.append_log("SCP: " + " ".join(cmd))
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            raise RuntimeError(f"scp 上传失败:\n{p.stderr or p.stdout}")

    # ---- pickers
    def pick_qemu(self):
        p, _ = QFileDialog.getOpenFileName(self, "选择 qemu-system-*.exe", str(APP_DIR), "EXE (*.exe);;All (*.*)")
        if p:
            self.ed_qemu.setText(p)

    def pick_kernel(self):
        p, _ = QFileDialog.getOpenFileName(self, "选择 Kernel", str(APP_DIR), "All (*.*)")
        if p:
            self.ed_kernel.setText(p)

    def pick_disk(self):
        p, _ = QFileDialog.getOpenFileName(self, "选择 Disk", str(APP_DIR), "Disk (*.qcow2 *.img *.raw *.vhdx *.vmdk);;All (*.*)")
        if p:
            self.ed_disk.setText(p)

    # ---- network UI
    def pf_add(self, default=None):
        r = self.tbl_pf.rowCount()
        self.tbl_pf.insertRow(r)
        proto, hp, gp = default if default else ("tcp", "8080", "80")
        self.tbl_pf.setItem(r, 0, QTableWidgetItem(str(proto)))
        self.tbl_pf.setItem(r, 1, QTableWidgetItem(str(hp)))
        self.tbl_pf.setItem(r, 2, QTableWidgetItem(str(gp)))

    def pf_del(self):
        rows = sorted({idx.row() for idx in self.tbl_pf.selectedIndexes()}, reverse=True)
        for r in rows:
            self.tbl_pf.removeRow(r)

    def on_net_mode_changed(self, mode: str):
        is_nat = (mode == "nat")
        self.tbl_pf.setEnabled(is_nat)
        self.ed_tap.setEnabled(not is_nat)

    def refresh_host_ip(self):
        parts = []
        for name, addrs in psutil.net_if_addrs().items():
            ipv4s = [a.address for a in addrs if getattr(a, "family", None) == 2]
            if ipv4s:
                parts.append(f"{name}: {', '.join(ipv4s)}")
        full = " | ".join(parts) if parts else "未检测到 IPv4"
        short = full if len(full) <= 90 else (full[:90] + "...")
        self.lb_ip.setText(short)
        self.lb_ip.setToolTip(full)
        self.append_log("已刷新宿主 IP。")

    # ---- QEMU detection
    def autofill_qemu_for_arch(self, arch: str):
        names = QEMU_TARGETS.get(arch, [])
        found = which_any(names)
        if found:
            self.ed_qemu.setText(found)
            v = run_first_line([found, "--version"]) or "(unknown version)"
            self.lb_qemu_detect.setText(f"PATH 找到：{Path(found).name} / {v}")
        else:
            self.lb_qemu_detect.setText("PATH 未找到该架构 QEMU，请手动选择 qemu-system-*.exe")

    # ---- config
    def read_port_forwards(self) -> list[PortForward]:
        pfs: list[PortForward] = []
        for r in range(self.tbl_pf.rowCount()):
            proto = (self.tbl_pf.item(r, 0).text() if self.tbl_pf.item(r, 0) else "tcp").strip().lower()
            hp = int((self.tbl_pf.item(r, 1).text() if self.tbl_pf.item(r, 1) else "0").strip())
            gp = int((self.tbl_pf.item(r, 2).text() if self.tbl_pf.item(r, 2) else "0").strip())
            if proto not in ("tcp", "udp"):
                raise RuntimeError(f"端口转发第 {r+1} 行 proto 必须是 tcp/udp")
            if not (1 <= hp <= 65535 and 1 <= gp <= 65535):
                raise RuntimeError(f"端口转发第 {r+1} 行端口范围必须 1-65535")
            pfs.append(PortForward(proto=proto, host_port=hp, guest_port=gp))
        return pfs

    def build_config(self) -> LaunchConfig:
        arch = self.cb_arch.currentText().strip()
        qemu_path = self.ed_qemu.text().strip()
        kernel = self.ed_kernel.text().strip()
        disk = self.ed_disk.text().strip()

        qemu_img = which_any(["qemu-img.exe", "qemu-img"])
        if not qemu_path:
            found = which_any(QEMU_TARGETS.get(arch, []))
            if found:
                qemu_path = found
                self.ed_qemu.setText(found)

        disk_format = guess_disk_format(disk)
        pfs = self.read_port_forwards()

        ssh_fwd = 2222
        if self.cb_net_mode.currentText().strip() == "nat":
            pf_ssh = next((pf for pf in pfs if pf.proto == "tcp" and pf.guest_port == 22), None)
            if pf_ssh:
                ssh_fwd = pf_ssh.host_port

        return LaunchConfig(
            arch=arch,
            qemu_path=qemu_path,
            qemu_img_path=qemu_img,
            kernel_path=kernel,
            disk_path=disk,
            disk_format=disk_format,
            memory_mb=int(self.sp_mem.value()),
            vnc_display=int(self.sp_vnc_display.value()),
            ws_port=int(self.sp_ws_port.value()),
            net_mode=self.cb_net_mode.currentText().strip(),
            tap_ifname=self.ed_tap.text().strip(),
            port_forwards=pfs,
            ssh_forward_port=ssh_fwd,
        )

    # ---- env check
    def env_check_clicked(self):
        try:
            self.append_log("开始环境检测/安装...")
            ensure_novnc(self.append_log)
            ensure_websockify(self.append_log)

            cfg = self.build_config()
            errs = check_base_env(cfg)
            if errs:
                self.append_log("环境检测：发现问题：")
                for e in errs:
                    self.append_log(" - " + e)
                QMessageBox.warning(self, "环境不完整", "环境检测发现问题，请查看日志。")
            else:
                self.append_log("环境检测：OK")
                QMessageBox.information(self, "OK", "环境检测通过。")
        except Exception as e:
            QMessageBox.critical(self, "失败", str(e))

    # ---- noVNC + QEMU start/stop
    def start_websockify(self, ws_port: int, vnc_port: int):
        cmd = [
            sys.executable, "-m", "websockify",
            str(ws_port), f"127.0.0.1:{vnc_port}",
            "--web", str(NOVNC_DIR),
            "--wrap-mode=ignore",
        ]
        self.append_log("启动 websockify: " + " ".join(cmd))
        self.ws_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def build_qemu_cmd(self, cfg: LaunchConfig) -> list[str]:
        extra = []
        if cfg.arch == "x86_64":
            extra += ["-machine", "q35"]
        elif cfg.arch == "i386":
            extra += ["-machine", "pc"]
        elif cfg.arch == "aarch64":
            extra += ["-machine", "virt", "-cpu", "cortex-a57"]
        elif cfg.arch == "arm":
            extra += ["-machine", "virt", "-cpu", "cortex-a15"]
        elif cfg.arch in ("mips", "mipsel", "mips64", "mips64el"):
            extra += ["-machine", "malta"]
        elif cfg.arch == "riscv64":
            extra += ["-machine", "virt"]
        elif cfg.arch in ("ppc", "ppc64"):
            extra += ["-machine", "g3beige"]

        display = ["-display", f"vnc=127.0.0.1:{cfg.vnc_display}"]
        out = ["-nographic"] if self.chk_nographic.isChecked() else []

        if cfg.arch in ("mips", "mipsel", "mips64", "mips64el"):
            drive = ["-hda", cfg.disk_path]
        else:
            drive = ["-drive", f"file={cfg.disk_path},format={cfg.disk_format},if=virtio"]

        kappend = self.ed_kernel_append.text().strip()
        kernel = ["-kernel", cfg.kernel_path, "-append", kappend]

        if cfg.net_mode == "nat":
            hostfwd_args = [f"hostfwd={pf.proto}::{pf.host_port}-:{pf.guest_port}" for pf in cfg.port_forwards]
            netdev = ["-netdev", "user,id=n1," + ",".join(hostfwd_args)]
            netcard = ["-device", "e1000,netdev=n1"] if cfg.arch in ("mips", "mipsel", "mips64", "mips64el") else ["-device", "virtio-net-pci,netdev=n1"]
        else:
            netdev = ["-netdev", f"tap,id=n1,ifname={cfg.tap_ifname},script=no,downscript=no"]
            netcard = ["-device", "e1000,netdev=n1"]

        return [cfg.qemu_path, "-m", str(cfg.memory_mb)] + out + display + kernel + drive + netdev + netcard + extra

    def start_qemu(self, cfg: LaunchConfig):
        cmd = self.build_qemu_cmd(cfg)
        self.append_log("启动 QEMU: " + " ".join(cmd))
        self.qemu_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def load_novnc(self, ws_port: int):
        url = QUrl(
            f"http://127.0.0.1:{ws_port}/vnc.html"
            f"?host=127.0.0.1&port={ws_port}&path=websockify"
            f"&resize=scale&scaling=local"
        )
        self.append_log(f"加载 noVNC: {url.toString()}")
        self.web.load(url)
        self.right_stack.setCurrentWidget(self.web)

    def start_clicked(self):
        try:
            ensure_novnc(self.append_log)
            ensure_websockify(self.append_log)

            cfg = self.build_config()
            errs = check_base_env(cfg)
            if errs:
                raise RuntimeError("环境检测失败：\n- " + "\n- ".join(errs))

            self.ed_ssh_port.setText(str(cfg.ssh_forward_port))

            self.stop_clicked()

            vnc_port = 5900 + cfg.vnc_display
            self.start_websockify(cfg.ws_port, vnc_port)
            time.sleep(0.4)

            self.load_novnc(cfg.ws_port)
            self.start_qemu(cfg)

            host, user = self.ssh_conf()
            self.append_log(f"SSH Key 登录（System32 OpenSSH）：{user}@{host}:{cfg.ssh_forward_port}")
            self.set_ssh_actions_enabled(True)

        except Exception as e:
            QMessageBox.critical(self, "启动失败", str(e))

    def stop_clicked(self):
        self.right_stack.setCurrentWidget(self.right_placeholder)
        for name, proc in [("QEMU", self.qemu_proc), ("websockify", self.ws_proc)]:
            if proc and proc.poll() is None:
                self.append_log(f"停止 {name}...")
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        self.qemu_proc = None
        self.ws_proc = None

    # ----------------------------
    # Upload / Chroot / Umount (ssh/scp key login)
    # ----------------------------
    def upload_clicked(self):
        try:
            cfg = self.build_config()
            self._require_nat(cfg)

            local_dir = QFileDialog.getExistingDirectory(self, "选择固件 rootfs 目录（包含 etc/bin/dev/proc...）", str(APP_DIR))
            if not local_dir:
                return

            tar_path = str(WORK_DIR / f"rootfs_{int(time.time())}.tar")
            self.append_log(f"打包目录：{local_dir} -> {tar_path}")
            make_tar_of_dir(local_dir, tar_path)

            try:
                self.append_log(f"上传到 guest：{REMOTE_TAR}")
                self._run_scp_put(cfg, tar_path, REMOTE_TAR)

                self.append_log(f"解包到：{REMOTE_ROOTFS}")
                cmd = f"mkdir -p {REMOTE_ROOTFS} && rm -rf {REMOTE_ROOTFS}/* && tar -xf {REMOTE_TAR} -C {REMOTE_ROOTFS}"
                self._run_ssh(cfg, cmd, timeout=600)

                self.append_log("上传并解包完成。")
                QMessageBox.information(self, "完成", f"已上传并解包到 {REMOTE_ROOTFS}")
            finally:
                try:
                    Path(tar_path).unlink(missing_ok=True)
                except Exception:
                    pass

        except Exception as e:
            QMessageBox.critical(self, "上传失败", str(e))

    def chroot_clicked(self):
        """
        合并：mount + 进入 chroot
        进入 chroot 需要交互式 shell：这里在 Windows 新开控制台执行 ssh。
        """
        try:
            cfg = self.build_config()
            self._require_nat(cfg)

            self.append_log("准备 chroot：mount /dev /proc /sys ...")
            mount_cmd = (
                f"mkdir -p {REMOTE_ROOTFS}/{{proc,sys,dev}}; "
                f"mount --bind /dev {REMOTE_ROOTFS}/dev || true; "
                f"mount -t proc proc {REMOTE_ROOTFS}/proc || true; "
                f"mount -t sysfs sys {REMOTE_ROOTFS}/sys || true; "
                f"echo '[+] mounted ok';"
            )
            self._run_ssh(cfg, mount_cmd, timeout=120)

            ssh, _, host, port, user, common = self._ssh_args_common(cfg)
            chroot_cmd = f"chroot {REMOTE_ROOTFS} /bin/sh"
            cmd_list = [ssh, "-tt", "-p", str(port)] + common + [f"{user}@{host}", chroot_cmd]

            self.append_log("打开新终端进入 chroot（OpenSSH key 登录）...")
            # 关键：不要 join 给 cmd.exe 解析，直接传列表给 ssh
            subprocess.Popen(cmd_list, creationflags=subprocess.CREATE_NEW_CONSOLE)

        except Exception as e:
            QMessageBox.critical(self, "chroot 失败", str(e))

    def umount_clicked(self):
        try:
            cfg = self.build_config()
            self._require_nat(cfg)

            cmd = (
                f"umount -l {REMOTE_ROOTFS}/proc 2>/dev/null || true; "
                f"umount -l {REMOTE_ROOTFS}/sys  2>/dev/null || true; "
                f"umount -l {REMOTE_ROOTFS}/dev  2>/dev/null || true; "
                f"echo '[+] umount done';"
            )
            self._run_ssh(cfg, cmd, timeout=60)
            self.append_log("卸载完成。")
            QMessageBox.information(self, "完成", "卸载完成。")
        except Exception as e:
            QMessageBox.critical(self, "卸载失败", str(e))

    def closeEvent(self, event):
        try:
            self.stop_clicked()
        finally:
            super().closeEvent(event)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = Main()
    g = app.primaryScreen().availableGeometry()
    w.resize(int(g.width() * 0.78), int(g.height() * 0.82))
    w.show()
    w.move(w.x(), max(0, w.y() - 40))
    sys.exit(app.exec())
