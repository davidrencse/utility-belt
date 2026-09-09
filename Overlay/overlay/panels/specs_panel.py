"""
Specs panel - a Task-Manager-style read-out of this Windows 11 PC: name,
OS, CPU/GPU/RAM/disk/board, network adapters, and saved Wi-Fi networks with
passwords.

Everything reuses the existing engine (system_info.gather, net_recon.
get_local_network_info); the slow bits (a PowerShell CIM call, ipconfig)
run on a worker so opening the tab never freezes the HUD. Wi-Fi passwords
come from `netsh wlan show profile key=clear` on THIS machine (the user's own
saved networks) and are only fetched when the user clicks the reveal button.
"""
import re
import subprocess

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QPushButton, QScrollArea, QFrame)

from ..core import bridge as eng
from .. import theme as T

_NOWIN = 0x08000000  # CREATE_NO_WINDOW (Popen is also patched globally)


def _run(cmd, timeout=12):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, creationflags=_NOWIN)
        return (p.stdout or "") + (p.stderr or "")
    except (subprocess.TimeoutExpired, OSError):
        return ""


class SpecsWorker(QThread):
    """Gathers the static specs + network + current Wi-Fi SSID off-thread."""
    done = Signal(dict)

    def run(self):
        out = {"sys": {}, "net": {}, "ssid": None}
        try:
            if eng.ENGINE_OK:
                out["sys"] = eng.system_info.gather()  # slow: CIM/PowerShell
                out["net"] = eng.net_recon.get_local_network_info()
        except Exception as exc:
            out["error"] = f"{type(exc).__name__}: {exc}"
        text = _run(["netsh", "wlan", "show", "interfaces"], timeout=6)
        m = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", text, re.M)
        if m:
            out["ssid"] = m.group(1)
        self.done.emit(out)


class WifiWorker(QThread):
    """Lists saved WLAN profiles and their cleartext keys (user's own PC)."""
    done = Signal(list)

    def run(self):
        results = []
        listing = _run(["netsh", "wlan", "show", "profiles"], timeout=8)
        names = re.findall(r"All User Profile\s*:\s*(.+?)\s*$", listing, re.M)
        names += re.findall(r"User Profile\s*:\s*(.+?)\s*$", listing, re.M)
        seen = set()
        for name in names:
            if name in seen:
                continue
            seen.add(name)
            detail = _run(["netsh", "wlan", "show", "profile",
                           f"name={name}", "key=clear"], timeout=8)
            key = re.search(r"Key Content\s*:\s*(.+?)\s*$", detail, re.M)
            auth = re.search(r"Authentication\s*:\s*(.+?)\s*$", detail, re.M)
            results.append({
                "ssid": name,
                "password": key.group(1) if key else "(none / open)",
                "auth": auth.group(1) if auth else "",
            })
        self.done.emit(results)


class SpecsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._built_rows = False
        self._revealed = False
        self._build()
        self._load()

    # -- scaffolding -------------------------------------------------------
    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background:transparent;")
        outer.addWidget(scroll)
        body = QWidget(); body.setStyleSheet("background:transparent;")
        self.col = QVBoxLayout(body)
        self.col.setContentsMargins(14, 8, 14, 12)
        self.col.setSpacing(3)
        scroll.setWidget(body)

        self.status = QLabel("reading system information…")
        self.status.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:8pt '{T.MONO}';")
        self.col.addWidget(self.status)
        self.col.addStretch(1)

    def _section(self, title):
        lbl = QLabel(title.upper())
        lbl.setStyleSheet(
            f"color:{T.hexs(T.TEXT_DIM)};font:700 7pt '{T.MONO}';letter-spacing:2px;"
            "margin-top:9px;")
        self.col.insertWidget(self.col.count() - 1, lbl)

    def _kv(self, key, value):
        if value in (None, "", "None"):
            value = "—"
        row = QHBoxLayout(); row.setSpacing(8)
        k = QLabel(key)
        k.setFixedWidth(118)
        k.setStyleSheet(f"color:{T.hexs(T.TEXT_MUTED)};font:8pt '{T.UI}';")
        v = QLabel(str(value))
        v.setStyleSheet(f"color:{T.hexs(T.TEXT)};font:8pt '{T.MONO}';")
        v.setTextInteractionFlags(Qt.TextSelectableByMouse)
        v.setWordWrap(True)
        row.addWidget(k)
        row.addWidget(v, 1)
        w = QWidget(); w.setLayout(row)
        self.col.insertWidget(self.col.count() - 1, w)
        return v

    # -- load --------------------------------------------------------------
    def _load(self):
        self.worker = SpecsWorker(self)
        self.worker.done.connect(self._populate)
        self.worker.start()

    def _populate(self, data):
        if self._built_rows:
            return
        self._built_rows = True
        self.status.hide()
        s = data.get("sys", {}) or {}
        n = data.get("net", {}) or {}

        self._section("System")
        self._kv("PC name", s.get("hostname") or n.get("hostname"))
        self._kv("Model", s.get("model"))
        self._kv("Motherboard", s.get("board"))
        self._kv("OS", s.get("os"))
        self._kv("OS build", s.get("os_version"))
        self._kv("Architecture", s.get("arch"))
        self._kv("Uptime", s.get("uptime"))

        self._section("Processor")
        cores = s.get("cpu_cores")
        self._kv("CPU", s.get("cpu"))
        self._kv("Logical cores", cores)

        self._section("Graphics")
        self._kv("GPU", s.get("gpu"))

        self._section("Memory")
        self._kv("Installed RAM", f"{s.get('ram_total_gb')} GB" if s.get("ram_total_gb") else None)
        self._kv("Available", f"{s.get('ram_available_gb')} GB" if s.get("ram_available_gb") else None)

        self._section("Storage")
        tot, used = s.get("disk_total_gb"), s.get("disk_used_gb")
        self._kv("System drive", f"{used} / {tot} GB used" if tot else None)

        self._section("Network")
        self._kv("Primary IP", n.get("primary_ip"))
        for a in (n.get("adapters") or [])[:4]:
            self._kv("Adapter", a.get("name"))
            self._kv("  IPv4", a.get("ipv4"))
            self._kv("  Gateway", a.get("gateway"))
            self._kv("  MAC", a.get("mac"))
            if a.get("dns_servers"):
                self._kv("  DNS", ", ".join(a["dns_servers"]))

        self._section("Wi-Fi")
        self._kv("Connected SSID", data.get("ssid"))
        self.reveal_btn = QPushButton("Reveal saved Wi-Fi passwords")
        self.reveal_btn.setCursor(Qt.PointingHandCursor)
        self.reveal_btn.setStyleSheet(T.ghost_btn_qss())
        self.reveal_btn.clicked.connect(self._reveal_wifi)
        self.col.insertWidget(self.col.count() - 1, self.reveal_btn)
        self.wifi_note = QLabel("saved networks on this PC · your own credentials")
        self.wifi_note.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:7pt '{T.MONO}';")
        self.col.insertWidget(self.col.count() - 1, self.wifi_note)

    # -- wifi reveal -------------------------------------------------------
    def _reveal_wifi(self):
        if self._revealed:
            return
        self.reveal_btn.setEnabled(False)
        self.reveal_btn.setText("reading saved networks…")
        self.wifi_worker = WifiWorker(self)
        self.wifi_worker.done.connect(self._show_wifi)
        self.wifi_worker.start()

    def _show_wifi(self, networks):
        self._revealed = True
        self.reveal_btn.hide()
        if not networks:
            self.wifi_note.setText("no saved Wi-Fi profiles found (or netsh unavailable)")
            return
        self.wifi_note.setText(f"{len(networks)} saved network(s):")
        for net in networks:
            self._kv(net["ssid"], net["password"])

    def shutdown(self):
        for w in ("worker", "wifi_worker"):
            t = getattr(self, w, None)
            if t and t.isRunning():
                t.wait(1500)
