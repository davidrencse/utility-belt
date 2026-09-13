"""
Network tool - a keyless internet speed test plus live Wi-Fi and internet
details.

Speed test uses Cloudflare's public endpoints (speed.cloudflare.com, no API
key): latency + jitter from small requests, download and upload throughput
from timed transfers. Wi-Fi details come from `netsh wlan show interfaces`;
public IP / ISP from ip-api.com; local IP / gateway / DNS from the reused
net_recon engine. All network work runs on worker threads.
"""
import re
import statistics
import subprocess
import time
import urllib.request

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QPushButton, QGridLayout)

from ..core import bridge as eng
from .. import theme as T

_NOWIN = 0x08000000
_DOWN = "https://speed.cloudflare.com/__down?bytes={}"
_UP = "https://speed.cloudflare.com/__up"
_UA = {"User-Agent": "sysmon-overlay"}


def _run(cmd, timeout=8):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, creationflags=_NOWIN)
        return (p.stdout or "") + (p.stderr or "")
    except (subprocess.TimeoutExpired, OSError):
        return ""


class SpeedWorker(QThread):
    phase = Signal(str)              # "ping" / "download" / "upload"
    partial = Signal(str, float)     # phase, mbps so far
    done = Signal(dict)
    fail = Signal(str)

    def run(self):
        try:
            self.phase.emit("ping")
            lat = []
            for _ in range(6):
                t0 = time.perf_counter()
                urllib.request.urlopen(
                    urllib.request.Request(_DOWN.format(1), headers=_UA),
                    timeout=8).read()
                lat.append((time.perf_counter() - t0) * 1000)
            ping = statistics.median(lat)
            jitter = statistics.pstdev(lat)

            self.phase.emit("download")
            down = self._download()

            self.phase.emit("upload")
            up = self._upload()

            self.done.emit({"down": down, "up": up, "ping": ping, "jitter": jitter})
        except Exception as exc:
            self.fail.emit(f"{type(exc).__name__}: {exc}")

    def _download(self):
        req = urllib.request.Request(_DOWN.format(300_000_000), headers=_UA)
        got = 0
        t0 = time.perf_counter()
        last = t0
        with urllib.request.urlopen(req, timeout=15) as r:
            while True:
                chunk = r.read(262144)
                if not chunk:
                    break
                got += len(chunk)
                now = time.perf_counter()
                if now - last >= 0.4:
                    self.partial.emit("download", got * 8 / (now - t0) / 1e6)
                    last = now
                if now - t0 >= 6.0:
                    break
        el = max(0.05, time.perf_counter() - t0)
        return got * 8 / el / 1e6

    def _upload(self):
        payload = b"0" * 12_000_000
        req = urllib.request.Request(_UP, data=payload, headers=_UA, method="POST")
        t0 = time.perf_counter()
        urllib.request.urlopen(req, timeout=20).read()
        el = max(0.05, time.perf_counter() - t0)
        return len(payload) * 8 / el / 1e6


class InfoWorker(QThread):
    done = Signal(dict)

    def run(self):
        out = {"wifi": self._wifi(), "net": None, "pub": None}
        try:
            if eng.ENGINE_OK:
                out["net"] = eng.net_recon.get_local_network_info()
        except Exception:
            pass
        try:
            import json
            req = urllib.request.Request(
                "http://ip-api.com/json/?fields=status,query,isp,org,as,city,"
                "regionName,country,timezone", headers=_UA)
            with urllib.request.urlopen(req, timeout=8) as r:
                out["pub"] = json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            pass
        self.done.emit(out)

    @staticmethod
    def _wifi():
        text = _run(["netsh", "wlan", "show", "interfaces"], timeout=6)
        if not text:
            return None

        def g(label):
            m = re.search(rf"^\s*{label}\s*:\s*(.+?)\s*$", text, re.M)
            return m.group(1) if m else None

        if not g("SSID"):
            return {}
        return {
            "ssid": g("SSID"), "bssid": g("BSSID"), "radio": g("Radio type"),
            "auth": g("Authentication"), "band": g("Band"), "channel": g("Channel"),
            "signal": g("Signal"), "rx": g(r"Receive rate \(Mbps\)"),
            "tx": g(r"Transmit rate \(Mbps\)"),
        }


class _Stat(QWidget):
    def __init__(self, label, big=True, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self); lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(0)
        self._v = QLabel("—")
        size = "300 30pt" if big else "600 12pt"
        self._v.setStyleSheet(f"color:{T.hexs(T.TEXT)};font:{size} '{T.UI}';")
        k = QLabel(label.upper())
        k.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:700 7pt '{T.MONO}';"
                        "letter-spacing:1px;")
        lay.addWidget(self._v); lay.addWidget(k)

    def set(self, v):
        self._v.setText(str(v))


class _Card(QWidget):
    def __init__(self, title, rows, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setObjectName("card")
        self.setStyleSheet(f"QWidget#card{{background:{T.rgba(QColor(255,255,255,8))};"
                           f"border:1px solid {T.rgba(T.BORDER_SOFT)};"
                           f"border-radius:{T.R_CTRL + 2}px;}}")
        lay = QVBoxLayout(self); lay.setContentsMargins(13, 11, 13, 11); lay.setSpacing(7)
        t = QLabel(title.upper())
        t.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:700 8pt '{T.MONO}';"
                        "letter-spacing:2px;border:none;background:transparent;")
        lay.addWidget(t)
        grid = QGridLayout(); grid.setVerticalSpacing(4); grid.setHorizontalSpacing(10)
        self._v = {}
        for i, key in enumerate(rows):
            k = QLabel(key)
            k.setStyleSheet(f"color:{T.hexs(T.TEXT_MUTED)};font:9pt '{T.UI}';"
                            "border:none;background:transparent;")
            v = QLabel("—")
            v.setStyleSheet(f"color:{T.hexs(T.TEXT)};font:600 10pt '{T.MONO}';"
                            "border:none;background:transparent;")
            v.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            grid.addWidget(k, i, 0); grid.addWidget(v, i, 1)
            self._v[key] = v
        grid.setColumnStretch(1, 1)
        lay.addLayout(grid); lay.addStretch(1)

    def set(self, key, v):
        if key in self._v and v not in (None, "", "None"):
            self._v[key].setText(str(v))


class NetPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.speed = None
        self.info = None
        self._build()
        self._load_info()

    def _build(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(14, 12, 14, 12)
        root.setSpacing(12)

        # left: speed test
        left = QVBoxLayout(); left.setSpacing(10)
        title = QLabel("SPEED TEST")
        title.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:700 8pt '{T.MONO}';"
                            "letter-spacing:2px;")
        left.addWidget(title)
        nums = QHBoxLayout(); nums.setSpacing(18)
        self.s_down = _Stat("Down Mbps")
        self.s_up = _Stat("Up Mbps")
        nums.addWidget(self.s_down); nums.addWidget(self.s_up)
        left.addLayout(nums)
        small = QHBoxLayout(); small.setSpacing(18)
        self.s_ping = _Stat("Ping ms", big=False)
        self.s_jit = _Stat("Jitter ms", big=False)
        small.addWidget(self.s_ping); small.addWidget(self.s_jit); small.addStretch(1)
        left.addLayout(small)
        self.run_btn = QPushButton("Run speed test")
        self.run_btn.setCursor(Qt.PointingHandCursor)
        self.run_btn.setStyleSheet(T.primary_btn_qss())
        self.run_btn.clicked.connect(self._run_speed)
        left.addWidget(self.run_btn)
        self.status = QLabel("Cloudflare · no API key")
        self.status.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:8pt '{T.MONO}';")
        left.addWidget(self.status)
        left.addStretch(1)
        root.addLayout(left, 3)

        # right: wifi + internet cards
        self.wifi = _Card("Wi-Fi", ["SSID", "Signal", "Band", "Channel",
                                    "Radio", "Rx / Tx", "Security", "BSSID"])
        self.inet = _Card("Internet", ["Public IP", "ISP", "ASN", "Location",
                                       "Local IP", "Gateway", "DNS"])
        root.addWidget(self.wifi, 2)
        root.addWidget(self.inet, 2)

    # -- speed test --------------------------------------------------------
    def _run_speed(self):
        if self.speed and self.speed.isRunning():
            return
        self.run_btn.setEnabled(False)
        self.s_down.set("—"); self.s_up.set("—")
        self.speed = SpeedWorker(self)
        self.speed.phase.connect(lambda p: self.status.setText(f"testing {p}…"))
        self.speed.partial.connect(
            lambda p, m: self.s_down.set(f"{m:.0f}") if p == "download" else None)
        self.speed.done.connect(self._speed_done)
        self.speed.fail.connect(lambda m: (self.status.setText("error: " + m),
                                           self.run_btn.setEnabled(True)))
        self.speed.start()

    def _speed_done(self, d):
        self.s_down.set(f"{d['down']:.0f}")
        self.s_up.set(f"{d['up']:.0f}")
        self.s_ping.set(f"{d['ping']:.0f}")
        self.s_jit.set(f"{d['jitter']:.0f}")
        self.status.setText("Cloudflare · done")
        self.run_btn.setEnabled(True)

    # -- info --------------------------------------------------------------
    def _load_info(self):
        self.info = InfoWorker(self)
        self.info.done.connect(self._info_done)
        self.info.start()

    def _info_done(self, d):
        w = d.get("wifi")
        if w is None:
            self.wifi.set("SSID", "no Wi-Fi adapter")
        elif w == {}:
            self.wifi.set("SSID", "not connected")
        else:
            self.wifi.set("SSID", w.get("ssid"))
            self.wifi.set("Signal", w.get("signal"))
            self.wifi.set("Band", w.get("band"))
            self.wifi.set("Channel", w.get("channel"))
            self.wifi.set("Radio", w.get("radio"))
            if w.get("rx") or w.get("tx"):
                self.wifi.set("Rx / Tx", f"{w.get('rx','?')} / {w.get('tx','?')} Mbps")
            self.wifi.set("Security", w.get("auth"))
            self.wifi.set("BSSID", w.get("bssid"))

        pub, net = d.get("pub"), d.get("net")
        if pub and pub.get("status") == "success":
            self.inet.set("Public IP", pub.get("query"))
            self.inet.set("ISP", pub.get("isp"))
            self.inet.set("ASN", (pub.get("as") or "").split(" ")[0] or "—")
            self.inet.set("Location", f"{pub.get('city','')}, {pub.get('country','')}"
                          .strip(", "))
        if net:
            self.inet.set("Local IP", net.get("primary_ip"))
            a = (net.get("adapters") or [None])[0]
            if a:
                self.inet.set("Gateway", a.get("gateway"))
                if a.get("dns_servers"):
                    self.inet.set("DNS", ", ".join(a["dns_servers"][:2]))

    def shutdown(self):
        for w in (self.speed, self.info):
            if w and w.isRunning():
                w.wait(2000)
