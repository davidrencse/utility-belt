"""
Network tool - a keyless internet speed test plus live Wi-Fi and internet
details.

Speed test uses Cloudflare's public endpoints (speed.cloudflare.com, no API
key): latency + jitter from small requests on a warm connection, download
and upload throughput from 4 parallel streams with the slow-start window
excluded. Wi-Fi details come from `netsh wlan show interfaces`;
public IP / ISP from ip-api.com; local IP / gateway / DNS from the reused
net_recon engine. All network work runs on worker threads.
"""
import http.client
import os
import re
import statistics
import subprocess
import threading
import time
import urllib.request

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QPushButton, QGridLayout)

from ..core import bridge as eng
from .. import theme as T

_NOWIN = 0x08000000
_UA = {"User-Agent": "sysmon-overlay"}


def _run(cmd, timeout=8):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, creationflags=_NOWIN)
        return (p.stdout or "") + (p.stderr or "")
    except (subprocess.TimeoutExpired, OSError):
        return ""


_HOST = "speed.cloudflare.com"
_STREAMS = 4                  # parallel connections, like browser speed tests
_TEST_S = 8.0                 # per direction
_WARMUP_S = 1.5               # TCP slow start - excluded from the result
_TCP_RTT = re.compile(r"[?&]rtt=(\d+)")        # microseconds
_TCP_VAR = re.compile(r"[?&]rtt_var=(\d+)")


def _conn():
    c = http.client.HTTPSConnection(_HOST, timeout=10, blocksize=65536)
    c.connect()
    return c


class _Upload:
    """File-like request body that counts bytes as http.client sends them."""

    def __init__(self, size, chunk, meter):
        self._left, self._chunk, self._meter = size, chunk, meter

    def read(self, n=-1):
        if self._left <= 0:
            return b""
        n = min(self._left, len(self._chunk) if n is None or n < 0 else n,
                len(self._chunk))
        self._left -= n
        self._meter.add(n)
        return self._chunk[:n]


def _num(v):
    """Whole numbers once they're big enough; one decimal below 10."""
    return f"{v:.1f}" if v < 10 else f"{v:.0f}"


class _Meter:
    """Thread-safe byte counter with a timestamped history, so the result
    can exclude the warm-up window and partials can show a rolling rate."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total = 0
        self.t0 = time.perf_counter()
        self.hist = [(self.t0, 0)]

    def add(self, n):
        with self._lock:
            self.total += n

    def mark(self):
        with self._lock:
            self.hist.append((time.perf_counter(), self.total))

    def at(self, t):
        """Bytes transferred by time t (linear between marks)."""
        h = self.hist
        for (ta, ba), (tb, bb) in zip(h, h[1:]):
            if ta <= t <= tb:
                return ba + (bb - ba) * ((t - ta) / (tb - ta) if tb > ta else 1)
        return h[-1][1] if t > h[-1][0] else 0

    def mbps(self, start, end):
        return max(0.0, self.at(end) - self.at(start)) * 8 / max(1e-3, end - start) / 1e6


class SpeedWorker(QThread):
    phase = Signal(str)              # "ping" / "download" / "upload"
    partial = Signal(str, float)     # phase, mbps so far
    done = Signal(dict)
    fail = Signal(str)

    def run(self):
        try:
            self.phase.emit("ping")
            ping, jitter = self._latency()

            self.phase.emit("download")
            down = self._measure("download", self._down_stream)

            self.phase.emit("upload")
            up = self._measure("upload", self._up_stream)

            self.done.emit({"down": down, "up": up, "ping": ping, "jitter": jitter})
        except Exception as exc:
            self.fail.emit(f"{type(exc).__name__}: {exc}")

    @staticmethod
    def _latency(n=12):
        """Latency on one warm keep-alive connection (DNS/TCP/TLS setup not
        counted). Cloudflare reports its kernel's TCP RTT and RTT variance
        for the connection (Server-Timing cfL4); that excludes server
        processing time, so it is preferred. Otherwise fall back to the
        client-side request time, with jitter as the mean absolute
        difference between consecutive samples (Speedtest / RFC 3550)."""
        c = _conn()
        try:
            c.request("GET", "/__down?bytes=0", headers=_UA)
            c.getresponse().read()                   # warm-up
            lat, tcp_rtt, tcp_var = [], [], []
            for _ in range(n):
                t0 = time.perf_counter()
                c.request("GET", "/__down?bytes=0", headers=_UA)
                r = c.getresponse()
                lat.append((time.perf_counter() - t0) * 1000)
                r.read()
                timing = r.getheader("Server-Timing") or ""
                m = _TCP_RTT.search(timing)
                v = _TCP_VAR.search(timing)
                if m:
                    tcp_rtt.append(int(m.group(1)) / 1000)
                if v:
                    tcp_var.append(int(v.group(1)) / 1000)
        finally:
            c.close()
        if len(tcp_rtt) >= n // 2:
            return (statistics.median(tcp_rtt),
                    statistics.median(tcp_var) if tcp_var else 0.0)
        diffs = [abs(a - b) for a, b in zip(lat, lat[1:])]
        return statistics.median(lat), (statistics.fmean(diffs) if diffs else 0.0)

    @staticmethod
    def _down_stream(meter, end):
        c = _conn()
        try:
            while time.perf_counter() < end:
                # the endpoint rejects (403) bodies much above 25 MB
                c.request("GET", f"/__down?bytes={25_000_000}", headers=_UA)
                r = c.getresponse()
                if r.status != 200:
                    raise OSError(f"download HTTP {r.status}")
                while time.perf_counter() < end:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    meter.add(len(chunk))
                else:
                    break                        # deadline mid-body: drop conn
        finally:
            c.close()

    @staticmethod
    def _up_stream(meter, end):
        chunk = os.urandom(65536)                # incompressible payload
        size = 8_000_000
        c = _conn()
        try:
            while time.perf_counter() < end:
                hdr = dict(_UA, **{"Content-Length": str(size),
                                   "Content-Type": "application/octet-stream"})
                c.request("POST", "/__up", body=_Upload(size, chunk, meter),
                          headers=hdr)
                r = c.getresponse()
                r.read()
                if r.status != 200:
                    raise OSError(f"upload HTTP {r.status}")
        finally:
            c.close()

    def _measure(self, phase, stream):
        meter = _Meter()
        start = meter.t0
        end = start + _TEST_S
        errors = []

        def worker():
            try:
                stream(meter, end)
            except Exception as exc:             # a late stream error is fine
                errors.append(exc)

        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(_STREAMS)]
        for t in threads:
            t.start()
        while (now := time.perf_counter()) < end:
            time.sleep(0.1)
            meter.mark()
            if now - start >= 0.5:               # rolling 1 s rate
                self.partial.emit(phase, meter.mbps(max(start, now - 1.0), now))
        meter.mark()
        for t in threads:
            t.join(timeout=3)
        if meter.total == 0 and errors:
            raise errors[0]
        return meter.mbps(start + _WARMUP_S, end)


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
            lambda p, m: (self.s_down if p == "download" else self.s_up).set(_num(m)))
        self.speed.done.connect(self._speed_done)
        self.speed.fail.connect(lambda m: (self.status.setText("error: " + m),
                                           self.run_btn.setEnabled(True)))
        self.speed.start()

    def _speed_done(self, d):
        self.s_down.set(_num(d["down"]))
        self.s_up.set(_num(d["up"]))
        self.s_ping.set(_num(d["ping"]))
        self.s_jit.set(_num(d["jitter"]))
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
