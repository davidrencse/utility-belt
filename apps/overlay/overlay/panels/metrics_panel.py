"""
Live telemetry panel: CPU / RAM / disk gauges plus rolling sparklines for CPU
load, ping latency and network throughput.

Sampling runs on a background QThread and delivers a typed `Sample` (a
dataclass, not a loose dict) so the UI reads named fields. Cadence and ping
target come from settings; the sampler idles while the HUD is hidden.
"""
import ctypes
import threading
import time
from dataclasses import dataclass

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                               QLabel)

from ..core import bridge as eng
from ..core import netstat
from .. import theme as T
from ..settings import settings
from ..widgets import Sparkline, Gauge
from .stats_panel import _mem, _power    # reuse swap + battery readers


def _proc_count():
    # EnumProcesses silently truncates to the buffer; grow until it fits
    size = 1024
    try:
        while size <= 65536:
            arr = (ctypes.c_uint * size)()
            needed = ctypes.c_uint()
            if not ctypes.windll.psapi.EnumProcesses(
                    ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(needed)):
                return None
            if needed.value < ctypes.sizeof(arr):
                return needed.value // ctypes.sizeof(ctypes.c_uint)
            size *= 4
    except Exception:
        pass
    return None


@dataclass
class Sample:
    cpu: float | None = None
    mem_pct: float | None = None
    mem_total_gb: float | None = None
    mem_avail_gb: float | None = None
    disk_pct: float | None = None
    disk_total_gb: float | None = None
    uptime: str | None = None
    net_down_bps: float = 0.0
    net_up_bps: float = 0.0
    ping_ms: float | None = None
    swap_used_gb: float | None = None
    swap_total_gb: float | None = None
    sess_down: float = 0.0        # bytes downloaded since the app started
    sess_up: float = 0.0
    procs: int | None = None
    batt_pct: int | None = None
    batt_ac: bool = False
    batt_present: bool = True


class Sampler(QThread):
    tick = Signal(object)   # emits a Sample

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = True
        self._paused = True            # MetricsPanel unpauses once it is visible
        self._wake = threading.Event()
        self._net = netstat.NetMeter()
        self._cpu = eng.system_info.CpuMeter() if eng.ENGINE_OK else None
        # ping runs on its own thread: a 1.5 s timeout must never stall or
        # skew the CPU/net cadence. The sampler reads the latest result.
        self._ping_ms = None
        self._ping_wake = threading.Event()

    def stop(self):
        self._running = False
        self._wake.set()
        self._ping_wake.set()

    def set_paused(self, paused):
        self._paused = bool(paused)
        self._wake.set()
        self._ping_wake.set()

    def _ping_loop(self):
        while self._running:
            if self._paused:
                self._ping_ms = None
                self._ping_wake.wait()
                self._ping_wake.clear()
                continue
            t0 = time.perf_counter()
            self._ping_ms = self._ping(settings.get("ping_target"))
            wait = settings.get("sample_ms") / 1000.0 - (time.perf_counter() - t0)
            if wait > 0:
                self._ping_wake.wait(wait)
                self._ping_wake.clear()

    @staticmethod
    def _ping(target):
        try:
            return netstat.icmp_ping_ms(target, timeout=1.5)
        except Exception:
            pass
        if eng.ENGINE_OK:                  # no ICMP API: fall back to ping.exe
            try:
                return eng.net_recon.ping_host(target, timeout=1.5).get("latency_ms")
            except Exception:
                pass
        return None

    def run(self):
        threading.Thread(target=self._ping_loop, daemon=True).start()
        self._net.read()                       # prime the per-interface baseline
        i = 0
        next_at = time.perf_counter()
        while self._running:
            if self._paused:
                if self._cpu:
                    self._cpu.reset()
                self._wake.wait()          # sleep until resumed/stopped, no polling
                self._wake.clear()
                # new baseline: session totals keep the bytes that flowed while
                # paused, the rate average over the pause is discarded, and a
                # short gap keeps the first rate from being a ~0 ms delta
                self._net.read()
                if self._running and not self._paused:
                    self._wake.wait(0.25)
                    self._wake.clear()
                next_at = time.perf_counter()
                continue
            s = Sample()
            if eng.ENGINE_OK:
                s.cpu = self._cpu.read()
                dtot, _du, s.disk_pct = eng.system_info.disk()
                s.disk_total_gb = round(dtot / 1024**3, 0) if dtot else None
                s.uptime = eng.system_info.format_uptime(
                    eng.system_info.uptime_seconds())

            mem = _mem()                       # one GlobalMemoryStatusEx call
            if mem:
                rt, rf, st, sf = mem
                s.mem_total_gb = rt / 1024**3
                s.mem_avail_gb = rf / 1024**3
                s.mem_pct = round((1 - rf / rt) * 100, 1) if rt else None
                s.swap_total_gb = st / 1024**3
                s.swap_used_gb = (st - sf) / 1024**3
            elif eng.ENGINE_OK:
                tot, avail, s.mem_pct = eng.system_info.memory()
                s.mem_total_gb = tot / 1024**3 if tot else None
                s.mem_avail_gb = avail / 1024**3 if avail else None

            s.net_down_bps, s.net_up_bps = self._net.read()
            s.sess_down = self._net.session_in
            s.sess_up = self._net.session_out

            pw = _power()
            if pw:
                s.batt_present = not pw.get("no_battery")
                s.batt_pct = pw.get("pct")
                s.batt_ac = pw.get("ac") == 1

            if i % 4 == 0:                     # process count every ~4th tick
                s.procs = _proc_count()
            i += 1

            s.ping_ms = self._ping_ms

            self.tick.emit(s)
            # fixed-rate schedule (no drift): aim at absolute deadlines
            period = settings.get("sample_ms") / 1000.0
            next_at += period
            now = time.perf_counter()
            if next_at < now:                  # fell behind: don't burst
                next_at = now + period
            remaining = next_at - now
            if remaining > 0 and self._running and not self._paused:
                self._wake.wait(remaining)
                self._wake.clear()


def _fmt_bps(bps):
    if bps is None:
        return "--"
    for unit in ("B", "KB", "MB", "GB"):
        if bps < 1024:
            return f"{bps:.0f} {unit}/s"
        bps /= 1024
    return f"{bps:.0f} TB/s"


def _fmt_bytes(b):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.0f} {unit}"
        b /= 1024
    return f"{b:.0f} PB"


class MetricsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()
        self._apply_settings()
        settings.changed.connect(self._on_setting)
        self._host_paused = False
        self.sampler = Sampler(self)
        self.sampler.tick.connect(self._on_tick)
        self.sampler.start()

    def _build(self):
        # horizontal layout: gauges on the left, live graphs filling the right
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 10)
        root.setSpacing(8)

        content = QHBoxLayout()
        content.setSpacing(16)

        left = QVBoxLayout()
        left.setSpacing(10)
        gauges = QHBoxLayout()
        gauges.setSpacing(10)
        self.g_cpu = Gauge("CPU")
        self.g_mem = Gauge("RAM")
        self.g_disk = Gauge("DISK")
        for g in (self.g_cpu, self.g_mem, self.g_disk):
            gauges.addWidget(g)
        left.addLayout(gauges)

        # extra live readouts under the gauges
        left.addSpacing(4)
        grid = QGridLayout()
        grid.setVerticalSpacing(3)
        grid.setHorizontalSpacing(10)
        self._stat = {}
        for i, key in enumerate(["RAM", "Swap", "Net ↓", "Net ↑",
                                 "Procs", "Battery"]):
            k = QLabel(key)
            k.setStyleSheet(f"color:{T.hexs(T.TEXT_MUTED)};font:8pt '{T.UI}';")
            v = QLabel("—")
            v.setStyleSheet(f"color:{T.hexs(T.TEXT)};font:600 9pt '{T.MONO}';")
            v.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            grid.addWidget(k, i, 0)
            grid.addWidget(v, i, 1)
            self._stat[key] = v
        grid.setColumnStretch(1, 1)
        left.addLayout(grid)

        left.addStretch(1)
        self.status = QLabel("starting…")
        self.status.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:8pt '{T.MONO}';")
        self.status.setWordWrap(True)
        left.addWidget(self.status)
        content.addLayout(left)

        right = QVBoxLayout()
        right.setSpacing(10)
        self.sp_cpu = Sparkline(color=T.G_CPU, floor=100, unit="%")
        self.sp_ping = Sparkline(color=T.G_PING, floor=50, unit="ms")
        self.sp_net = Sparkline(color=T.G_NET, floor=1.0, unit="")
        for sp in (self.sp_cpu, self.sp_ping, self.sp_net):
            sp.setMinimumHeight(56)
            right.addWidget(sp, 1)
        content.addLayout(right, 1)

        root.addLayout(content, 1)

        if not eng.ENGINE_OK:
            self.status.setText("engine import FAILED: " + str(eng.ENGINE_ERROR))

    # -- settings ----------------------------------------------------------
    def _apply_settings(self):
        fill = bool(settings.get("graph_fill"))
        for sp in (self.sp_cpu, self.sp_ping, self.sp_net):
            sp.set_fill(fill)
        self.sp_cpu.setVisible(bool(settings.get("show_cpu")))
        self.sp_ping.setVisible(bool(settings.get("show_ping")))
        self.sp_net.setVisible(bool(settings.get("show_net")))

    def _on_setting(self, key, _value):
        if key in ("graph_fill", "show_cpu", "show_ping", "show_net"):
            self._apply_settings()

    # -- data --------------------------------------------------------------
    def _on_tick(self, s: Sample):
        if s.cpu is not None:
            self.g_cpu.set_value(s.cpu)
            self.sp_cpu.push(s.cpu)
            self.sp_cpu.set_label("CPU", f"{s.cpu:.1f}%")
        if s.mem_pct is not None:
            sub = ""
            if s.mem_total_gb:
                used = s.mem_total_gb - (s.mem_avail_gb or 0)
                sub = f"{used:.0f}/{s.mem_total_gb:.0f}G"
            self.g_mem.set_value(s.mem_pct, sub)
        if s.disk_pct is not None:
            sub = f"{s.disk_total_gb:.0f}G" if s.disk_total_gb else ""
            self.g_disk.set_value(s.disk_pct, sub)

        if s.ping_ms is not None:
            self.sp_ping.push(s.ping_ms)
            self.sp_ping.set_label(
                "Ping", f"{s.ping_ms:.1f} ms" if s.ping_ms < 10 else f"{s.ping_ms:.0f} ms")
        else:
            self.sp_ping.push(0)
            self.sp_ping.set_label("Ping", "--")

        self.sp_net.push(s.net_down_bps)
        self.sp_net.set_label(
            "Network", f"↓ {_fmt_bps(s.net_down_bps)}   ↑ {_fmt_bps(s.net_up_bps)}")

        if s.mem_total_gb:
            self._stat["RAM"].setText(
                f"{s.mem_total_gb - (s.mem_avail_gb or 0):.1f} / {s.mem_total_gb:.1f} GB")
        if s.swap_total_gb is not None:
            self._stat["Swap"].setText(f"{s.swap_used_gb:.1f} / {s.swap_total_gb:.1f} GB")
        self._stat["Net ↓"].setText(_fmt_bytes(s.sess_down))
        self._stat["Net ↑"].setText(_fmt_bytes(s.sess_up))
        if s.procs is not None:
            self._stat["Procs"].setText(str(s.procs))
        if not s.batt_present:
            self._stat["Battery"].setText("none")
        elif s.batt_pct is not None:
            self._stat["Battery"].setText(f"{s.batt_pct}%{' AC' if s.batt_ac else ''}")

        self.status.setText(
            f"uptime {s.uptime or '--'}   ·   sampled ~{settings.get('sample_ms')//1000 or 0.5}s")

    # Sample only while actually on screen: the popup may be open on another
    # sub-tab, or never opened at all since the panel is built at startup.
    def set_paused(self, paused):
        self._host_paused = bool(paused)
        self._sync_sampler()

    def showEvent(self, e):
        super().showEvent(e)
        self._sync_sampler()

    def hideEvent(self, e):
        super().hideEvent(e)
        self._sync_sampler()

    def _sync_sampler(self):
        self.sampler.set_paused(self._host_paused or not self.isVisible())

    def shutdown(self):
        self.sampler.stop()
        self.sampler.wait(1500)
