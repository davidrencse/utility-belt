"""
Live telemetry panel: CPU / RAM / disk gauges plus rolling sparklines for CPU
load, ping latency and network throughput.

Sampling runs on a background QThread and delivers a typed `Sample` (a
dataclass, not a loose dict) so the UI reads named fields. Cadence and ping
target come from settings; the sampler idles while the HUD is hidden.
"""
import time
from dataclasses import dataclass

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel

from ..core import bridge as eng
from ..core import netstat
from .. import theme as T
from ..settings import settings
from ..widgets import Sparkline, Gauge


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


class Sampler(QThread):
    tick = Signal(object)   # emits a Sample

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = True
        self._paused = False
        self._last_net = None
        self._last_net_t = None

    def stop(self):
        self._running = False

    def set_paused(self, paused):
        self._paused = bool(paused)

    def run(self):
        self._last_net = netstat.total_octets()
        self._last_net_t = time.perf_counter()
        while self._running:
            if self._paused:
                self.msleep(200)
                continue
            t_start = time.perf_counter()
            s = Sample()
            if eng.ENGINE_OK:
                s.cpu = eng.system_info.cpu_load()
                tot, avail, s.mem_pct = eng.system_info.memory()
                s.mem_total_gb = round(tot / 1024**3, 1) if tot else None
                s.mem_avail_gb = round(avail / 1024**3, 1) if avail else None
                dtot, _du, s.disk_pct = eng.system_info.disk()
                s.disk_total_gb = round(dtot / 1024**3, 0) if dtot else None
                s.uptime = eng.system_info.format_uptime(
                    eng.system_info.uptime_seconds())

            now = time.perf_counter()
            cur = netstat.total_octets()
            dt = max(1e-3, now - self._last_net_t)
            s.net_down_bps = max(0, cur[0] - self._last_net[0]) / dt
            s.net_up_bps = max(0, cur[1] - self._last_net[1]) / dt
            self._last_net, self._last_net_t = cur, now

            if eng.ENGINE_OK:
                try:
                    res = eng.net_recon.ping_host(settings.get("ping_target"),
                                                  timeout=1.5)
                    s.ping_ms = res.get("latency_ms")
                except Exception:
                    s.ping_ms = None

            self.tick.emit(s)
            target = settings.get("sample_ms") / 1000.0
            while self._running and (time.perf_counter() - t_start) < target:
                self.msleep(50)


def _fmt_bps(bps):
    if bps is None:
        return "--"
    for unit in ("B", "KB", "MB", "GB"):
        if bps < 1024:
            return f"{bps:.0f} {unit}/s"
        bps /= 1024
    return f"{bps:.0f} TB/s"


class MetricsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()
        self._apply_settings()
        settings.changed.connect(self._on_setting)
        self.sampler = Sampler(self)
        self.sampler.tick.connect(self._on_tick)
        self.sampler.start()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 12)
        root.setSpacing(14)

        gauges = QHBoxLayout()
        gauges.setSpacing(10)
        self.g_cpu = Gauge("CPU")
        self.g_mem = Gauge("RAM")
        self.g_disk = Gauge("DISK")
        for g in (self.g_cpu, self.g_mem, self.g_disk):
            gauges.addWidget(g)
        root.addLayout(gauges)

        self.sp_cpu = Sparkline(color=T.G_CPU, floor=100, unit="%")
        self.sp_ping = Sparkline(color=T.G_PING, floor=50, unit="ms")
        self.sp_net = Sparkline(color=T.G_NET, floor=1.0, unit="")
        for sp in (self.sp_cpu, self.sp_ping, self.sp_net):
            root.addWidget(sp)

        self.status = QLabel("starting…")
        self.status.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:8pt '{T.MONO}';")
        root.addWidget(self.status)
        root.addStretch(1)

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
            self.sp_cpu.set_label("CPU", f"{s.cpu:.0f}%")
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
            self.sp_ping.set_label("Ping", f"{s.ping_ms:.0f} ms")
        else:
            self.sp_ping.push(0)
            self.sp_ping.set_label("Ping", "--")

        self.sp_net.push(s.net_down_bps)
        self.sp_net.set_label(
            "Network", f"↓ {_fmt_bps(s.net_down_bps)}   ↑ {_fmt_bps(s.net_up_bps)}")

        self.status.setText(
            f"uptime {s.uptime or '--'}   ·   sampled ~{settings.get('sample_ms')//1000 or 0.5}s")

    def set_paused(self, paused):
        self.sampler.set_paused(paused)

    def shutdown(self):
        self.sampler.stop()
        self.sampler.wait(1500)
