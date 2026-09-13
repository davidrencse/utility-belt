"""
Stats sub-view - detailed numeric readouts for the SYSTEM tab: RAM
(used/free/total), swap/page-file (used/free/total), CPU load, and battery
(time to full/empty, charge or discharge wattage, and health).

RAM + swap come from GlobalMemoryStatusEx, quick battery state from
GetSystemPowerStatus (both ctypes, fast, no subprocess). Wattage, health and
time-to-full need WMI, so those are refreshed less often via one PowerShell
CIM call. The worker only runs while this sub-view is actually visible.
"""
import ctypes
import json
import platform
import subprocess

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QFrame, QGridLayout)

from ..core import bridge as eng
from .. import theme as T

IS_WINDOWS = platform.system().lower().startswith("win")
_NOWIN = 0x08000000
_GB = 1024 ** 3


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


class _POWER(ctypes.Structure):
    _fields_ = [("ACLineStatus", ctypes.c_ubyte), ("BatteryFlag", ctypes.c_ubyte),
                ("BatteryLifePercent", ctypes.c_ubyte), ("SystemStatusFlag", ctypes.c_ubyte),
                ("BatteryLifeTime", ctypes.c_ulong), ("BatteryFullLifeTime", ctypes.c_ulong)]


def _mem():
    """(ram_total, ram_free, swap_total, swap_free) in bytes, or None."""
    if not IS_WINDOWS:
        return None
    s = _MEMORYSTATUSEX(); s.dwLength = ctypes.sizeof(s)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(s)):
        return None
    swap_total = max(0, s.ullTotalPageFile - s.ullTotalPhys)
    swap_free = max(0, min(swap_total, s.ullAvailPageFile - s.ullAvailPhys))
    return s.ullTotalPhys, s.ullAvailPhys, swap_total, swap_free


def _power():
    if not IS_WINDOWS:
        return None
    p = _POWER()
    if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(p)):
        return None
    return {
        "ac": p.ACLineStatus,                       # 1 plugged, 0 battery
        "no_battery": bool(p.BatteryFlag & 128),
        "pct": None if p.BatteryLifePercent == 255 else p.BatteryLifePercent,
        "secs_left": None if p.BatteryLifeTime == 0xFFFFFFFF else p.BatteryLifeTime,
    }


_BAT_PS = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$b=Get-CimInstance Win32_Battery|Select-Object -First 1;"
    "$bs=Get-CimInstance -Namespace root\\wmi -ClassName BatteryStatus|Select-Object -First 1;"
    "$fc=Get-CimInstance -Namespace root\\wmi -ClassName BatteryFullChargedCapacity|Select-Object -First 1;"
    "$sd=Get-CimInstance -Namespace root\\wmi -ClassName BatteryStaticData|Select-Object -First 1;"
    "if(-not $b){'{}'}else{[PSCustomObject]@{tofull=$b.TimeToFullCharge;"
    "runtime=$b.EstimatedRunTime;status=$b.BatteryStatus;charge=$bs.ChargeRate;"
    "discharge=$bs.DischargeRate;full=$fc.FullChargedCapacity;"
    "design=$sd.DesignedCapacity}|ConvertTo-Json -Compress}"
)


def _wmi_battery():
    if not IS_WINDOWS:
        return None
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _BAT_PS],
            capture_output=True, text=True, timeout=15, creationflags=_NOWIN)
        out = (proc.stdout or "").strip()
        return json.loads(out) if out and out != "{}" else None
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None


_HEALTH_CACHE = None    # health % once computed (barely changes), or False


def _battery_health():
    """Health % = full-charge / design capacity, from `powercfg /batteryreport`
    (more reliable than WMI's DesignedCapacity). Computed once, then cached."""
    global _HEALTH_CACHE
    if _HEALTH_CACHE is not None:
        return _HEALTH_CACHE or None
    if not IS_WINDOWS:
        _HEALTH_CACHE = False
        return None
    import os
    import re
    import tempfile
    try:
        path = os.path.join(tempfile.gettempdir(), "overlay_batt.xml")
        subprocess.run(["powercfg", "/batteryreport", "/xml", "/output", path],
                       capture_output=True, timeout=20, creationflags=_NOWIN)
        with open(path, encoding="utf-8", errors="replace") as f:
            xml = f.read()
        d = re.search(r"<DesignCapacity>(\d+)</DesignCapacity>", xml)
        fc = re.search(r"<FullChargeCapacity>(\d+)</FullChargeCapacity>", xml)
        if d and fc and int(d.group(1)) > 0:
            _HEALTH_CACHE = int(fc.group(1)) / int(d.group(1)) * 100
        else:
            _HEALTH_CACHE = False
    except (OSError, subprocess.TimeoutExpired, ValueError):
        _HEALTH_CACHE = False
    return _HEALTH_CACHE or None


_CPU_TEMP_OK = True     # flips off after the ACPI zone proves unavailable


def _temps():
    """GPU temp/usage/VRAM via nvidia-smi (reliable when an NVIDIA GPU is
    present); CPU temp via the ACPI thermal zone (often needs admin, so it may
    stay None); battery temp is rarely exposed on Windows."""
    out = {"cpu": None, "gpu": None, "gpu_util": None,
           "vram_used": None, "vram_total": None, "batt": None}
    try:
        r = subprocess.run(
            ["nvidia-smi", "--query-gpu=temperature.gpu,utilization.gpu,"
             "memory.used,memory.total", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=6, creationflags=_NOWIN)
        line = (r.stdout or "").strip().splitlines()
        if line:
            parts = [p.strip() for p in line[0].split(",")]
            out["gpu"] = int(parts[0])
            out["gpu_util"] = int(parts[1])
            out["vram_used"] = int(parts[2])
            out["vram_total"] = int(parts[3])
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        pass
    global _CPU_TEMP_OK
    if IS_WINDOWS and _CPU_TEMP_OK:
        try:
            ps = ("Get-CimInstance -Namespace root/wmi -ClassName "
                  "MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue|"
                  "Select-Object -First 1 -ExpandProperty CurrentTemperature")
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=8, creationflags=_NOWIN)
            v = (r.stdout or "").strip()
            if v.isdigit():
                out["cpu"] = round(int(v) / 10 - 273.15)
            else:
                _CPU_TEMP_OK = False     # not exposed here; stop retrying
        except (OSError, subprocess.TimeoutExpired, ValueError):
            _CPU_TEMP_OK = False
    return out


class StatsWorker(QThread):
    """Fast numbers (RAM / swap / CPU / battery %) come from ctypes and are
    emitted every ~2 s straight away. The slow sources - PowerShell WMI,
    powercfg's battery report, nvidia-smi - take seconds each, so they run
    in parallel on a side thread that emits its own tick when they land,
    instead of blocking the first update. Results are cached at class level
    so reopening Stats shows the last known values instantly."""
    tick = Signal(dict)

    _SLOW_EVERY = 10.0                       # seconds between slow refreshes
    _cache = {"bat": None, "temps": None}

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = True
        self._paused = True
        self._slow_busy = False
        self._slow_at = 0.0

    def stop(self):
        self._running = False

    def set_paused(self, p):
        self._paused = bool(p)

    def _slow_refresh(self):
        from concurrent.futures import ThreadPoolExecutor
        try:
            with ThreadPoolExecutor(max_workers=3) as ex:
                f_bat = ex.submit(_wmi_battery)
                f_health = ex.submit(_battery_health)   # cached after first run
                f_temps = ex.submit(_temps)
                bat, health, temps = f_bat.result(), f_health.result(), f_temps.result()
            if bat is not None:
                des, fll = bat.get("design"), bat.get("full")
                bat["health_pct"] = fll / des * 100 if des and fll else health
            StatsWorker._cache = {"bat": bat, "temps": temps}
            if self._running and not self._paused:
                self.tick.emit(self._fast())     # show slow data as soon as it lands
        except Exception:
            pass
        finally:
            self._slow_busy = False

    def _fast(self):
        d = {"mem": _mem(), "power": _power()}
        if eng.ENGINE_OK:
            d["cpu"] = eng.system_info.cpu_load()
            d["uptime"] = eng.system_info.format_uptime(
                eng.system_info.uptime_seconds())
        d.update(StatsWorker._cache)
        return d

    def run(self):
        import threading
        import time
        while self._running:
            if self._paused:
                self.msleep(150)
                continue
            now = time.monotonic()
            if not self._slow_busy and now - self._slow_at >= self._SLOW_EVERY:
                self._slow_busy, self._slow_at = True, now
                threading.Thread(target=self._slow_refresh, daemon=True).start()
            self.tick.emit(self._fast())
            for _ in range(20):                  # ~2 s cadence
                if not self._running or self._paused:
                    break
                self.msleep(100)


class _Card(QFrame):
    def __init__(self, title, rows, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setStyleSheet(
            f"background:{T.rgba(T.SURFACE)};border:1px solid {T.hexs(T.BORDER)};"
            f"border-radius:10px;")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)
        t = QLabel(title.upper())
        t.setStyleSheet(
            f"color:{T.hexs(T.TEXT_DIM)};font:700 8pt '{T.MONO}';letter-spacing:2px;"
            "border:none;background:transparent;")
        lay.addWidget(t)
        grid = QGridLayout(); grid.setVerticalSpacing(5); grid.setHorizontalSpacing(8)
        self._vals = {}
        for i, key in enumerate(rows):
            k = QLabel(key)
            k.setStyleSheet(f"color:{T.hexs(T.TEXT_MUTED)};font:9pt '{T.UI}';"
                            "border:none;background:transparent;")
            v = QLabel("—")
            v.setStyleSheet(f"color:{T.hexs(T.TEXT)};font:600 11pt '{T.MONO}';"
                            "border:none;background:transparent;")
            v.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            grid.addWidget(k, i, 0)
            grid.addWidget(v, i, 1)
            self._vals[key] = v
        grid.setColumnStretch(1, 1)
        lay.addLayout(grid)
        lay.addStretch(1)

    def set(self, key, value):
        if key in self._vals:
            self._vals[key].setText(str(value))


class StatsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._started = False
        self._build()
        self.worker = StatsWorker(self)
        self.worker.tick.connect(self._on_tick)

    def _build(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(14, 12, 14, 12)
        root.setSpacing(10)
        self.ram = _Card("RAM", ["Used", "Free", "Total"])
        self.swap = _Card("Swap", ["Used", "Free", "Total"])
        self.cpu = _Card("CPU", ["Load", "Temp", "Uptime"])
        self.gpu = _Card("GPU", ["Temp", "Usage", "VRAM"])
        self.bat = _Card("Battery", ["State", "Time", "Power", "Charge",
                                     "Health", "Temp"])
        for c in (self.ram, self.swap, self.cpu, self.gpu, self.bat):
            root.addWidget(c, 1)

    # start/stop the worker with visibility so it costs nothing when unseen
    def showEvent(self, e):
        super().showEvent(e)
        if not self._started:
            self._started = True
            self.worker.start()
        self.worker.set_paused(False)

    def hideEvent(self, e):
        super().hideEvent(e)
        self.worker.set_paused(True)

    @staticmethod
    def _gb(b):
        return f"{b / _GB:.1f} GB" if b else "—"

    @staticmethod
    def _dur(mins):
        if not mins or mins <= 0 or mins > 6000:
            return None
        return f"{mins // 60}h {mins % 60}m" if mins >= 60 else f"{mins}m"

    def _on_tick(self, d):
        mem = d.get("mem")
        if mem:
            rt, rf, st, sf = mem
            self.ram.set("Used", self._gb(rt - rf))
            self.ram.set("Free", self._gb(rf))
            self.ram.set("Total", self._gb(rt))
            self.swap.set("Used", self._gb(st - sf))
            self.swap.set("Free", self._gb(sf))
            self.swap.set("Total", self._gb(st))
        if d.get("cpu") is not None:
            self.cpu.set("Load", f"{d['cpu']}%")
        if d.get("uptime"):
            self.cpu.set("Uptime", d["uptime"])

        if d.get("temps") is None:
            for card, key in ((self.cpu, "Temp"), (self.gpu, "Temp"),
                              (self.gpu, "Usage"), (self.gpu, "VRAM"), (self.bat, "Temp")):
                card.set(key, "reading…")
        tm = d.get("temps")
        if tm is not None:
            self.cpu.set("Temp", f"{tm['cpu']}°C" if tm.get("cpu") is not None else "n/a")
            self.gpu.set("Temp", f"{tm['gpu']}°C" if tm.get("gpu") is not None else "n/a")
            self.gpu.set("Usage", f"{tm['gpu_util']}%" if tm.get("gpu_util") is not None else "—")
            if tm.get("vram_total"):
                self.gpu.set("VRAM", f"{tm['vram_used']/1024:.1f}/{tm['vram_total']/1024:.1f} GB")
            else:
                self.gpu.set("VRAM", "—")
            self.bat.set("Temp", f"{tm['batt']}°C" if tm.get("batt") is not None else "n/a")

        pw, bat = d.get("power"), d.get("bat")
        if pw is None or pw.get("no_battery"):
            self.bat.set("State", "No battery")
            for k in ("Time", "Power", "Charge", "Health"):
                self.bat.set(k, "—")
            return
        charging = pw.get("ac") == 1 and (pw.get("pct") or 0) < 100
        full = pw.get("ac") == 1 and (pw.get("pct") or 0) >= 100
        self.bat.set("State", "Full" if full else ("Charging" if charging
                     else "On battery"))
        self.bat.set("Charge", f"{pw['pct']}%" if pw.get("pct") is not None else "—")

        # time: to full when charging, to empty when discharging
        t = None
        if bat:
            t = (self._dur(bat.get("tofull")) if charging
                 else self._dur(bat.get("runtime")))
        if t is None and not charging and pw.get("secs_left"):
            m = pw["secs_left"] // 60
            t = self._dur(m)
        self.bat.set("Time", (t + (" to full" if charging else " left")) if t else "—")

        # wattage + health from WMI
        if bat:
            charge, dis = bat.get("charge") or 0, bat.get("discharge") or 0
            if charge > 0:
                self.bat.set("Power", f"+{charge/1000:.1f} W")
            elif dis > 0:
                self.bat.set("Power", f"-{dis/1000:.1f} W")
            else:
                self.bat.set("Power", "—")
            hp = bat.get("health_pct")
            self.bat.set("Health", f"{hp:.0f}%" if hp else "—")
        else:
            self.bat.set("Power", "—")
            self.bat.set("Health", "—")

    def shutdown(self):
        self.worker.stop()
        self.worker.wait(1500)
