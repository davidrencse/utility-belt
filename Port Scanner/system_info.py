#!/usr/bin/env python3
"""
Collects this machine's hardware/OS specs for the dashboard and the 3D
view. Standard library only (winreg/ctypes/shutil/platform), plus a
single optional PowerShell CIM call on Windows for GPU + system model.

Every field degrades to None rather than raising, so a missing value
just shows as "—" in the UI instead of breaking a scan.
"""

import ctypes
import json
import os
import platform
import shutil
import socket
import subprocess
import time

IS_WINDOWS = platform.system().lower().startswith("win")


def _gb(n):
    return round(n / (1024 ** 3), 1) if n else None


# ------------------------------------------------------------------ CPU --

def cpu_name():
    if IS_WINDOWS:
        try:
            import winreg
            key = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
                return winreg.QueryValueEx(k, "ProcessorNameString")[0].strip()
        except OSError:
            pass
    else:
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.lower().startswith("model name"):
                        return line.split(":", 1)[1].strip()
        except OSError:
            pass
    return platform.processor() or platform.machine() or None


def cpu_load(sample=0.12):
    """Instantaneous CPU busy percentage from two GetSystemTimes samples."""
    if not IS_WINDOWS:
        try:
            return round(os.getloadavg()[0] / (os.cpu_count() or 1) * 100)
        except (OSError, AttributeError):
            return None

    class FILETIME(ctypes.Structure):
        _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

    def snapshot():
        idle, kernel, user = FILETIME(), FILETIME(), FILETIME()
        ok = ctypes.windll.kernel32.GetSystemTimes(
            ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user))
        if not ok:
            return None
        val = lambda ft: (ft.high << 32) | ft.low  # noqa: E731
        return val(idle), val(kernel), val(user)

    try:
        first = snapshot()
        if not first:
            return None
        time.sleep(sample)
        second = snapshot()
        if not second:
            return None
        idle_delta = second[0] - first[0]
        # On Windows the kernel time already includes idle time.
        total_delta = (second[1] - first[1]) + (second[2] - first[2])
        if total_delta <= 0:
            return None
        return max(0, min(100, round((1 - idle_delta / total_delta) * 100)))
    except (OSError, AttributeError):
        return None


# --------------------------------------------------------------- memory --

def memory():
    """Returns (total_bytes, available_bytes, percent_used)."""
    if IS_WINDOWS:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        try:
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(stat)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return stat.ullTotalPhys, stat.ullAvailPhys, stat.dwMemoryLoad
        except (OSError, AttributeError):
            pass
        return None, None, None

    try:
        total = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        avail = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_AVPHYS_PAGES")
        return total, avail, round((1 - avail / total) * 100)
    except (OSError, ValueError, AttributeError):
        return None, None, None


# ----------------------------------------------------------------- disk --

def disk(path=None):
    """Returns (total_bytes, used_bytes, percent_used) for the system drive."""
    if path is None:
        path = os.environ.get("SystemDrive", "C:") + "\\" if IS_WINDOWS else "/"
    try:
        usage = shutil.disk_usage(path)
        pct = round(usage.used / usage.total * 100) if usage.total else None
        return usage.total, usage.used, pct
    except OSError:
        return None, None, None


# --------------------------------------------------------------- uptime --

def uptime_seconds():
    if IS_WINDOWS:
        try:
            get_tick = ctypes.windll.kernel32.GetTickCount64
            get_tick.restype = ctypes.c_ulonglong
            return int(get_tick() / 1000)
        except (OSError, AttributeError):
            return None
    try:
        with open("/proc/uptime") as f:
            return int(float(f.read().split()[0]))
    except (OSError, ValueError):
        return None


def format_uptime(seconds):
    if seconds is None:
        return None
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


# ------------------------------------------------- GPU / model via CIM --

def _windows_cim():
    """One PowerShell round-trip for the things only WMI/CIM knows."""
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$g=@(Get-CimInstance Win32_VideoController | Select-Object -First 2 -ExpandProperty Name) -join ' / ';"
        "$cs=Get-CimInstance Win32_ComputerSystem;"
        "$os=Get-CimInstance Win32_OperatingSystem;"
        "$bb=Get-CimInstance Win32_BaseBoard;"
        "[PSCustomObject]@{gpu=$g;manufacturer=$cs.Manufacturer;model=$cs.Model;"
        "board=$bb.Product;osname=$os.Caption} | ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=20,
        )
        out = (proc.stdout or "").strip()
        if out:
            return json.loads(out)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        pass
    return {}


# ------------------------------------------------------------- gather --

def gather(include_cim=True):
    """Collect everything. include_cim=False skips the (slower)
    PowerShell call, for when you only need the fast fields."""
    total_mem, avail_mem, mem_pct = memory()
    total_disk, used_disk, disk_pct = disk()
    cim = _windows_cim() if (include_cim and IS_WINDOWS) else {}

    os_name = cim.get("osname")
    if not os_name:
        os_name = f"{platform.system()} {platform.release()}"

    model_bits = [cim.get("manufacturer"), cim.get("model")]
    model = " ".join(b.strip() for b in model_bits if b and b.strip()) or None

    return {
        "hostname": socket.gethostname(),
        "os": os_name,
        "os_version": platform.version(),
        "arch": platform.machine(),
        "model": model,
        "board": cim.get("board") or None,
        "cpu": cpu_name(),
        "cpu_cores": os.cpu_count(),
        "cpu_load_pct": cpu_load(),
        "gpu": (cim.get("gpu") or None),
        "ram_total_gb": _gb(total_mem),
        "ram_available_gb": _gb(avail_mem),
        "ram_used_pct": mem_pct,
        "disk_total_gb": _gb(total_disk),
        "disk_used_gb": _gb(used_disk),
        "disk_used_pct": disk_pct,
        "uptime": format_uptime(uptime_seconds()),
        "python": platform.python_version(),
    }


if __name__ == "__main__":
    for key, value in gather().items():
        print(f"{key:>18}: {value}")
