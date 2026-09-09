"""
Imports the existing Port Scanner engine (one folder over) without copying
or rewriting a line of it. Everything in ../Port Scanner is standard-library
Python, so we just put that folder on sys.path and re-export the modules the
overlay needs.

Reused as-is:
  system_info : cpu_load(), memory(), disk(), uptime_seconds(), gather()
  port_scanner: scan_port(), scan_udp_port(), parse_ports(), resolve_target(),
                RateLimiter, get_service_name()
  net_recon   : ping_host(), traceroute()
  geoip       : locate()
"""
import os
import platform
import subprocess
import sys

# --- suppress flashing console windows -------------------------------------
# The engine (net_recon.ping_host, arp, tracert, and system_info's PowerShell
# CIM call) shells out with subprocess. Under pythonw each of those flashes a
# black console window - once per ping, i.e. every second. Patch Popen so
# every child process on Windows is created with CREATE_NO_WINDOW, without
# touching the shared engine files.
if platform.system().lower().startswith("win"):
    _CREATE_NO_WINDOW = 0x08000000
    _orig_popen_init = subprocess.Popen.__init__

    def _quiet_popen_init(self, *args, **kwargs):
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | _CREATE_NO_WINDOW
        return _orig_popen_init(self, *args, **kwargs)

    subprocess.Popen.__init__ = _quiet_popen_init

_HERE = os.path.dirname(os.path.abspath(__file__))
# overlay/core -> overlay -> Overlay -> Undetectable (holds sibling repos)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
_ENGINE_DIR = os.path.normpath(os.path.join(PROJECT_ROOT, "Port Scanner"))

if _ENGINE_DIR not in sys.path:
    sys.path.insert(0, _ENGINE_DIR)

ENGINE_DIR = _ENGINE_DIR
ENGINE_OK = True
ENGINE_ERROR = None

try:
    import system_info          # noqa: E402
    import port_scanner         # noqa: E402
    import net_recon            # noqa: E402
    try:
        import geoip            # noqa: E402
    except Exception:           # geoip is optional (needs network anyway)
        geoip = None
except Exception as exc:        # pragma: no cover - surfaced in the UI
    ENGINE_OK = False
    ENGINE_ERROR = f"{type(exc).__name__}: {exc}"
    system_info = port_scanner = net_recon = geoip = None


# --- StegKit steganography (sibling repo, imported like the scanner) -------
_STEGO_DIR = os.path.normpath(os.path.join(PROJECT_ROOT, "Steganography-Multi-Tool"))
if os.path.isdir(_STEGO_DIR) and _STEGO_DIR not in sys.path:
    sys.path.insert(0, _STEGO_DIR)

STEGO_DIR = _STEGO_DIR
STEGO_OK = True
STEGO_ERROR = None
try:
    from stegkit import image as stego_image     # noqa: E402
    from stegkit import text as stego_text       # noqa: E402
    from stegkit import errors as stego_errors    # noqa: E402
except Exception as exc:        # pragma: no cover - surfaced in the UI
    STEGO_OK = False
    STEGO_ERROR = f"{type(exc).__name__}: {exc}"
    stego_image = stego_text = stego_errors = None
