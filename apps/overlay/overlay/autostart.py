"""
Start-with-Windows helper. Writes an HKCU\\...\\Run entry so the overlay
launches at login (which is what "open when I log into Windows / resume from
sleep" needs - a Run entry fires on each interactive logon). Per-user, no
admin required, and fully reversible.
"""
import os
import sys

try:
    import winreg
except ImportError:              # non-Windows
    winreg = None

_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_NAME = "SysmonOverlay"


def _command():
    """`pythonw main.py` using the current interpreter, quoted for the shell."""
    exe = sys.executable or "pythonw.exe"
    pyw = exe.replace("python.exe", "pythonw.exe")
    main = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "main.py"))
    return f'"{pyw}" "{main}"'


def is_enabled():
    if not winreg:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY) as k:
            val, _ = winreg.QueryValueEx(k, _NAME)
            return bool(val)
    except OSError:
        return False


def set_enabled(on):
    if not winreg:
        return False
    try:
        if on:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _KEY) as k:
                winreg.SetValueEx(k, _NAME, 0, winreg.REG_SZ, _command())
        else:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0,
                                winreg.KEY_SET_VALUE) as k:
                try:
                    winreg.DeleteValue(k, _NAME)
                except FileNotFoundError:
                    pass
        return True
    except OSError:
        return False
