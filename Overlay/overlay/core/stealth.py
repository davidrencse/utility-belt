"""
Platform window helpers.

On Windows, the headline one is SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE),
which tells the desktop compositor to leave this window OUT of any capture:
Zoom / Teams / Meet / Discord screen-share, OBS "Display/Window Capture",
PrintScreen, and the Windows Graphics Capture / DXGI Desktop Duplication
APIs all render it as blank. The local user still sees it normally.

Linux/Wayland compositors, including Hyprland, do not expose an equivalent
per-window capture-exclusion API to normal client applications. The overlay
still runs there, but this module reports capture exclusion as unsupported.

HONEST LIMITS (do not oversell this):
  * A phone or camera pointed at the monitor still sees the window.
  * Kernel-level anti-cheat / proctoring can detect the *process or window*
    (and can even query this affinity flag) - this is not stealth from them.
  * It is a per-window compositor flag, not OS-wide invisibility.
So this is Windows capture exclusion, not invisibility by all means.
"""
import ctypes
import platform

from PySide6.QtCore import Qt

IS_WINDOWS = platform.system().lower().startswith("win")

# SetWindowDisplayAffinity constants
WDA_NONE = 0x00000000
WDA_MONITOR = 0x00000001
WDA_EXCLUDEFROMCAPTURE = 0x00000011  # needs Windows 10 2004 (build 19041)+

# GetWindowLong / SetWindowLong
GWL_EXSTYLE = -20
WS_EX_TOOLWINDOW = 0x00000080     # keep out of alt-tab and taskbar
WS_EX_LAYERED = 0x00080000
WS_EX_TRANSPARENT = 0x00000020    # click-through (events fall to window below)
WS_EX_NOACTIVATE = 0x08000000     # don't steal focus when shown


def _u32():
    return ctypes.windll.user32 if IS_WINDOWS else None


def _hwnd(win):
    """Accept a Qt widget, an int, or a sip/shiboken voidptr and return int."""
    try:
        return int(win)
    except (TypeError, ValueError):
        return int(win.winId())


def set_capture_exclusion(win, enabled=True):
    """Exclude (or re-include) the window from screen capture.
    Returns True on success, False if the OS/driver refused."""
    if not IS_WINDOWS:
        return not enabled
    hwnd = _hwnd(win)
    affinity = WDA_EXCLUDEFROMCAPTURE if enabled else WDA_NONE
    ok = _u32().SetWindowDisplayAffinity(ctypes.wintypes.HWND(hwnd),
                                         ctypes.wintypes.DWORD(affinity))
    if not ok and enabled:
        # Older builds lack EXCLUDEFROMCAPTURE; MONITOR still blanks most
        # capture paths (window shows as black rather than absent).
        ok = _u32().SetWindowDisplayAffinity(ctypes.wintypes.HWND(hwnd),
                                             ctypes.wintypes.DWORD(WDA_MONITOR))
    return bool(ok)


def _get_exstyle(hwnd):
    return _u32().GetWindowLongW(ctypes.wintypes.HWND(hwnd), GWL_EXSTYLE)


def _set_exstyle(hwnd, style):
    return _u32().SetWindowLongW(ctypes.wintypes.HWND(hwnd), GWL_EXSTYLE,
                                 ctypes.c_long(style))


def apply_tool_window(win):
    """Drop the window from the taskbar / alt-tab list."""
    if not IS_WINDOWS:
        return False
    hwnd = _hwnd(win)
    style = _get_exstyle(hwnd) | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE
    _set_exstyle(hwnd, style)
    return True


def set_click_through(win, enabled=True):
    """When enabled, mouse events pass straight through the window to
    whatever is beneath it (the HUD becomes a pure overlay you can't grab)."""
    if not IS_WINDOWS:
        win.setAttribute(Qt.WA_TransparentForMouseEvents, bool(enabled))
        return True
    hwnd = _hwnd(win)
    style = _get_exstyle(hwnd)
    if enabled:
        style |= WS_EX_LAYERED | WS_EX_TRANSPARENT
    else:
        style &= ~WS_EX_TRANSPARENT  # keep LAYERED; it's harmless
    _set_exstyle(hwnd, style)
    return True


if IS_WINDOWS:
    # Make sure wintypes is populated (some frozen builds are lazy).
    import ctypes.wintypes  # noqa: E402,F401
