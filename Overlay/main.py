r"""
Overlay HUD - launcher.

A borderless, translucent, always-on-top utility-belt overlay. This file is a
thin entry point; the app lives in the `overlay` package.

Run:  python main.py   (or double-click "Run Overlay.bat")
"""
import os
import sys

# Launchable from any working directory: put this folder on sys.path so the
# `overlay` package imports, then hand off to it.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Prefer native Wayland on Hyprland, but keep XCB as a fallback for mixed Qt
# installs. This must be set before QApplication is constructed.
if os.environ.get("HYPRLAND_INSTANCE_SIGNATURE") or os.environ.get("WAYLAND_DISPLAY"):
    os.environ.setdefault("QT_QPA_PLATFORM", "wayland;xcb")

# QtWebEngine wants this set before the QApplication is created.
_flags = os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "")
_needed = "--disable-features=WebRTCHideLocalIpsWithMdns"
if _needed not in _flags:
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (_flags + " " + _needed).strip()

from overlay.app import main

if __name__ == "__main__":
    main()
