r"""
Overlay HUD - launcher.

A borderless, translucent, always-on-top Windows 11 utility-belt overlay that
is excluded from screen capture. This file is a thin entry point; the app
lives in the `overlay` package.

Run:  python main.py   (or double-click "Run Overlay.bat")
"""
import os
import sys

# Launchable from any working directory: put this folder on sys.path so the
# `overlay` package imports, then hand off to it.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# QtWebEngine wants this set before the QApplication is created.
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS",
                      "--disable-features=WebRTCHideLocalIpsWithMdns")

from overlay.app import main

if __name__ == "__main__":
    main()
