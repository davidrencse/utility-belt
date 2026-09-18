"""Small cross-platform helpers for the overlay runtime."""
import os
import platform

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices


SYSTEM = platform.system().lower()
IS_WINDOWS = SYSTEM.startswith("win")
IS_LINUX = SYSTEM == "linux"
IS_HYPRLAND = bool(os.environ.get("HYPRLAND_INSTANCE_SIGNATURE"))


def open_path(path):
    """Open a file, folder, or URL with the user's default handler."""
    if not path:
        return False
    low = path.lower()
    if low.startswith(("http://", "https://")):
        return QDesktopServices.openUrl(QUrl(path))
    return QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path)))


def runtime_note():
    if IS_WINDOWS:
        return "Windows"
    if IS_HYPRLAND:
        return "Hyprland"
    if IS_LINUX:
        return "Linux"
    return platform.system() or "this OS"
