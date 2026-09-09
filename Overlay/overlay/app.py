r"""
Application bootstrap: builds the QApplication, the overlay window, the tray
icon, and wires up the global hotkeys. Kept thin - all behaviour lives in the
window and panels.

Global hotkeys (work even when unfocused):
  Ctrl+Alt+\   show/hide      Ctrl+Alt+H  panic-hide
  Ctrl+Alt+C   click-through  Ctrl+Alt+X  toggle capture-exclusion
  Ctrl+Alt+Arrows  move
"""
import sys

from PySide6.QtWidgets import QApplication, QSystemTrayIcon, QMenu
from PySide6.QtGui import QIcon, QPixmap, QPainter, QColor, QAction
from PySide6.QtCore import Qt

from .core import bridge as _bridge  # noqa: F401  (sys.path + console-suppress)
from . import theme as T
from .hotkeys import HotkeyManager


def _tray_icon():
    pm = QPixmap(32, 32)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    p.setBrush(QColor(240, 240, 242))
    p.setPen(Qt.NoPen)
    p.drawEllipse(6, 6, 20, 20)
    p.end()
    return QIcon(pm)


def main():
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)   # tray keeps us alive when hidden

    T.resolve_fonts()
    app.setStyleSheet(T.app_qss())

    from .window import OverlayWindow  # after fonts are resolved
    win = OverlayWindow()

    hk = HotkeyManager()
    app.installNativeEventFilter(hk)

    _dispatch = {
        "toggle_visible": win.toggle_visible,
        "cycle_tab": win.cycle_tab,
        "capture": win.toggle_capture,
        "click_through": win.toggle_click_through,
        "panic": win.panic,
        "nudge_left": lambda: win.nudge(-20, 0),
        "nudge_right": lambda: win.nudge(20, 0),
        "nudge_up": lambda: win.nudge(0, -20),
        "nudge_down": lambda: win.nudge(0, 20),
    }
    hk.triggered.connect(lambda action: _dispatch.get(action, lambda: None)())
    registered = hk.register()

    # re-register whenever the user edits keybinds in Settings
    from .settings import settings as _settings
    _settings.changed.connect(
        lambda key, _v: hk.reregister() if key == "hotkeys" else None)

    tray = QSystemTrayIcon(_tray_icon())
    tray.setToolTip("sysmon overlay")
    menu = QMenu()
    act_show = QAction("Show / Hide")
    act_cap = QAction("Toggle capture-exclusion")
    act_quit = QAction("Quit")
    act_show.triggered.connect(win.toggle_visible)
    act_cap.triggered.connect(win.toggle_capture)

    def _quit():
        hk.unregister()
        win.shutdown()
        app.quit()

    act_quit.triggered.connect(_quit)
    for a in (act_show, act_cap, act_quit):
        menu.addAction(a)
    tray.setContextMenu(menu)
    tray.activated.connect(
        lambda reason: win.toggle_visible()
        if reason == QSystemTrayIcon.Trigger else None)
    tray.show()

    screen = app.primaryScreen().availableGeometry()
    win.move(screen.right() - win.width() - 24, screen.top() + 24)
    win.show()

    if not registered:
        tray.showMessage(
            "Overlay", "Global hotkeys couldn't register (another app may "
            "own them). The window still works; use the tray menu.",
            QSystemTrayIcon.Information, 4000)

    sys.exit(app.exec())
