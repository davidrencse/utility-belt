r"""
Application bootstrap: builds the QApplication, the overlay window, the tray
icon, local command socket, and native hotkeys where the OS allows them. Kept
thin - all behaviour lives in the window and panels.

Global hotkeys (work even when unfocused):
  Ctrl+Alt+\   show/hide      Ctrl+Alt+H  panic-hide
  Ctrl+Alt+C   click-through  Ctrl+Alt+X  toggle capture-exclusion
  Ctrl+Alt+Arrows  move
"""
import argparse
import os
import shlex
import sys

from PySide6.QtWidgets import QApplication, QSystemTrayIcon, QMenu
from PySide6.QtGui import QIcon, QPixmap, QPainter, QColor, QAction
from PySide6.QtCore import QCoreApplication, Qt

from .core import bridge as _bridge  # noqa: F401  (sys.path + console-suppress)
from . import theme as T
from .hotkeys import ACTIONS, HotkeyManager
from .ipc import CommandServer, VALID_COMMANDS, send_command
from .platform_utils import IS_HYPRLAND, runtime_note


def _parser():
    p = argparse.ArgumentParser(description="sysmon overlay")
    p.add_argument(
        "--command",
        choices=sorted(VALID_COMMANDS),
        help="send an action to an already-running overlay and exit",
    )
    p.add_argument(
        "--print-hyprland-binds",
        action="store_true",
        help="print Hyprland bind lines for the configured overlay actions",
    )
    return p


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


def _hypr_key(combo):
    if not combo:
        return None
    mods = []
    key = None
    mod_map = {
        "ctrl": "CTRL",
        "control": "CTRL",
        "alt": "ALT",
        "shift": "SHIFT",
        "win": "SUPER",
        "meta": "SUPER",
        "cmd": "SUPER",
        "super": "SUPER",
    }
    key_map = {"\\": "backslash", "|": "backslash", "esc": "escape"}
    for part in str(combo).lower().replace(" ", "").split("+"):
        if not part:
            continue
        if part in mod_map:
            mods.append(mod_map[part])
        else:
            key = key_map.get(part, part)
    if not key:
        return None
    return " ".join(dict.fromkeys(mods)), key.upper() if len(key) == 1 else key


def print_hyprland_binds():
    from .settings import settings

    script = shlex.quote(os.path.abspath(sys.argv[0]))
    python = shlex.quote(sys.executable)
    print("# sysmon overlay")
    print(f"exec-once = {python} {script}")
    print("# Add these to ~/.config/hypr/hyprland.conf, then run: hyprctl reload")
    for action, _label in ACTIONS:
        parsed = _hypr_key((settings.get("hotkeys") or {}).get(action, ""))
        if not parsed:
            continue
        mods, key = parsed
        print(f"bind = {mods}, {key}, exec, {python} {script} --command {action}")


def main():
    args = _parser().parse_args()
    if args.print_hyprland_binds:
        print_hyprland_binds()
        return
    if args.command:
        app = QCoreApplication(sys.argv[:1])
        ok, msg = send_command(args.command)
        if not ok:
            print(msg, file=sys.stderr)
            sys.exit(2)
        return

    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)   # tray keeps us alive when hidden
    app.setApplicationName("sysmon-overlay")
    app.setDesktopFileName("sysmon-overlay")

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

    command_server = CommandServer(app)
    command_server.received.connect(lambda action: _dispatch.get(action, lambda: None)())
    ipc_ok = command_server.listen()

    # re-register whenever the user edits keybinds in Settings
    from .settings import settings as _settings
    _settings.changed.connect(
        lambda key, _v: hk.reregister() if key == "hotkeys" else None)

    tray = QSystemTrayIcon(_tray_icon())
    tray.setToolTip("sysmon overlay")
    menu = QMenu()
    act_show = QAction("Show / Hide")
    act_cap = QAction("Toggle capture hiding")
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
        if IS_HYPRLAND:
            msg = (
                "Global hotkeys are managed by Hyprland. Run "
                "`python main.py --print-hyprland-binds` for bind lines."
            )
        else:
            msg = (
                f"Global hotkeys couldn't register on {runtime_note()}. "
                "The window still works; use the tray menu."
            )
        tray.showMessage(
            "Overlay", msg, QSystemTrayIcon.Information, 5000)
    if not ipc_ok:
        tray.showMessage(
            "Overlay", "The local command socket could not start; compositor "
            "keybind commands will not reach this window.",
            QSystemTrayIcon.Warning, 5000)

    sys.exit(app.exec())
