"""
Banner UI - a thin bar pinned to the top of the screen. Each tab is a chip;
hovering a chip drops its panel down as a menu that closes when the cursor
leaves. ChatGPT is the exception: clicking its chip pins it open so it
persists after the cursor is gone (click again, or its ×, to close).

Motion (Framer-Motion conventions, see motion.py):
  * one hover pill springs between chips (shared layoutId), keeping its
    velocity as you sweep across the bar
  * menus enter with opacity + a short y spring, exit faster with ease-in
  * moving chip -> chip hands off directionally: the old menu slips out,
    the new one slides in from the side you came from
  * panic / capture paths stay instant - stealth beats polish

Reuses the existing panels unchanged. Capture-exclusion, click-through and the
app-facing methods (toggle_visible / capture / panic / nudge / cycle_tab /
capture_analyze / shutdown) mirror the old window so app.py needs no changes.
"""
import ctypes
import platform

from PySide6.QtCore import Qt, QRectF, QTimer, QPoint, QSize
from PySide6.QtGui import (QPainter, QColor, QBrush, QPainterPath, QPen,
                           QCursor, QFont, QLinearGradient)
from PySide6.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout, QLabel,
                               QPushButton, QApplication, QLineEdit,
                               QAbstractSpinBox, QPlainTextEdit, QTextEdit)

from . import motion
from . import theme as T
from .core import stealth as win_stealth
from .nav import NavStrip
from .settings import settings
from .panels.system_panel import SystemPanel
from .panels.network_panel import NetworkPanel
from .panels.intel_panel import IntelPanel
from .panels.history_panel import HistoryPanel
from .panels.weather_panel import WeatherPanel
from .panels.chatgpt_panel import ChatGPTPanel
from .panels.settings_panel import SettingsPanel
from .clipboard import history as _clip_history
from .screenshots import history as _shot_history

BAR_H = 30              # thin full-width bar along the top edge
GRACE_MS = 260          # cursor-left grace before a hover menu closes
SHADOW = 14             # transparent margin around a dropdown for its shadow
GAP = 6                 # air between the bar and a dropdown card
_IS_WINDOWS = platform.system().lower().startswith("win")
if _IS_WINDOWS:
    import ctypes.wintypes  # noqa: F401  (populates MSG for nativeEvent)
_WM_WTSSESSION_CHANGE = 0x02B1
_WTS_SESSION_UNLOCK = 0x8
_WTS_SESSION_LOGON = 0x5

# (label, attr, default dropdown card size), in two groups:
#   what you look at / use  |  the assistant and app configuration
_TABS = [
    ("SYSTEM", "system", (880, 340)),     # Live · Stats · Specs
    ("NETWORK", "network", (760, 340)),   # Speed Test · Port Scan · Sniffer
    ("INTEL", "intel", (720, 330)),       # VirusTotal · Steganography · OSINT
    ("HISTORY", "history", (620, 380)),   # Clipboard · Screenshots
    ("WEATHER", "weather", (760, 300)),
    ("CHAT", "chat", (660, 500)),
    ("SETTINGS", "settings", (480, 400)), # Display · Behavior · Keybinds
]
_GROUP_END = (4,)                         # divider after WEATHER
CHAT_INDEX = [attr for _l, attr, _s in _TABS].index("chat")


class CaptureStatus(QWidget):
    """Filled dot = hidden from capture, hollow ring = visible to capture.
    Pops with a spring when the state flips so the change is noticed."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._on = True
        self._scale = motion.Spring(1.0, T.SPRING_SNAPPY, owner=self,
                                    on_change=lambda _v: self.update())
        self._fill = motion.Spring(1.0, T.SPRING_SOFT, owner=self,
                                   on_change=lambda _v: self.update())
        self._font = QFont(T.MONO, 7, QFont.Bold)
        self._font.setLetterSpacing(QFont.AbsoluteSpacing, 1.5)
        self.setFixedHeight(BAR_H)

    def sizeHint(self):
        return QSize(84, BAR_H)

    def set_hidden(self, on, animate=True):
        on = bool(on)
        changed = on != self._on
        self._on = on
        self.setToolTip("Hidden from screen capture" if on
                        else "Visible to screen capture")
        self._fill.set(1.0 if on else 0.0, immediate=not animate)
        if changed and animate:
            self._scale.jump(0.55)
            self._scale.set(1.0)
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        cy = self.height() / 2
        r = 3.6 * self._scale.value
        cx = 12
        p.setPen(QPen(T.TEXT, 1.3))
        fill = QColor(T.TEXT); fill.setAlphaF(max(0.0, min(1.0, self._fill.value)))
        p.setBrush(fill)
        p.drawEllipse(QRectF(cx - r, cy - r, 2 * r, 2 * r))
        p.setFont(self._font)
        p.setPen(T.TEXT_MUTED if self._on else T.TEXT_DIM)
        p.drawText(QRectF(cx + 10, 0, self.width() - cx - 10, self.height()),
                   Qt.AlignVCenter | Qt.AlignLeft,
                   "HIDDEN" if self._on else "VISIBLE")
        p.end()


class Dropdown(QWidget):
    """A frameless popup under a chip, holding one panel."""

    def __init__(self, panel, banner, index, pinned=False):
        super().__init__()
        self._banner = banner
        self._panel = panel
        self._i = index
        self._pinned = pinned
        self._applied = False
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint
                            | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setWindowTitle("sysmon-overlay")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(SHADOW + 4, SHADOW + 2, SHADOW + 4, SHADOW + 6)
        lay.setSpacing(0)
        if pinned:
            head = QHBoxLayout()
            head.setContentsMargins(T.S2, 0, 0, 0)
            title = QLabel(_TABS[index][0])
            title.setStyleSheet(T.label_qss("eyebrow"))
            head.addWidget(title)
            head.addStretch(1)
            close = QPushButton("✕")
            close.setFixedSize(26, 24)
            close.setCursor(Qt.PointingHandCursor)
            close.setToolTip("Close")
            close.setAccessibleName("Close")
            close.setStyleSheet(T.icon_btn_qss())
            close.clicked.connect(lambda: self._banner._toggle_chat())
            head.addWidget(close)
            lay.addLayout(head)
            lay.addSpacing(2)
        panel.setParent(self)
        panel.show()
        lay.addWidget(panel, 1)

    def card_rect(self):
        return QRectF(self.rect().adjusted(SHADOW, SHADOW, -SHADOW, -SHADOW))

    def resize_card(self, w, h):
        self.resize(w + 2 * SHADOW, h + 2 * SHADOW)

    def enterEvent(self, _e):
        if not self._pinned:
            self._banner._menu_enter(self._i)

    def leaveEvent(self, _e):
        if not self._pinned:
            self._banner._menu_leave(self._i)

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        card = self.card_rect()
        radius = T.R_CARD

        # soft ambient shadow: stacked, expanding low-alpha rounded rects
        p.setPen(Qt.NoPen)
        for i in range(SHADOW, 0, -2):
            a = round(26 * (1 - i / SHADOW) ** 2)
            path = QPainterPath()
            path.addRoundedRect(card.adjusted(-i, -i + 4, i, i + 4),
                                radius + i, radius + i)
            p.fillPath(path, QColor(0, 0, 0, a))

        body = QPainterPath()
        body.addRoundedRect(card, radius, radius)
        alpha = int(settings.get("card_opacity"))
        grad = QLinearGradient(0, card.top(), 0, card.bottom())
        grad.setColorAt(0.0, QColor(20, 20, 23, alpha))
        grad.setColorAt(0.35, QColor(10, 10, 12, alpha))
        grad.setColorAt(1.0, QColor(8, 8, 10, alpha))
        p.fillPath(body, QBrush(grad))

        # hairline border, brighter along the top edge (light from above)
        edge = QLinearGradient(0, card.top(), 0, card.bottom())
        edge.setColorAt(0.0, QColor(255, 255, 255, 46))
        edge.setColorAt(0.5, QColor(255, 255, 255, 20))
        edge.setColorAt(1.0, QColor(255, 255, 255, 14))
        p.setPen(QPen(QBrush(edge), 1))
        p.drawRoundedRect(card.adjusted(0.5, 0.5, -0.5, -0.5), radius, radius)
        p.end()

    def showEvent(self, e):
        super().showEvent(e)
        if not self._applied:
            self._applied = True
            win_stealth.apply_tool_window(self)
        win_stealth.set_capture_exclusion(self, self._banner._capture_on)
        if hasattr(self._panel, "set_paused"):
            self._panel.set_paused(False)

    def hideEvent(self, e):
        super().hideEvent(e)
        if hasattr(self._panel, "set_paused"):
            self._panel.set_paused(True)


class Banner(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint
                            | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setWindowTitle("sysmon-overlay")
        self._capture_on = bool(settings.get("capture_exclusion"))
        self._click_through = bool(settings.get("click_through"))
        self._apply_pending = True
        self._drops = {}          # index -> Dropdown
        self._open = None         # index of the visible hover menu
        self._chat_pinned = False
        self._wts_registered = False
        self._entering = False

        _clip_history.start()          # record clipboard from launch
        self.system = SystemPanel()
        self.network = NetworkPanel()
        self.intel = IntelPanel()
        self.history = HistoryPanel(take_screenshot=self.take_screenshot,
                                    send_to_chat=self.send_image_to_chat)
        self.clipboard = self.history.clipboard
        self.weather = WeatherPanel()
        self.chat = ChatGPTPanel()
        self.settingsp = SettingsPanel()
        self._panels = {"system": self.system, "network": self.network,
                        "intel": self.intel, "history": self.history,
                        "weather": self.weather, "chat": self.chat,
                        "settings": self.settingsp}

        self._close_timer = QTimer(self)
        self._close_timer.setSingleShot(True)
        self._close_timer.setInterval(GRACE_MS)
        self._close_timer.timeout.connect(self._maybe_close)

        self._build()
        settings.changed.connect(self._on_setting)

    # -- UI ----------------------------------------------------------------
    def _build(self):
        row = QHBoxLayout(self)
        row.setContentsMargins(T.S2, 0, T.S3, 0)
        row.setSpacing(T.S2)
        self.status = CaptureStatus()
        self.status.set_hidden(self._capture_on, animate=False)
        row.addWidget(self.status)

        sep = QWidget()
        sep.setFixedSize(1, 12)
        sep.setStyleSheet(f"background:{T.hexs(T.BORDER)};")
        row.addWidget(sep)

        font = QFont(T.UI, 8, QFont.Bold)
        font.setLetterSpacing(QFont.AbsoluteSpacing, 1.2)
        self._strip = NavStrip([label for label, _a, _s in _TABS], font=font,
                               style="pill", follow_hover=True, height=22,
                               pad_x=11, spacing=2, dividers=_GROUP_END)
        self._strip.hovered.connect(self._chip_enter)
        self._strip.unhovered.connect(self._chip_leave)
        self._strip.activated.connect(self._chip_click)
        self._chips = self._strip.items
        row.addWidget(self._strip)
        row.addStretch(1)          # chips sit on the left; bar fills the width
        self.setFixedHeight(BAR_H)

    def _panel_for(self, index):
        return self._panels[_TABS[index][1]]

    def _sync_chips(self):
        self._strip.set_active(self._open)
        chat = self._chips[CHAT_INDEX]
        chat.set_badge(self._chat_pinned)
        if self._chat_pinned:
            chat.set_on(True)

    # -- geometry ----------------------------------------------------------
    def _home(self):
        return QApplication.primaryScreen().geometry().topLeft()

    def _reposition(self):
        # full-width bar flush against the very top edge of the screen
        scr = QApplication.primaryScreen().geometry()
        self.resize(scr.width(), BAR_H)
        if not self._entering:
            self.move(scr.left(), scr.top())

    # -- hover / open logic ------------------------------------------------
    def _drop_for(self, index):
        if index not in self._drops:
            pinned = index == CHAT_INDEX
            d = Dropdown(self._panel_for(index), self, index, pinned=pinned)
            d.resize_card(*_TABS[index][2])
            self._drops[index] = d
        return self._drops[index]

    def _drop_pos(self, index):
        d = self._drop_for(index)
        chip = self._chips[index]
        cg = chip.mapToGlobal(QPoint(0, 0))
        scr = QApplication.primaryScreen().availableGeometry()
        x = cg.x() - SHADOW - 4
        x = max(scr.left() - SHADOW + 4,
                min(x, scr.right() - d.width() + SHADOW - 4))
        y = self.mapToGlobal(QPoint(0, self.height())).y() + GAP - SHADOW
        return QPoint(x, y)

    def _open_menu(self, index):
        prev = self._open
        d = self._drop_for(index)
        if prev is not None and prev != index:
            direction = 1 if index > prev else -1
            self._hide_menu(prev, offset=(direction * -12, 0))
            motion.present(d, self._drop_pos(index), offset=(direction * 18, 0))
        elif prev == index and d.isVisible() and not motion.is_leaving(d):
            pass
        else:
            motion.present(d, self._drop_pos(index), offset=(0, -10))
        d.raise_()
        self._open = index
        self._sync_chips()

    def _hide_menu(self, index, offset=(0, -6), instant=False):
        d = self._drops.get(index)
        if d:
            if instant:
                d.hide()
            else:
                motion.dismiss(d, offset=offset)
        if self._open == index:
            self._open = None
        self._sync_chips()

    def _chip_enter(self, index):
        if index == CHAT_INDEX:
            return               # chat is click-to-pin, not hover
        self._close_timer.stop()
        self._open_menu(index)

    def _chip_leave(self, index):
        if index == CHAT_INDEX:
            return
        self._close_timer.start()

    def _menu_enter(self, _index):
        self._close_timer.stop()

    def _menu_leave(self, _index):
        self._close_timer.start()

    def _held_open(self, d):
        """Reasons a hover menu must not close even though the cursor left:
        a modal dialog (e.g. a file picker) or popup (combo list, menu) is
        up, or the user is typing into a field inside the menu."""
        app = QApplication.instance()
        if app.activeModalWidget() is not None or app.activePopupWidget() is not None:
            return True
        focus = app.focusWidget()
        if (d.isActiveWindow() and focus is not None and d.isAncestorOf(focus)
                and isinstance(focus, (QLineEdit, QAbstractSpinBox, QPlainTextEdit,
                                       QTextEdit))):
            return True
        return False

    def _maybe_close(self):
        if self._open is None:
            return
        idx = self._open
        if self._held_open(self._drops[idx]):
            self._close_timer.start()      # check again shortly
            return
        pos = QCursor.pos()
        over_chip = self._chips[idx].rect().contains(
            self._chips[idx].mapFromGlobal(pos))
        d = self._drops.get(idx)
        card = d.card_rect().toRect().translated(d.pos())
        over_menu = d.isVisible() and card.adjusted(-GAP, -GAP - 2, GAP, GAP).contains(pos)
        if not over_chip and not over_menu:
            self._hide_menu(idx)

    def _chip_click(self, index):
        if index == CHAT_INDEX:
            self._toggle_chat()
        else:
            self._open_menu(index)

    def _toggle_chat(self):
        d = self._drop_for(CHAT_INDEX)
        if self._chat_pinned and d.isVisible():
            self._chat_pinned = False
            motion.dismiss(d)
        else:
            self._chat_pinned = True
            motion.present(d, self._drop_pos(CHAT_INDEX), offset=(0, -10))
            d.raise_(); d.activateWindow()
            if getattr(self.chat, "view", None):
                self.chat.view.setFocus()
        self._sync_chips()

    # -- painting ----------------------------------------------------------
    def paintEvent(self, _e):
        p = QPainter(self)
        r = self.rect()
        alpha = min(255, int(settings.get("card_opacity")) + 30)
        grad = QLinearGradient(0, 0, 0, r.height())
        grad.setColorAt(0.0, QColor(6, 6, 8, alpha))
        grad.setColorAt(1.0, QColor(13, 13, 16, alpha))
        p.fillRect(r, grad)
        # bottom hairline that fades out toward both edges
        line = QLinearGradient(r.left(), 0, r.right(), 0)
        line.setColorAt(0.0, QColor(255, 255, 255, 36))
        line.setColorAt(0.5, QColor(255, 255, 255, 18))
        line.setColorAt(1.0, QColor(255, 255, 255, 0))
        p.setPen(QPen(QBrush(line), 1))
        p.drawLine(r.left(), r.bottom(), r.right(), r.bottom())
        p.end()

    # -- stealth / lifecycle ----------------------------------------------
    def showEvent(self, e):
        super().showEvent(e)
        self._reposition()
        if self._apply_pending:
            self._apply_pending = False
            win_stealth.apply_tool_window(self)
            win_stealth.set_capture_exclusion(self, self._capture_on)
            win_stealth.set_click_through(self, self._click_through)
        if _IS_WINDOWS and not self._wts_registered:
            try:                       # re-show on unlock / resume-from-sleep
                ctypes.windll.wtsapi32.WTSRegisterSessionNotification(
                    int(self.winId()), 0)
                self._wts_registered = True
            except Exception:
                pass

    def nativeEvent(self, event_type, message):
        if _IS_WINDOWS and event_type == b"windows_generic_MSG":
            try:
                msg = ctypes.wintypes.MSG.from_address(int(message))
                if (msg.message == _WM_WTSSESSION_CHANGE
                        and msg.wParam in (_WTS_SESSION_UNLOCK, _WTS_SESSION_LOGON)):
                    self.show()
                    self.raise_()
            except Exception:
                pass
        return False, 0

    def _all_windows(self):
        return [self] + list(self._drops.values())

    def _on_setting(self, key, value):
        if key == "card_opacity":
            self.update()
            for d in self._drops.values():
                d.update()
        elif key == "capture_exclusion":
            self.set_capture(bool(value))
        elif key == "click_through":
            self._click_through = bool(value)
            win_stealth.set_click_through(self, self._click_through)

    # -- app-facing API (mirrors the old window) --------------------------
    def set_capture(self, on):
        self._capture_on = on
        for w in self._all_windows():
            win_stealth.set_capture_exclusion(w, on)
        self.status.set_hidden(on)

    def toggle_capture(self):
        settings.set("capture_exclusion", not self._capture_on)

    def toggle_click_through(self):
        settings.set("click_through", not self._click_through)

    def toggle_visible(self):
        if self.isVisible():
            for d in self._drops.values():
                d.hide()
            self._open = None
            self._sync_chips()
            motion.dismiss(self, offset=(0, -BAR_H // 2), duration=T.DUR_FAST)
        else:
            self._entering = True
            motion.present(self, self._home(), offset=(0, -BAR_H))
            self._entering = False
            self.raise_()
            self.activateWindow()

    def cycle_tab(self):
        nxt = 0 if self._open is None else (self._open + 1) % len(_TABS)
        if nxt == CHAT_INDEX:
            nxt = (nxt + 1) % len(_TABS)
        self._open_menu(nxt)

    def panic(self):
        # deliberately instant: no exit animation on the panic path
        self.set_capture(False)
        for d in self._drops.values():
            d.hide()
        self._chat_pinned = False
        self._open = None
        self._sync_chips()
        self.hide()

    def nudge(self, dx, dy):
        self.move(self.x() + dx, self.y() + dy)

    def _grab_clean(self, keep_chat=False):
        """Hide every overlay window instantly, grab the screen, then bring
        the bar back. Returns the QImage (or None)."""
        was = self.isVisible()
        for d in self._drops.values():
            if not (keep_chat and d is self._drops.get(CHAT_INDEX) and self._chat_pinned):
                d.hide()
        self._open = None
        if was:
            self.hide()
        QApplication.processEvents()
        try:
            image = _shot_history.grab_screen()
        except Exception:
            image = None
        if was:
            self.show()
        self._sync_chips()
        return image

    def take_screenshot(self):
        """Screenshot hotkey / button: save to history and copy to the
        clipboard. The overlay itself is never in the shot."""
        image = self._grab_clean()
        if image is None:
            return
        _shot_history.add(image)
        QApplication.clipboard().setImage(image)
        idx = [attr for _l, attr, _s in _TABS].index("history")
        self._chips[idx].set_on(True)           # HISTORY glows briefly = saved
        QTimer.singleShot(1200, self._sync_chips)

    def send_image_to_chat(self, image, mode="summary"):
        if not self._chat_pinned:
            self._toggle_chat()
        else:
            self._drop_for(CHAT_INDEX).show()
        self._sync_chips()
        if hasattr(self.chat, "inject_capture"):
            self.chat.inject_capture(image, mode)

    def capture_analyze(self, mode="deep"):
        image = self._grab_clean(keep_chat=True)
        if image is not None:
            _shot_history.add(image)
        self.show()
        self.send_image_to_chat(image, mode)

    def shutdown(self):
        for p in self._panels.values():
            if hasattr(p, "shutdown"):
                try:
                    p.shutdown()
                except Exception:
                    pass
        for d in self._drops.values():
            d.close()
