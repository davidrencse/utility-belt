"""
The overlay window itself: frameless, translucent, always-on-top, draggable
by its header, with a segmented tab strip switching between the utility-belt
panels. Capture-exclusion is applied right after the native window exists.

The rounded card, header divider and status pill are painted against a fully
transparent window so we control every pixel. A bottom-right grip resizes it.
"""
import os
import webbrowser

from PySide6.QtCore import Qt, QRectF, QPointF
from PySide6.QtGui import (QPainter, QColor, QBrush, QPainterPath, QPen,
                           QFont, QLinearGradient)
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                               QStackedWidget, QLabel, QSizeGrip, QMenu,
                               QFileDialog)

from . import theme as T
from .core import stealth as win_stealth
from .platform_utils import IS_WINDOWS, open_path, runtime_note
from .settings import settings
from .panels.system_panel import SystemPanel
from .panels.tools_panel import ToolsPanel
from .panels.chatgpt_panel import ChatGPTPanel
from .panels.settings_panel import SettingsPanel

PAD = 11  # transparent gutter around the card


class TabBar(QWidget):
    """Segmented control with a sliding accent pill under the active tab."""

    def __init__(self, names, on_select, parent=None):
        super().__init__(parent)
        self._names = names
        self._on_select = on_select
        self._active = 0
        self._hover = -1
        self.setFixedHeight(30)
        self.setMouseTracking(True)
        self.setCursor(Qt.PointingHandCursor)

    def set_active(self, idx):
        self._active = idx
        self.update()

    def _seg_rects(self):
        n = len(self._names)
        w = self.width() / n
        return [QRectF(i * w, 0, w, self.height()) for i in range(n)]

    def mouseMoveEvent(self, e):
        x = e.position().x()
        self._hover = min(len(self._names) - 1, int(x / (self.width() / len(self._names))))
        self.update()

    def leaveEvent(self, _e):
        self._hover = -1
        self.update()

    def mousePressEvent(self, e):
        idx = min(len(self._names) - 1, int(e.position().x() / (self.width() / len(self._names))))
        self._active = idx
        self._on_select(idx)
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        rects = self._seg_rects()
        f = QFont(T.UI, 8, QFont.Bold)
        f.setLetterSpacing(QFont.AbsoluteSpacing, 1.2)
        p.setFont(f)
        fm = p.fontMetrics()
        for i, (name, r) in enumerate(zip(self._names, rects)):
            if i == self._active:
                p.setPen(T.TEXT)
            elif i == self._hover:
                p.setPen(T.TEXT_MUTED)
            else:
                p.setPen(T.TEXT_DIM)
            p.drawText(r, Qt.AlignCenter, name)
            if i == self._active:
                tw = fm.horizontalAdvance(name)
                cx = r.center().x()
                y = r.bottom() - 4
                p.setPen(QPen(T.TEXT, 2))
                p.drawLine(QPointF(cx - tw / 2, y), QPointF(cx + tw / 2, y))
        p.end()


class OverlayWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint
                            | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setWindowTitle("sysmon-overlay")
        self.resize(468, 606)
        self.setMinimumSize(392, 440)

        self._drag = None
        self._capture_on = bool(settings.get("capture_exclusion"))
        self._click_through = bool(settings.get("click_through"))
        self._apply_stealth_pending = True
        self._apply_always_on_top(settings.get("always_on_top"), initial=True)

        self._build()
        self._select(int(settings.get("start_tab") or 0))
        settings.changed.connect(self._on_setting)

    # -- UI ----------------------------------------------------------------
    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(PAD + 4, PAD + 3, PAD + 4, PAD + 3)
        outer.setSpacing(0)

        # header
        header = QWidget()
        header.setFixedHeight(32)
        h = QHBoxLayout(header)
        h.setContentsMargins(2, 0, 0, 0)
        h.setSpacing(7)

        self._logo = QLabel()
        self._logo.setFixedSize(14, 14)  # drawn in paintEvent via geometry marker
        title = QLabel("SYSMON")
        tf = QFont(T.MONO, 9); tf.setBold(True)
        tf.setLetterSpacing(QFont.AbsoluteSpacing, 3.0)
        title.setFont(tf)
        title.setStyleSheet(f"color:{T.hexs(T.TEXT)};")
        h.addWidget(self._logo)
        h.addWidget(title)
        h.addSpacing(4)

        self.badge = QLabel("HIDDEN")
        self.badge.setToolTip(self._capture_tooltip())
        self._style_badge(True, True)
        h.addWidget(self.badge)
        h.addStretch(1)

        quick = QPushButton("⋯")
        quick.setToolTip("Quick launch — open saved folders, files or links")
        quick.clicked.connect(self._show_quick_menu)
        mini = QPushButton("–")
        close = QPushButton("✕")
        for b, cb, hover in ((quick, None, T.ACCENT),
                             (mini, self.hide, T.TEXT),
                             (close, self._quit, T.DANGER)):
            b.setFixedSize(24, 22)
            b.setCursor(Qt.PointingHandCursor)
            b.setStyleSheet(
                f"QPushButton{{background:transparent;color:{T.hexs(T.TEXT_MUTED)};"
                f"border:none;border-radius:6px;font:11pt '{T.UI}';}}"
                f"QPushButton:hover{{background:{T.rgba(T.SURFACE_HOVER)};"
                f"color:{T.hexs(hover)};}}")
            if cb is not None:
                b.clicked.connect(cb)
            h.addWidget(b)
        self._quick_btn = quick
        self._header = header
        outer.addWidget(header)
        outer.addSpacing(6)

        # tabs
        self.stack = QStackedWidget()
        self.system = SystemPanel()
        self.tools = ToolsPanel()
        self.chat = ChatGPTPanel()
        self.settingsp = SettingsPanel()
        self._panels = [self.system, self.tools, self.chat, self.settingsp]
        for w in self._panels:
            self.stack.addWidget(w)
        self.tabbar = TabBar(["SYSTEM", "TOOLS", "CHAT", "SETTINGS"],
                             self._select)
        outer.addWidget(self.tabbar)
        outer.addSpacing(6)
        outer.addWidget(self.stack, 1)

        # footer: hotkey hint + resize grip
        foot = QHBoxLayout()
        foot.setContentsMargins(2, 4, 0, 0)
        hint = QLabel("drag anywhere to move  ·  keybinds in Settings")
        hint.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:7pt '{T.MONO}';")
        foot.addWidget(hint)
        foot.addStretch(1)
        grip = QSizeGrip(self)
        grip.setStyleSheet("background:transparent;")
        foot.addWidget(grip, 0, Qt.AlignRight | Qt.AlignBottom)
        outer.addLayout(foot)

        self._select(0)

    def _style_badge(self, on, ok):
        if on and ok:
            fg, txt = T.TEXT_MUTED, "HIDDEN"
        elif on and not ok:
            fg, txt = T.TEXT, "UNSUPPORTED"
        else:
            fg, txt = T.TEXT, "VISIBLE"
        self.badge.setText("● " + txt)
        self.badge.setStyleSheet(
            f"color:{T.hexs(fg)};background:transparent;border:none;"
            f"font:700 7pt '{T.MONO}';letter-spacing:1px;")
        self.badge.setToolTip(self._capture_tooltip(ok))

    def _capture_tooltip(self, ok=False):
        if IS_WINDOWS:
            return "Excluded from screen capture when enabled"
        if ok:
            return "Screen-capture hiding is off"
        return f"Screen-capture hiding is not available on {runtime_note()}"

    def _select(self, idx):
        self.stack.setCurrentIndex(idx)
        self.tabbar.set_active(idx)

    def cycle_tab(self):
        self._select((self.stack.currentIndex() + 1) % self.stack.count())

    # -- painting (card) ---------------------------------------------------
    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        r = self.rect().adjusted(PAD, PAD, -PAD, -PAD)

        path = QPainterPath()
        path.addRoundedRect(QRectF(r), T.R_CARD, T.R_CARD)
        # subtle top-down sheen so the flat card has depth; alpha is the
        # user's transparency setting so the desktop shows through
        alpha = int(settings.get("card_opacity"))
        grad = QLinearGradient(0, r.top(), 0, r.bottom())
        grad.setColorAt(0.0, QColor(10, 10, 11, alpha))
        grad.setColorAt(1.0, QColor(6, 8, 12, alpha))
        p.fillPath(path, QBrush(grad))

        # border: faint white hairline
        p.setPen(QPen(QColor(255, 255, 255, 60), 1.2))
        p.drawPath(path)

        # header divider
        p.setPen(QPen(T.HAIRLINE, 1))
        y = r.top() + 44
        p.drawLine(r.left() + 14, y, r.right() - 14, y)

        # logo mark: concentric accent ring at the header dot
        lg = self._logo.geometry()
        cx = self._header.x() + lg.center().x() + PAD + 4
        cy = self._header.y() + lg.center().y() + PAD + 3
        p.setPen(QPen(T.ACCENT, 1.6))
        p.setBrush(Qt.NoBrush)
        p.drawEllipse(QRectF(cx - 6, cy - 6, 12, 12))
        p.setBrush(T.ACCENT)
        p.setPen(Qt.NoPen)
        p.drawEllipse(QRectF(cx - 2.4, cy - 2.4, 4.8, 4.8))
        p.end()

    # -- drag to move (from any empty area) -------------------------------
    # Interactive controls (buttons, inputs, tables, the tab bar, webviews)
    # consume their own presses, so any press that reaches the window landed
    # on empty space / a label / a graph - safe to start a drag there.
    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._drag = e.globalPosition().toPoint() - self.frameGeometry().topLeft()
            e.accept()

    def mouseMoveEvent(self, e):
        if self._drag is not None and e.buttons() & Qt.LeftButton:
            self.move(e.globalPosition().toPoint() - self._drag)
            e.accept()

    def mouseReleaseEvent(self, _e):
        self._drag = None

    # -- stealth -----------------------------------------------------------
    def showEvent(self, e):
        super().showEvent(e)
        self.system.set_paused(False)   # resume telemetry when visible
        if self._apply_stealth_pending:
            self._apply_stealth_pending = False
            win_stealth.apply_tool_window(self)
            self.set_capture(self._capture_on)
            win_stealth.set_click_through(self, self._click_through)

    def hideEvent(self, e):
        super().hideEvent(e)
        # stop pinging / sampling / repainting while hidden - saves CPU
        self.system.set_paused(True)

    def set_capture(self, on):
        self._capture_on = on
        ok = win_stealth.set_capture_exclusion(self, on)
        self._style_badge(on, ok)

    def toggle_capture(self):
        settings.set("capture_exclusion", not self._capture_on)

    # -- quick launch ------------------------------------------------------
    def _show_quick_menu(self):
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu{{background:{T.hexs(T.SURFACE_2)};color:{T.hexs(T.TEXT)};"
            f"border:1px solid {T.hexs(T.BORDER)};border-radius:8px;padding:4px;"
            f"font:9pt '{T.UI}';}}"
            f"QMenu::item{{padding:5px 18px;border-radius:5px;}}"
            f"QMenu::item:selected{{background:{T.rgba(T.ACCENT_SOFT)};}}"
            f"QMenu::separator{{height:1px;background:{T.hexs(T.BORDER)};margin:4px 8px;}}")
        shortcuts = settings.get("shortcuts") or []
        if not shortcuts:
            act = menu.addAction("(no shortcuts yet)")
            act.setEnabled(False)
        for sc in shortcuts:
            label = sc.get("label") or sc.get("path", "")
            act = menu.addAction(label)
            act.triggered.connect(lambda _=False, p=sc.get("path", ""): self._open_shortcut(p))
        menu.addSeparator()
        add_folder = menu.addAction("Add folder…")
        add_folder.triggered.connect(lambda: self._add_shortcut("folder"))
        add_file = menu.addAction("Add file…")
        add_file.triggered.connect(lambda: self._add_shortcut("file"))
        menu.exec(self._quick_btn.mapToGlobal(self._quick_btn.rect().bottomLeft()))

    def _open_shortcut(self, path):
        if not path:
            return
        low = path.lower()
        if low.startswith(("http://", "https://")):
            # open as a "quick tab" in the embedded browser
            idx = self.stack.indexOf(self.chat)
            self._select(idx)
            if getattr(self.chat, "view", None):
                self.chat._load(path)
            else:
                webbrowser.open(path)
            return
        try:
            ok = open_path(path)
            if not ok:
                self.badge.setToolTip(f"couldn't open: {path}")
        except OSError as exc:
            self.badge.setToolTip(f"couldn't open: {exc}")

    def _add_shortcut(self, kind):
        if kind == "folder":
            path = QFileDialog.getExistingDirectory(self, "Pick a folder to pin")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Pick a file to pin")
        if not path:
            return
        label = os.path.basename(os.path.normpath(path)) or path
        current = list(settings.get("shortcuts") or [])
        current.append({"label": label, "path": path})
        settings.set("shortcuts", current)

    # -- react to settings -------------------------------------------------
    def _on_setting(self, key, value):
        if key == "card_opacity":
            self.update()
        elif key == "capture_exclusion":
            self.set_capture(bool(value))
        elif key == "click_through":
            self._click_through = bool(value)
            win_stealth.set_click_through(self, self._click_through)
        elif key == "always_on_top":
            self._apply_always_on_top(bool(value))

    def _apply_always_on_top(self, on, initial=False):
        flags = (Qt.FramelessWindowHint | Qt.Tool)
        if on:
            flags |= Qt.WindowStaysOnTopHint
        self.setWindowFlags(flags)
        if not initial:
            # changing flags hides the window; re-show and re-apply stealth
            self._apply_stealth_pending = True
            self.show()

    def toggle_click_through(self):
        settings.set("click_through", not self._click_through)

    def toggle_visible(self):
        if self.isVisible():
            self.hide()
        else:
            self.show()
            self.raise_()

    def panic(self):
        self.set_capture(False)
        self.hide()

    def nudge(self, dx, dy):
        self.move(self.x() + dx, self.y() + dy)

    def _quit(self):
        from PySide6.QtWidgets import QApplication
        self.shutdown()
        QApplication.instance().quit()

    def shutdown(self):
        for w in self._panels:
            if hasattr(w, "shutdown"):
                try:
                    w.shutdown()
                except Exception:
                    pass
