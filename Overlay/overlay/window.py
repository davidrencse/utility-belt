"""
The overlay window itself: frameless, translucent, always-on-top, draggable
by its header, with a segmented tab strip switching between the utility-belt
panels. Capture-exclusion is applied right after the native window exists.

The rounded card, header divider and status pill are painted against a fully
transparent window so we control every pixel. A bottom-right grip resizes it.
"""
import os
import webbrowser

from PySide6.QtCore import (Qt, QRectF, QPointF, QRect, QTimer,
                            QVariantAnimation, QEasingCurve, QPropertyAnimation)
from PySide6.QtGui import (QPainter, QColor, QBrush, QPainterPath, QPen,
                           QFont, QFontMetrics, QLinearGradient, QShortcut,
                           QKeySequence)
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                               QStackedWidget, QLabel, QSizeGrip, QMenu,
                               QFileDialog, QGraphicsOpacityEffect)

from . import theme as T
from .core import stealth as win_stealth
from .platform_utils import IS_WINDOWS, open_path, runtime_note
from .settings import settings
from .panels.system_panel import SystemPanel
from .panels.tools_panel import ToolsPanel
from .panels.weather_panel import WeatherPanel
from .panels.chatgpt_panel import ChatGPTPanel
from .panels.settings_panel import SettingsPanel

PAD = 11  # transparent gutter around the card


class TabBar(QWidget):
    """Segmented control with an animated sliding underline. A tab can be
    dragged downward/out of the bar to tear it off into its own window
    (Chrome-style); a short press just selects it."""

    _TEAR = 26   # px of drag before a tab tears off

    def __init__(self, names, on_select, on_detach=None, parent=None):
        super().__init__(parent)
        self._names = names
        self._on_select = on_select
        self._on_detach = on_detach
        self._active = 0
        self._hover = -1
        self._detached = set()
        self._drop = False
        self._press_idx = -1
        self._press_pos = None
        self._torn = False
        # animated underline
        self._ind_x = 0.0
        self._ind_w = 0.0
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(180)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self._anim.valueChanged.connect(self._on_anim)
        self.setFixedHeight(30)
        self.setMouseTracking(True)
        self.setCursor(Qt.PointingHandCursor)

    def _idx_at(self, x):
        return max(0, min(len(self._names) - 1,
                          int(x / (self.width() / len(self._names)))))

    def _target_indicator(self, idx):
        f = QFont(T.UI, 8, QFont.Bold)
        f.setLetterSpacing(QFont.AbsoluteSpacing, 1.2)
        tw = QFontMetrics(f).horizontalAdvance(self._names[idx])
        w = self.width() / len(self._names)
        cx = idx * w + w / 2
        return cx - tw / 2, float(tw)

    def set_active(self, idx):
        self._active = idx
        tx, tw = self._target_indicator(idx)
        if self._ind_w == 0.0:      # first placement - no animation
            self._ind_x, self._ind_w = tx, tw
        else:
            self._anim.stop()
            self._anim.setStartValue((self._ind_x, self._ind_w))
            self._anim.setEndValue((tx, tw))
            self._anim.start()
        self.update()

    def _on_anim(self, val):
        self._ind_x, self._ind_w = val
        self.update()

    def set_detached(self, indices):
        self._detached = set(indices)
        self.update()

    def set_drop_hint(self, on):
        on = bool(on)
        if on != self._drop:
            self._drop = on
            self.update()

    def _seg_rects(self):
        n = len(self._names)
        w = self.width() / n
        return [QRectF(i * w, 0, w, self.height()) for i in range(n)]

    def mouseMoveEvent(self, e):
        if e.buttons() & Qt.LeftButton and self._press_idx >= 0 and not self._torn:
            d = e.position().toPoint() - self._press_pos
            if abs(d.y()) > self._TEAR or abs(d.x()) > self._TEAR * 2:
                self._torn = True
                if self._on_detach:
                    self._on_detach(self._press_idx, e.globalPosition().toPoint())
            return
        self._hover = self._idx_at(e.position().x())
        self.update()

    def leaveEvent(self, _e):
        self._hover = -1
        self.update()

    def mousePressEvent(self, e):
        if e.button() != Qt.LeftButton:
            return
        self._press_idx = self._idx_at(e.position().x())
        self._press_pos = e.position().toPoint()
        self._torn = False
        self._on_select(self._press_idx)

    def mouseReleaseEvent(self, _e):
        self._press_idx = -1
        self._torn = False

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        if self._drop:      # highlight the bar as a drop target while docking
            hr = QRectF(self.rect()).adjusted(1, 1, -1, -1)
            p.setPen(QPen(QColor(255, 255, 255, 150), 1.4, Qt.DashLine))
            p.setBrush(QBrush(QColor(255, 255, 255, 26)))
            p.drawRoundedRect(hr, 7, 7)
        rects = self._seg_rects()
        f = QFont(T.UI, 8, QFont.Bold)
        f.setLetterSpacing(QFont.AbsoluteSpacing, 1.2)
        p.setFont(f)
        for i, (name, r) in enumerate(zip(self._names, rects)):
            label = (name + "  ⧉") if i in self._detached else name
            if i in self._detached:
                p.setPen(T.TEXT_DIM)
            elif i == self._active:
                p.setPen(T.TEXT)
            elif i == self._hover:
                p.setPen(T.TEXT_MUTED)
            else:
                p.setPen(T.TEXT_DIM)
            p.drawText(r, Qt.AlignCenter, label)
        if self._active not in self._detached and self._ind_w > 0:
            y = self.height() - 4
            p.setPen(QPen(T.TEXT, 2))
            p.drawLine(QPointF(self._ind_x, y), QPointF(self._ind_x + self._ind_w, y))
        p.end()


class OverlayWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint
                            | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setWindowTitle("sysmon-overlay")
        self.resize(820, 340)          # landscape / horizontal HUD
        self.setMinimumSize(600, 300)

        self._drag = None
        self._resize = ""            # edge(s) being dragged: combo of l/r/t/b
        self._start_geo = None
        self._start_mouse = None
        self.setMouseTracking(True)
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
        self.weather = WeatherPanel()
        self.chat = ChatGPTPanel()
        self.settingsp = SettingsPanel()
        self._panels = [self.system, self.tools, self.weather,
                        self.chat, self.settingsp]
        self._tabs = [("SYSTEM", self.system), ("TOOLS", self.tools),
                      ("WEATHER", self.weather), ("CHAT", self.chat),
                      ("SETTINGS", self.settingsp)]
        self._detached = {}          # panel -> DetachedWindow
        self._active_tab = 0
        for w in self._panels:
            self.stack.addWidget(w)
        self.tabbar = TabBar([n for n, _ in self._tabs], self._select,
                             on_detach=self._tear_off)
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

        # zoom shortcuts (Ctrl +/- and Ctrl+0)
        for seq in ("Ctrl+=", "Ctrl++"):
            QShortcut(QKeySequence(seq), self, activated=lambda: self.zoom(1))
        QShortcut(QKeySequence("Ctrl+-"), self, activated=lambda: self.zoom(-1))
        QShortcut(QKeySequence("Ctrl+0"), self, activated=self.zoom_reset)

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

    def _tab_index(self, panel):
        return next(i for i, (_, p) in enumerate(self._tabs) if p is panel)

    def _select(self, idx):
        self._active_tab = idx
        name, panel = self._tabs[idx]
        self.tabbar.set_active(idx)
        if panel in self._detached:          # torn-off: raise its own window
            dw = self._detached[panel]
            dw.show(); dw.raise_(); dw.activateWindow()
            return
        self.stack.setCurrentWidget(panel)
        self._fade(panel)
        # efficiency: only sample telemetry while SYSTEM is the shown tab
        # (or torn off into its own window)
        self.system.set_paused(panel is not self.system
                               and self.system not in self._detached)
        if panel is self.chat and getattr(self.chat, "view", None):
            self.activateWindow()
            self.raise_()
            self.chat.view.setFocus()

    def _fade(self, panel):
        # a quick opacity fade-in makes tab switches feel seamless; skip web
        # panels (a graphics effect corrupts QtWebEngine rendering)
        if panel is self.chat or panel is self.tools:
            return
        eff = QGraphicsOpacityEffect(panel)
        panel.setGraphicsEffect(eff)
        anim = QPropertyAnimation(eff, b"opacity", self)
        anim.setDuration(150)
        anim.setStartValue(0.2)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.finished.connect(lambda: panel.setGraphicsEffect(None))
        anim.start()
        self._fade_anim = anim   # keep a ref so it isn't GC'd mid-flight

    def cycle_tab(self):
        self._select((self._active_tab + 1) % len(self._tabs))

    # -- detach / merge (Chrome-style tab tear-off) ------------------------
    def _detached_indices(self):
        return {i for i, (_, p) in enumerate(self._tabs) if p in self._detached}

    def detach_current(self):
        self.detach(self._active_tab)

    def _tear_off(self, idx, global_pos):
        self.detach(idx, global_pos)

    def detach(self, idx, at=None):
        name, panel = self._tabs[idx]
        if panel in self._detached:
            self._detached[panel].raise_()
            return
        size = panel.size()
        self.stack.removeWidget(panel)
        dw = DetachedWindow(panel, name, self)
        self._detached[panel] = dw
        dw.resize(max(380, size.width() // 1), max(320, size.height()))
        if at is not None:
            dw.move(at.x() - 60, at.y() - 12)   # appear under the cursor
        dw.show()
        dw.raise_()
        dw.activateWindow()
        self.tabbar.set_detached(self._detached_indices())
        # show a still-docked tab in the main window
        for i, (_, p) in enumerate(self._tabs):
            if p not in self._detached:
                self._select(i)
                break

    def dock_zone_contains(self, gpos):
        """True if a global point is over the main window's top strip (tab
        bar + header) - the drop target for docking a torn-off tab."""
        if not self.isVisible():
            return False
        tb = self.tabbar
        tl = tb.mapToGlobal(tb.rect().topLeft())
        zone = QRect(tl.x() - 12, tl.y() - 34, tb.width() + 24, tb.height() + 48)
        return zone.contains(gpos)

    def set_dock_hint(self, on):
        self.tabbar.set_drop_hint(on)

    def merge(self, panel):
        dw = self._detached.pop(panel, None)
        if dw is None:
            return
        idx = self._tab_index(panel)
        insert_at = sum(1 for j, (_, p) in enumerate(self._tabs)
                        if j < idx and p not in self._detached)
        panel.setParent(None)
        self.stack.insertWidget(insert_at, panel)
        self.tabbar.set_detached(self._detached_indices())
        dw.mark_merging()
        dw.close()
        self._select(idx)

    def capture_analyze(self, mode="deep"):
        """Screenshot the screen (without the overlay in the shot), switch to
        the ChatGPT tab, and paste the image + the chosen prompt so the user
        only has to press Enter. No API key - drives the web UI."""
        from PySide6.QtWidgets import QApplication
        was_visible = self.isVisible()
        if was_visible:
            self.hide()
            QApplication.processEvents()
        try:
            image = QApplication.primaryScreen().grabWindow(0).toImage()
        except Exception:
            image = None
        self.show()
        self.raise_()
        self.activateWindow()
        self._select(self._tab_index(self.chat))
        if hasattr(self.chat, "inject_capture"):
            self.chat.inject_capture(image, mode)

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
        p.end()

    # -- move + edge/corner resize (frameless) ----------------------------
    _RESIZE_MARGIN = 8

    def _edge_at(self, pos):
        m = self._RESIZE_MARGIN
        x, y, w, h = pos.x(), pos.y(), self.width(), self.height()
        edge = ""
        if y <= m:
            edge += "t"
        elif y >= h - m:
            edge += "b"
        if x <= m:
            edge += "l"
        elif x >= w - m:
            edge += "r"
        return edge

    def _cursor_for(self, edge):
        if edge in ("tl", "br"):
            return Qt.SizeFDiagCursor
        if edge in ("tr", "bl"):
            return Qt.SizeBDiagCursor
        if edge in ("l", "r"):
            return Qt.SizeHorCursor
        if edge in ("t", "b"):
            return Qt.SizeVerCursor
        return Qt.ArrowCursor

    def mousePressEvent(self, e):
        if e.button() != Qt.LeftButton:
            return
        edge = self._edge_at(e.position().toPoint())
        if edge:
            self._resize = edge
            self._start_geo = self.geometry()
            self._start_mouse = e.globalPosition().toPoint()
        else:
            self._drag = e.globalPosition().toPoint() - self.frameGeometry().topLeft()
        e.accept()

    def mouseMoveEvent(self, e):
        # no button held: just reflect the resize cursor near edges
        if not (e.buttons() & Qt.LeftButton):
            self.setCursor(self._cursor_for(self._edge_at(e.position().toPoint())))
            return
        if self._resize:
            self._do_resize(e.globalPosition().toPoint())
        elif self._drag is not None:
            self.move(e.globalPosition().toPoint() - self._drag)
        e.accept()

    def _do_resize(self, gpos):
        d = gpos - self._start_mouse
        g = QRect(self._start_geo)
        minw, minh = self.minimumWidth(), self.minimumHeight()
        if "l" in self._resize:
            g.setLeft(min(g.left() + d.x(), g.right() - minw))
        if "r" in self._resize:
            g.setRight(max(g.right() + d.x(), g.left() + minw))
        if "t" in self._resize:
            g.setTop(min(g.top() + d.y(), g.bottom() - minh))
        if "b" in self._resize:
            g.setBottom(max(g.bottom() + d.y(), g.top() + minh))
        self.setGeometry(g)

    def mouseReleaseEvent(self, _e):
        self._drag = None
        self._resize = ""

    # -- zoom --------------------------------------------------------------
    def _active_web_view(self):
        w = self._tabs[self._active_tab][1]
        if w in self._detached:
            return None
        if w is self.chat:
            return getattr(self.chat, "view", None)
        if w is self.tools:
            sub = self.tools.stack.currentWidget()
            return getattr(sub, "view", None)
        return None

    def zoom(self, direction):
        """Ctrl +/- : zoom the web page when a browser tab is active, else
        grow/shrink the whole HUD (which scales gauges, graphs and tables)."""
        view = self._active_web_view()
        if view is not None:
            f = max(0.3, min(3.0, round(view.zoomFactor() + 0.1 * direction, 2)))
            view.setZoomFactor(f)
            return
        factor = 1.1 if direction > 0 else 1 / 1.1
        w = max(self.minimumWidth(), min(2200, int(self.width() * factor)))
        h = max(self.minimumHeight(), min(1400, int(self.height() * factor)))
        self.resize(w, h)

    def zoom_reset(self):
        view = self._active_web_view()
        if view is not None:
            view.setZoomFactor(1.0)
        else:
            self.resize(820, 340)

    def wheelEvent(self, e):
        if e.modifiers() & Qt.ControlModifier:
            self.zoom(1 if e.angleDelta().y() > 0 else -1)
            e.accept()

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
        # stop sampling while hidden - unless SYSTEM is torn off into its own
        # window, which is still visible
        if self.system not in self._detached:
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
            self._select(self._tab_index(self.chat))
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
            self.activateWindow()   # allow typing immediately

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
        for dw in list(self._detached.values()):
            dw.mark_merging()
            dw.close()
        self._detached.clear()
        for w in self._panels:
            if hasattr(w, "shutdown"):
                try:
                    w.shutdown()
                except Exception:
                    pass


class DetachedWindow(QWidget):
    """A torn-off tab living in its own frameless window. Reparents the panel
    in on creation and hands it back to the main overlay when docked/closed."""

    def __init__(self, panel, name, main):
        super().__init__()
        self._main = main
        self._panel = panel
        self._merging = False
        self._drag = None
        self._apply_pending = True
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint
                            | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setWindowTitle(f"sysmon-overlay · {name}")
        self.setMinimumSize(360, 300)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(PAD + 4, PAD + 3, PAD + 4, PAD + 3)
        outer.setSpacing(6)

        self._over_dock = False
        header = QWidget()
        header.setFixedHeight(28)
        h = QHBoxLayout(header)
        h.setContentsMargins(4, 0, 4, 0)
        h.setSpacing(7)
        title = QLabel(name)
        tf = QFont(T.MONO, 9); tf.setBold(True)
        tf.setLetterSpacing(QFont.AbsoluteSpacing, 2.0)
        title.setFont(tf)
        title.setStyleSheet(f"color:{T.hexs(T.TEXT)};")
        h.addWidget(title)
        h.addStretch(1)
        hint = QLabel("drag onto the tab bar to dock")
        hint.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:7pt '{T.MONO}';")
        h.addWidget(hint)
        self._header = header
        outer.addWidget(header)

        panel.setParent(self)
        panel.show()
        outer.addWidget(panel, 1)

        foot = QHBoxLayout()
        foot.addStretch(1)
        grip = QSizeGrip(self)
        grip.setStyleSheet("background:transparent;")
        foot.addWidget(grip, 0, Qt.AlignRight | Qt.AlignBottom)
        outer.addLayout(foot)

    def mark_merging(self):
        self._merging = True

    def _dock(self):
        self._main.set_dock_hint(False)
        self._main.merge(self._panel)

    # -- card paint (matches the main overlay) -----------------------------
    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        r = self.rect().adjusted(PAD, PAD, -PAD, -PAD)
        path = QPainterPath()
        path.addRoundedRect(QRectF(r), T.R_CARD, T.R_CARD)
        alpha = int(settings.get("card_opacity"))
        grad = QLinearGradient(0, r.top(), 0, r.bottom())
        grad.setColorAt(0.0, QColor(10, 10, 11, alpha))
        grad.setColorAt(1.0, QColor(6, 8, 12, alpha))
        p.fillPath(path, QBrush(grad))
        p.setPen(QPen(QColor(255, 255, 255, 60), 1.2))
        p.drawPath(path)
        p.end()

    def showEvent(self, e):
        super().showEvent(e)
        if self._apply_pending:
            self._apply_pending = False
            win_stealth.apply_tool_window(self)
            win_stealth.set_capture_exclusion(self, self._main._capture_on)

    def closeEvent(self, e):
        if not self._merging:
            e.ignore()
            QTimer.singleShot(0, self._dock)
        else:
            e.accept()

    # -- drag to move / drop onto the tab bar to dock ---------------------
    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._drag = e.globalPosition().toPoint() - self.frameGeometry().topLeft()
            e.accept()

    def mouseMoveEvent(self, e):
        if self._drag is not None and e.buttons() & Qt.LeftButton:
            gpos = e.globalPosition().toPoint()
            self.move(gpos - self._drag)
            self._over_dock = self._main.dock_zone_contains(gpos)
            self._main.set_dock_hint(self._over_dock)
            e.accept()

    def mouseReleaseEvent(self, _e):
        was_dragging = self._drag is not None
        self._drag = None
        if was_dragging and self._over_dock:
            self._over_dock = False
            self._dock()          # merge back into the main overlay
        else:
            self._main.set_dock_hint(False)
