"""
Settings tab - toggles for UI, stealth behaviour and performance. Every
control writes to the shared `settings` store, which persists to disk and
emits `changed`; the window and the other panels listen and update live.

Layout: eyebrow section titles over grouped cards of rows (label + optional
hint on the left, control on the right, hairlines between rows). Boolean
rows are fully clickable - the whole row is the hit target, not just the
switch.
"""
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QSlider, QComboBox, QLineEdit, QScrollArea,
                               QFrame)

from .. import theme as T
from ..platform_utils import IS_WINDOWS, runtime_note
from ..settings import settings
from ..subtabs import SubTabHost
from ..widgets import Switch


def _section(text):
    lbl = QLabel(text.upper())
    lbl.setStyleSheet(T.label_qss("eyebrow") + "padding:0 2px;")
    lbl.setContentsMargins(0, T.S3, 0, T.S1)
    return lbl


class _Group(QFrame):
    """Rounded card holding rows separated by hairlines."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("group")
        self.setStyleSheet(
            f"QFrame#group{{background:{T.rgba(QColor(255, 255, 255, 7))};"
            f"border:1px solid {T.rgba(T.HAIRLINE)};border-radius:{T.R_CTRL + 2}px;}}")
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(0, 0, 0, 0)
        self._lay.setSpacing(0)
        self._rows = 0

    def add(self, widget):
        if self._rows:
            line = QFrame()
            line.setFixedHeight(1)
            line.setStyleSheet(f"background:{T.rgba(T.BORDER_SOFT)};margin:0 12px;")
            self._lay.addWidget(line)
        self._lay.addWidget(widget)
        self._rows += 1
        return widget


class _Row(QWidget):
    def __init__(self, label, control=None, hint=None, clickable=None, parent=None):
        super().__init__(parent)
        self._click = clickable
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setObjectName("row")
        self.setStyleSheet(
            "QWidget#row{background:transparent;border-radius:9px;}"
            + ("QWidget#row:hover{background:rgba(255,255,255,8);}" if clickable else ""))
        if clickable:
            self.setCursor(Qt.PointingHandCursor)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(T.S3, T.S2, T.S3, T.S2)
        lay.setSpacing(T.S3)
        text = QVBoxLayout()
        text.setSpacing(1)
        self.label = QLabel(label)
        self.label.setStyleSheet(T.label_qss("body"))
        text.addWidget(self.label)
        if hint:
            h = QLabel(hint)
            h.setStyleSheet(T.label_qss("caption"))
            h.setWordWrap(True)
            text.addWidget(h)
        lay.addLayout(text, 1)
        if control is not None:
            lay.addWidget(control, 0, Qt.AlignVCenter)

    def mouseReleaseEvent(self, e):
        if self._click and e.button() == Qt.LeftButton and self.rect().contains(e.position().toPoint()):
            self._click()
        super().mouseReleaseEvent(e)


def _page():
    """Scrollable, transparent page; returns (scroll, body layout)."""
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.NoFrame)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    scroll.setStyleSheet("QScrollArea{background:transparent;}")
    scroll.viewport().setStyleSheet("background:transparent;")
    body = QWidget()
    body.setStyleSheet("background:transparent;")
    root = QVBoxLayout(body)
    root.setContentsMargins(T.S3, 0, T.S3, T.S3)
    root.setSpacing(T.S1)
    scroll.setWidget(body)
    return scroll, root


class SettingsPanel(SubTabHost):
    """Settings split by intent so nothing needs a long scroll:
    Display (how it looks) · Behavior (stealth, startup, telemetry) ·
    Keybinds."""

    def __init__(self, parent=None):
        self._checks = {}
        super().__init__([
            ("Display", self._build_display()),
            ("Behavior", self._build_behavior()),
            ("Keybinds", self._build_keybinds()),
        ], parent)
        # keep controls in sync when settings change elsewhere (e.g. hotkeys)
        settings.changed.connect(self._on_setting)

    # -- pages -------------------------------------------------------------
    def _build_display(self):
        page, root = _page()
        root.addWidget(_section("Appearance"))
        g = _Group(); root.addWidget(g)

        self.op_val = QLabel()
        self.op_val.setStyleSheet(T.label_qss("value"))
        g.add(_Row("Transparency", self.op_val))
        slider_wrap = QWidget()
        sw = QHBoxLayout(slider_wrap)
        sw.setContentsMargins(T.S3, 0, T.S3, T.S3)
        self.opacity = QSlider(Qt.Horizontal)
        self.opacity.setRange(110, 245)
        self.opacity.setValue(settings.get("card_opacity"))
        self.opacity.setStyleSheet(T.slider_qss())
        self.opacity.setCursor(Qt.PointingHandCursor)
        self.opacity.setAccessibleName("Transparency")
        self.opacity.valueChanged.connect(self._on_opacity)
        sw.addWidget(self.opacity)
        g._lay.addWidget(slider_wrap)
        self._on_opacity(self.opacity.value())

        self._toggle(g, "Filled graphs", "graph_fill")
        self._toggle(g, "Reduce motion", "reduce_motion",
                     hint="Snap instead of springs and fades")

        root.addWidget(_section("Graphs"))
        g = _Group(); root.addWidget(g)
        self._toggle(g, "CPU", "show_cpu")
        self._toggle(g, "Ping", "show_ping")
        self._toggle(g, "Network", "show_net")
        root.addStretch(1)
        return page

    def _build_behavior(self):
        page, root = _page()
        root.addWidget(_section("Stealth & window"))
        g = _Group(); root.addWidget(g)
        if IS_WINDOWS:
            self._toggle(g, "Hidden from screen capture", "capture_exclusion",
                         hint="Share-screen, OBS and PrintScreen see nothing")
        else:
            self._toggle(g, "Hidden from screen capture", "capture_exclusion",
                         hint=f"Unsupported on {runtime_note()}", enabled=False)
        self._toggle(g, "Click-through", "click_through",
                     hint="Mouse events pass to the window below")
        self._toggle(g, "Always on top", "always_on_top")

        # -- startup -------------------------------------------------------
        if IS_WINDOWS:
            from ..autostart import is_enabled, set_enabled
            root.addWidget(_section("Startup"))
            g = _Group(); root.addWidget(g)
            self._autostart = Switch()
            self._autostart.setAccessibleName("Start with Windows")
            self._autostart.setChecked(is_enabled())
            self._autostart.toggled.connect(lambda v: set_enabled(bool(v)))
            g.add(_Row("Start with Windows", self._autostart,
                       hint="Launch on login and resume",
                       clickable=self._autostart.toggle))

        root.addWidget(_section("Telemetry"))
        g = _Group(); root.addWidget(g)
        self.rate = QComboBox()
        self.rate.addItems(["0.5 s  fast", "1 s", "2 s  light"])
        self.rate.setCurrentIndex({500: 0, 1000: 1, 2000: 2}.get(
            settings.get("sample_ms"), 1))
        self.rate.setFixedWidth(120)
        self.rate.setStyleSheet(T.input_qss(height=22))
        self.rate.setCursor(Qt.PointingHandCursor)
        self.rate.currentIndexChanged.connect(
            lambda i: settings.set("sample_ms", (500, 1000, 2000)[i]))
        g.add(_Row("Sample rate", self.rate, hint="Telemetry refresh cadence"))
        self.ping = QLineEdit(settings.get("ping_target"))
        self.ping.setFixedWidth(150)
        self.ping.setStyleSheet(T.input_qss(height=22))
        self.ping.editingFinished.connect(
            lambda: settings.set("ping_target", self.ping.text().strip() or "8.8.8.8"))
        g.add(_Row("Ping target", self.ping, hint="Host for the latency graph"))
        root.addStretch(1)
        return page

    def _build_keybinds(self):
        from ..hotkeys import ACTIONS
        page, root = _page()
        root.addWidget(_section("Global hotkeys"))
        if IS_WINDOWS:
            note_text = "e.g. alt+y · ctrl+alt+left · f8 — blank turns a bind off"
        else:
            note_text = "Hyprland uses these combos when printing bind lines"
        note = QLabel(note_text)
        note.setStyleSheet(T.label_qss("caption") + "padding:0 2px 4px 2px;")
        root.addWidget(note)
        g = _Group(); root.addWidget(g)
        self._keyedits = {}
        for aid, label in ACTIONS:
            edit = QLineEdit((settings.get("hotkeys") or {}).get(aid, ""))
            edit.setFixedWidth(130)
            edit.setAlignment(Qt.AlignCenter)
            edit.setStyleSheet(T.input_qss(height=20))
            edit.setAccessibleName(label)
            edit.editingFinished.connect(lambda a=aid, e=edit: self._set_key(a, e.text()))
            self._keyedits[aid] = edit
            g.add(_Row(label, edit))

        root.addStretch(1)
        hint = QLabel("Changes apply instantly and save to _settings.json")
        hint.setStyleSheet(T.label_qss("caption") + "padding:8px 2px 0 2px;")
        root.addWidget(hint)
        return page

    def _set_key(self, action, combo):
        binds = dict(settings.get("hotkeys") or {})
        combo = combo.strip().lower()
        if binds.get(action, "") == combo:
            return
        binds[action] = combo
        settings.set("hotkeys", binds)   # app re-registers on this change

    # -- helpers -----------------------------------------------------------
    def _toggle(self, group, label, key, hint=None, enabled=True):
        sw = Switch()
        sw.setAccessibleName(label)
        sw.setChecked(bool(settings.get(key)))
        sw.setEnabled(bool(enabled))
        sw.toggled.connect(lambda v, k=key: settings.set(k, bool(v)))
        self._checks[key] = sw
        group.add(_Row(label, sw, hint=hint,
                       clickable=sw.toggle if enabled else None))

    def _on_setting(self, key, value):
        cb = self._checks.get(key)
        if cb is not None and cb.isChecked() != bool(value):
            cb.setChecked(bool(value))
        if key == "card_opacity" and self.opacity.value() != value:
            self.opacity.setValue(int(value))

    def _on_opacity(self, v):
        pct = round((v - 110) / (245 - 110) * 100)
        self.op_val.setText(f"{100 - pct}% clear")
        settings.set("card_opacity", v)

    def shutdown(self):
        pass
