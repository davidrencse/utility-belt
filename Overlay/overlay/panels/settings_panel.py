"""
Settings tab - toggles for UI, stealth behaviour and performance. Every
control writes to the shared `settings` store, which persists to disk and
emits `changed`; the window and the other panels listen and update live.
"""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QCheckBox, QSlider, QComboBox, QLineEdit,
                               QScrollArea, QFrame)

from .. import theme as T
from ..settings import settings


def _section(text):
    lbl = QLabel(text.upper())
    lbl.setStyleSheet(
        f"color:{T.hexs(T.TEXT_DIM)};font:700 7pt '{T.MONO}';letter-spacing:2px;"
        "margin-top:6px;")
    return lbl


def _row_label(text):
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color:{T.hexs(T.TEXT)};font:9pt '{T.UI}';")
    return lbl


class SettingsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._checks = {}
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background:transparent;")
        outer.addWidget(scroll)

        body = QWidget()
        body.setStyleSheet("background:transparent;")
        root = QVBoxLayout(body)
        root.setContentsMargins(14, 8, 14, 12)
        root.setSpacing(9)
        scroll.setWidget(body)

        # -- UI ------------------------------------------------------------
        root.addWidget(_section("Appearance"))

        op = QHBoxLayout()
        op.addWidget(_row_label("Transparency"))
        op.addStretch(1)
        self.op_val = QLabel()
        self.op_val.setStyleSheet(f"color:{T.hexs(T.TEXT_MUTED)};font:8pt '{T.MONO}';")
        op.addWidget(self.op_val)
        root.addLayout(op)
        self.opacity = QSlider(Qt.Horizontal)
        self.opacity.setRange(110, 245)
        self.opacity.setValue(settings.get("card_opacity"))
        self.opacity.setStyleSheet(self._slider_qss())
        self.opacity.valueChanged.connect(self._on_opacity)
        root.addWidget(self.opacity)
        self._on_opacity(self.opacity.value())

        self._toggle(root, "Filled graphs", "graph_fill")
        self._toggle(root, "Show CPU graph", "show_cpu")
        self._toggle(root, "Show ping graph", "show_ping")
        self._toggle(root, "Show network graph", "show_net")

        # -- stealth -------------------------------------------------------
        root.addWidget(_section("Stealth & window"))
        self._toggle(root, "Hidden from screen capture", "capture_exclusion")
        self._toggle(root, "Click-through (ignore mouse)", "click_through")
        self._toggle(root, "Always on top", "always_on_top")

        # -- performance ---------------------------------------------------
        root.addWidget(_section("Performance"))
        rate = QHBoxLayout()
        rate.addWidget(_row_label("Sample rate"))
        rate.addStretch(1)
        self.rate = QComboBox()
        self.rate.addItems(["0.5 s (fast)", "1 s", "2 s (light)"])
        self.rate.setCurrentIndex({500: 0, 1000: 1, 2000: 2}.get(
            settings.get("sample_ms"), 1))
        self.rate.setStyleSheet(T.input_qss(height=22))
        self.rate.currentIndexChanged.connect(
            lambda i: settings.set("sample_ms", (500, 1000, 2000)[i]))
        rate.addWidget(self.rate)
        root.addLayout(rate)

        # -- data ----------------------------------------------------------
        root.addWidget(_section("Data"))
        pt = QHBoxLayout()
        pt.addWidget(_row_label("Ping target"))
        pt.addStretch(1)
        self.ping = QLineEdit(settings.get("ping_target"))
        self.ping.setFixedWidth(150)
        self.ping.setStyleSheet(T.input_qss(height=22))
        self.ping.editingFinished.connect(
            lambda: settings.set("ping_target", self.ping.text().strip() or "8.8.8.8"))
        pt.addWidget(self.ping)
        root.addLayout(pt)

        vt = QHBoxLayout()
        vt.addWidget(_row_label("VirusTotal API key"))
        vt.addStretch(1)
        self.vt = QLineEdit(settings.get("vt_api_key"))
        self.vt.setEchoMode(QLineEdit.Password)
        self.vt.setPlaceholderText("optional")
        self.vt.setFixedWidth(150)
        self.vt.setStyleSheet(T.input_qss(height=22))
        self.vt.editingFinished.connect(
            lambda: settings.set("vt_api_key", self.vt.text().strip()))
        vt.addWidget(self.vt)
        root.addLayout(vt)

        # -- keybinds ------------------------------------------------------
        from ..hotkeys import ACTIONS
        root.addWidget(_section("Keybinds"))
        note = QLabel("e.g. alt+y · ctrl+alt+left · f8   (blank = off)")
        note.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:7pt '{T.MONO}';")
        root.addWidget(note)
        self._keyedits = {}
        for aid, label in ACTIONS:
            row = QHBoxLayout()
            row.addWidget(_row_label(label))
            row.addStretch(1)
            edit = QLineEdit((settings.get("hotkeys") or {}).get(aid, ""))
            edit.setFixedWidth(130)
            edit.setStyleSheet(T.input_qss(height=22))
            edit.editingFinished.connect(lambda a=aid, e=edit: self._set_key(a, e.text()))
            self._keyedits[aid] = edit
            row.addWidget(edit)
            root.addLayout(row)

        root.addStretch(1)
        hint = QLabel("Changes apply instantly and are saved to _settings.json")
        hint.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:7pt '{T.MONO}';")
        root.addWidget(hint)

        # keep controls in sync when settings change elsewhere (e.g. hotkeys)
        settings.changed.connect(self._on_setting)

    def _set_key(self, action, combo):
        binds = dict(settings.get("hotkeys") or {})
        combo = combo.strip().lower()
        if binds.get(action, "") == combo:
            return
        binds[action] = combo
        settings.set("hotkeys", binds)   # app re-registers on this change

    # -- helpers -----------------------------------------------------------
    def _toggle(self, layout, label, key):
        row = QHBoxLayout()
        row.addWidget(_row_label(label))
        row.addStretch(1)
        cb = QCheckBox()
        cb.setChecked(bool(settings.get(key)))
        cb.setStyleSheet(T.checkbox_qss())
        cb.toggled.connect(lambda v, k=key: settings.set(k, bool(v)))
        self._checks[key] = cb
        row.addWidget(cb)
        layout.addLayout(row)

    def _on_setting(self, key, value):
        cb = self._checks.get(key)
        if cb is not None and cb.isChecked() != bool(value):
            cb.setChecked(bool(value))
        if key == "card_opacity" and self.opacity.value() != value:
            self.opacity.setValue(int(value))

    def _on_opacity(self, v):
        pct = round((v - 110) / (245 - 110) * 100)
        self.op_val.setText(f"{100 - pct}% see-through")
        settings.set("card_opacity", v)

    def _slider_qss(self):
        return (
            "QSlider::groove:horizontal{height:4px;background:"
            f"{T.hexs(T.SURFACE_2)};border-radius:2px;}}"
            "QSlider::sub-page:horizontal{background:"
            f"{T.hexs(T.TEXT_MUTED)};border-radius:2px;}}"
            "QSlider::handle:horizontal{width:14px;height:14px;margin:-6px 0;"
            f"border-radius:7px;background:{T.hexs(T.TEXT)};}}"
            "QSlider::handle:horizontal:hover{background:#ffffff;}")

    def shutdown(self):
        pass
