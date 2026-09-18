"""
Clipboard history panel - lists what you've copied (newest first). Click an
entry to copy it back to the clipboard, ready to paste; × removes one, Clear
empties the list. Backed by the in-memory `clipboard.history` singleton.
"""
import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QPushButton, QScrollArea, QFrame)

from .. import theme as T
from ..clipboard import history


def _ago(ts):
    d = max(0, int(time.time() - ts))
    if d < 5:
        return "now"
    if d < 60:
        return f"{d}s"
    if d < 3600:
        return f"{d // 60}m"
    if d < 86400:
        return f"{d // 3600}h"
    return f"{d // 86400}d"


class _Row(QFrame):
    def __init__(self, text, ts, panel):
        super().__init__()
        self._text = text
        self._panel = panel
        self.setCursor(Qt.PointingHandCursor)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setFixedHeight(24)
        self._restyle(False)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 0, 5, 0)
        lay.setSpacing(6)

        preview = text.strip().replace("\n", " ⏎ ").replace("\t", " ")
        if len(preview) > 120:
            preview = preview[:120] + "…"
        self._lbl = QLabel(preview)
        self._lbl.setStyleSheet(f"color:{T.hexs(T.TEXT)};font:8pt '{T.MONO}';"
                                "background:transparent;border:none;")
        lay.addWidget(self._lbl, 1)

        meta = QLabel(_ago(ts))
        meta.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:7pt '{T.MONO}';"
                           "background:transparent;border:none;")
        lay.addWidget(meta)

        rm = QPushButton("✕")
        rm.setFixedSize(16, 16)
        rm.setCursor(Qt.PointingHandCursor)
        rm.setToolTip("Remove")
        rm.setStyleSheet(
            f"QPushButton{{background:transparent;color:{T.hexs(T.TEXT_DIM)};"
            f"border:none;font:8pt '{T.UI}';}}"
            f"QPushButton:hover{{color:{T.hexs(T.DANGER)};}}")
        rm.clicked.connect(lambda: history.remove(self._text))
        lay.addWidget(rm)

    def _restyle(self, hover):
        bg = T.rgba(T.SURFACE_2) if hover else T.rgba(T.SURFACE)
        self.setStyleSheet(f"background:{bg};border:1px solid {T.hexs(T.BORDER)};"
                           f"border-radius:{T.R_CHIP}px;")

    def enterEvent(self, _e):
        self._restyle(True)

    def leaveEvent(self, _e):
        self._restyle(False)

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._panel._use(self._text)


class ClipboardPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 7, 10, 8)
        root.setSpacing(6)

        head = QHBoxLayout()
        title = QLabel("CLIPBOARD HISTORY")
        title.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:700 8pt '{T.MONO}';"
                            "letter-spacing:2px;")
        head.addWidget(title)
        head.addStretch(1)
        self.status = QLabel("")
        self.status.setStyleSheet(f"color:{T.hexs(T.TEXT_MUTED)};font:8pt '{T.MONO}';")
        head.addWidget(self.status)
        clear = QPushButton("Clear")
        clear.setCursor(Qt.PointingHandCursor)
        clear.setStyleSheet(T.ghost_btn_qss())
        clear.clicked.connect(history.clear)
        head.addWidget(clear)
        root.addLayout(head)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background:transparent;")
        root.addWidget(scroll, 1)
        body = QWidget()
        body.setStyleSheet("background:transparent;")
        self._list = QVBoxLayout(body)
        self._list.setContentsMargins(0, 0, 4, 0)
        self._list.setSpacing(3)
        self._list.addStretch(1)
        scroll.setWidget(body)

        # Rebuilding creates a widget row per entry; history changes on every copy
        # anywhere in Windows, so only rebuild while visible (or on next show).
        self._dirty = True
        history.changed.connect(self._on_history_changed)

    def _on_history_changed(self):
        if self.isVisible():
            self._rebuild()
        else:
            self._dirty = True

    def showEvent(self, e):
        super().showEvent(e)
        if self._dirty:
            self._rebuild()

    def _use(self, text):
        history.copy(text)
        self.status.setText("copied ✓")
        QTimer.singleShot(1200, lambda: self.status.setText(""))

    def _rebuild(self):
        self._dirty = False
        # clear existing rows (keep the trailing stretch); detach immediately
        # so a pending deleteLater can't leave a ghost row visible
        while self._list.count() > 1:
            item = self._list.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)
                w.deleteLater()
        items = history.items()
        if not items:
            empty = QLabel("Nothing copied yet — copy anything and it appears here.")
            empty.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:9pt '{T.UI}';")
            empty.setAlignment(Qt.AlignCenter)
            self._list.insertWidget(0, empty)
            return
        for i, it in enumerate(items):
            self._list.insertWidget(i, _Row(it["text"], it["ts"], self))
