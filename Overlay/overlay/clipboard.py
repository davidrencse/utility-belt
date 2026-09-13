"""
Clipboard history - records everything copied while the overlay runs so you
can paste an earlier clip (Win+V style). Kept in memory for the session only;
it is deliberately NOT written to disk, so copied passwords/tokens never land
in a file.

`history` is the module singleton; Banner.start()s it at launch so it captures
from the moment the app opens, whether or not the Clipboard panel is open.
"""
import time

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication

MAX_ITEMS = 200
MAX_LEN = 20000        # cap stored text so a huge copy can't bloat memory


class ClipboardHistory(QObject):
    changed = Signal()

    def __init__(self):
        super().__init__()
        self._items = []          # newest first: [{"text": str, "ts": float}]
        self._started = False

    def start(self):
        if self._started:
            return
        cb = QApplication.clipboard()
        if cb is None:
            return
        cb.dataChanged.connect(self._on_change)
        self._started = True
        self._capture(cb)         # seed with whatever is on the clipboard now

    def _on_change(self):
        self._capture(QApplication.clipboard())

    def _capture(self, cb):
        try:
            md = cb.mimeData()
        except Exception:
            return
        if md is None or not md.hasText():
            return                # images / files aren't tracked
        text = md.text()
        if not text or not text.strip():
            return
        if len(text) > MAX_LEN:
            text = text[:MAX_LEN]
        # move an identical earlier clip to the front instead of duplicating
        self._items = [it for it in self._items if it["text"] != text]
        self._items.insert(0, {"text": text, "ts": time.time()})
        del self._items[MAX_ITEMS:]
        self.changed.emit()

    def items(self):
        return list(self._items)

    def copy(self, text):
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(text)      # ready to paste; dedupe moves it to the front

    def remove(self, text):
        before = len(self._items)
        self._items = [it for it in self._items if it["text"] != text]
        if len(self._items) != before:
            self.changed.emit()

    def clear(self):
        if self._items:
            self._items = []
            self.changed.emit()


history = ClipboardHistory()
