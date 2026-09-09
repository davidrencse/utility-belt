"""
SubTabHost - a reusable inner tab strip + stacked content area, shared by the
SYSTEM and TOOLS tabs so the pattern (underline sub-nav, lazy content, child
shutdown) lives in exactly one place.

items are (label, provider) pairs. `provider` is either a ready QWidget
(built eagerly) or a zero-arg callable (built lazily on first visit - used for
panels whose construction is expensive, like the specs query).
"""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                               QStackedWidget, QPushButton)

from . import theme as T


class _SubButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet(
            f"QPushButton{{background:transparent;color:{T.hexs(T.TEXT_DIM)};"
            f"border:none;border-bottom:2px solid transparent;padding:3px 12px;"
            f"font:700 8pt '{T.UI}';}}"
            f"QPushButton:checked{{color:{T.hexs(T.TEXT)};"
            f"border-bottom:2px solid {T.hexs(T.TEXT)};}}"
            f"QPushButton:hover:!checked{{color:{T.hexs(T.TEXT_MUTED)};}}")


class SubTabHost(QWidget):
    def __init__(self, items, parent=None):
        super().__init__(parent)
        self._providers = [p for _, p in items]
        self._built = [None] * len(items)   # resolved widgets, filled lazily

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 4, 0, 0)
        root.setSpacing(4)

        nav = QHBoxLayout()
        nav.setContentsMargins(10, 0, 10, 0)
        nav.setSpacing(2)
        self._btns = []
        for i, (label, _) in enumerate(items):
            b = _SubButton(label)
            b.clicked.connect(lambda _=False, idx=i: self._select(idx))
            nav.addWidget(b)
            self._btns.append(b)
        nav.addStretch(1)
        root.addLayout(nav)

        self.stack = QStackedWidget()
        # placeholders keep stack indices aligned with providers
        for _ in items:
            self.stack.addWidget(QWidget())
        root.addWidget(self.stack, 1)

        self._select(0)

    def _resolve(self, idx):
        if self._built[idx] is None:
            provider = self._providers[idx]
            widget = provider() if callable(provider) else provider
            placeholder = self.stack.widget(idx)
            self.stack.insertWidget(idx, widget)
            self.stack.removeWidget(placeholder)
            placeholder.deleteLater()
            self._built[idx] = widget
        return self._built[idx]

    def _select(self, idx):
        self._resolve(idx)
        self.stack.setCurrentIndex(idx)
        for i, b in enumerate(self._btns):
            b.setChecked(i == idx)

    def built_widgets(self):
        return [w for w in self._built if w is not None]

    def shutdown(self):
        for w in self.built_widgets():
            if hasattr(w, "shutdown"):
                try:
                    w.shutdown()
                except Exception:
                    pass
