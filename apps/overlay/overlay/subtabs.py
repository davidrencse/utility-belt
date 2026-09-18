"""
SubTabHost - a reusable inner tab strip + stacked content area, shared by the
SYSTEM / NETWORK / INTEL / SETTINGS tabs so the pattern (sliding-pill sub-nav, lazy content,
child shutdown) lives in exactly one place.

items are (label, provider) pairs. `provider` is either a ready QWidget
(built eagerly) or a zero-arg callable (built lazily on first visit - used for
panels whose construction is expensive, like the specs query).

Motion: the active pill springs between labels (NavStrip), and the incoming
page slides in from the side you navigated toward while it fades up.
"""
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget

from . import motion
from . import theme as T
from .nav import NavStrip


class SubTabHost(QWidget):
    def __init__(self, items, parent=None):
        super().__init__(parent)
        self._providers = [p for _, p in items]
        self._built = [None] * len(items)   # resolved widgets, filled lazily
        self._current = None

        root = QVBoxLayout(self)
        root.setContentsMargins(0, T.S2, 0, 0)
        root.setSpacing(T.S1)

        nav = QHBoxLayout()
        nav.setContentsMargins(T.S3, 0, T.S3, 0)
        self.nav = NavStrip([label for label, _ in items],
                            font=QFont(T.UI, 8, QFont.DemiBold),
                            style="pill", height=22, pad_x=11, spacing=1)
        self.nav.activated.connect(self._select)
        nav.addWidget(self.nav)
        nav.addStretch(1)
        root.addLayout(nav)

        self.stack = QStackedWidget()
        # placeholders keep stack indices aligned with providers
        for _ in items:
            self.stack.addWidget(QWidget())
        root.addWidget(self.stack, 1)
        self.nav.set_active(0)
        # the first page is built on first show, so a host that is never opened
        # never constructs (or starts the workers of) any of its pages

    def showEvent(self, e):
        super().showEvent(e)
        if self._current is None:
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
        if idx == self._current:
            return
        widget = self._resolve(idx)
        prev = self._current
        self._current = idx
        self.stack.setCurrentIndex(idx)
        self.nav.set_active(idx)
        if prev is not None:
            direction = 1 if idx > prev else -1
            motion.reveal(widget, dx=14 * direction, dy=0)

    def built_widgets(self):
        return [w for w in self._built if w is not None]

    def shutdown(self):
        for w in self.built_widgets():
            if hasattr(w, "shutdown"):
                try:
                    w.shutdown()
                except Exception:
                    pass
