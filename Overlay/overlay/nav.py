"""
NavStrip - a row of text items with a shared-layout indicator, the Qt
equivalent of Framer Motion's `<motion.div layoutId="pill" />`: one
indicator that springs between items (keeping velocity when you sweep the
cursor across them) instead of each item toggling its own background.

Used by the top banner (hover-follow pill) and SubTabHost (active pill).
Items paint their own label so text brightness can tween rather than snap.
"""
from PySide6.QtCore import Qt, QRectF, Signal, QSize
from PySide6.QtGui import QPainter, QColor, QFont, QFontMetrics, QPen
from PySide6.QtWidgets import QWidget, QHBoxLayout

from . import motion
from . import theme as T


class NavItem(QWidget):
    entered = Signal(int)
    left = Signal(int)
    clicked = Signal(int)

    def __init__(self, text, index, font, pad_x=10, height=22, parent=None):
        super().__init__(parent)
        self._text = text
        self._i = index
        self._font = font
        self._pad = pad_x
        self._h = height
        self._on = False
        self._hover = False
        self._badge = False
        self._emph = motion.Spring(0.0, T.SPRING_SNAPPY, owner=self,
                                   on_change=lambda _v: self.update())
        self.setMouseTracking(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.TabFocus)
        self.setAccessibleName(text)
        self.setAttribute(Qt.WA_Hover, True)
        self.setAcceptDrops(True)

    def sizeHint(self):
        fm = QFontMetrics(self._font)
        return QSize(fm.horizontalAdvance(self._text) + self._pad * 2
                     + (8 if self._badge else 0), self._h)

    def minimumSizeHint(self):
        return self.sizeHint()

    def set_on(self, on):
        self._on = bool(on)
        self._retarget()

    def set_badge(self, on):
        """Small dot after the label (e.g. a pinned panel)."""
        if self._badge != bool(on):
            self._badge = bool(on)
            self.updateGeometry()
            self.update()

    def _retarget(self):
        self._emph.set(1.0 if self._on else (0.55 if self._hover else 0.0))

    def enterEvent(self, _e):
        self._hover = True
        self._retarget()
        self.entered.emit(self._i)

    def leaveEvent(self, _e):
        self._hover = False
        self._retarget()
        self.left.emit(self._i)

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self.clicked.emit(self._i)

    # dragging a file over a chip opens its menu, so it can be dropped inside
    # (enter/leave events are not delivered while a drag is in progress)
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self.enterEvent(e)

    def dragLeaveEvent(self, e):
        self.leaveEvent(e)

    def dropEvent(self, e):
        e.ignore()

    def keyPressEvent(self, e):
        if e.key() in (Qt.Key_Return, Qt.Key_Enter, Qt.Key_Space):
            self.clicked.emit(self._i)
        else:
            super().keyPressEvent(e)

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        p.setFont(self._font)
        p.setPen(motion.blend(T.TEXT_DIM, T.TEXT, self._emph.value))
        r = self.rect()
        text_r = r.adjusted(0, 0, -8, 0) if self._badge else r
        p.drawText(text_r, Qt.AlignCenter, self._text)
        if self._badge:
            fm = QFontMetrics(self._font)
            x = (text_r.width() + fm.horizontalAdvance(self._text)) / 2 + 4
            p.setPen(Qt.NoPen)
            p.setBrush(T.TEXT)
            p.drawEllipse(QRectF(x, r.height() / 2 - 2, 4, 4))
        if self.hasFocus():
            p.setPen(QPen(T.TEXT_MUTED, 1))
            p.setBrush(Qt.NoBrush)
            p.drawRoundedRect(QRectF(r).adjusted(1, 1, -1, -1), 6, 6)
        p.end()


class NavStrip(QWidget):
    """items: labels. style: 'pill' (filled rounded indicator) or
    'underline'. The indicator's target is the hovered item when
    follow_hover is on, otherwise the active item."""

    hovered = Signal(int)
    unhovered = Signal(int)
    activated = Signal(int)

    def __init__(self, labels, font=None, style="pill", follow_hover=False,
                 height=22, pad_x=10, spacing=2, dividers=(), parent=None):
        """dividers: item indices followed by a hairline group separator."""
        super().__init__(parent)
        self._style = style
        self._follow = follow_hover
        self._active = None
        self._hover = None
        self._font = font or QFont(T.UI, 8, QFont.DemiBold)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(spacing)
        self.items = []
        for i, text in enumerate(labels):
            it = NavItem(text, i, self._font, pad_x=pad_x, height=height)
            it.entered.connect(self._on_enter)
            it.left.connect(self._on_leave)
            it.clicked.connect(self.activated.emit)
            lay.addWidget(it)
            self.items.append(it)
            if i in dividers and i < len(labels) - 1:
                lay.addSpacing(T.S1)
                sep = QWidget()
                sep.setFixedSize(1, max(8, height // 2))
                sep.setStyleSheet(f"background:{T.hexs(T.BORDER)};")
                lay.addWidget(sep, 0, Qt.AlignVCenter)
                lay.addSpacing(T.S1)
        # indicator rect (x, y, w, h) + opacity, both springs
        self._rect = motion.Spring((0.0, 0.0, 0.0, 0.0), T.SPRING_SNAPPY,
                                   owner=self, rest=0.2,
                                   on_change=lambda _v: self.update())
        self._alpha = motion.Spring(0.0, T.SPRING_SNAPPY, owner=self,
                                    on_change=lambda _v: self.update())
        self._placed = False

    def item(self, i):
        return self.items[i]

    # -- state -------------------------------------------------------------
    def set_active(self, i):
        self._active = i
        for k, it in enumerate(self.items):
            it.set_on(k == i)
        self._retarget()

    def set_hover(self, i):
        self._hover = i
        self._retarget()

    def _on_enter(self, i):
        self._hover = i
        self._retarget()
        self.hovered.emit(i)

    def _on_leave(self, i):
        if self._hover == i:
            self._hover = None
        self._retarget()
        self.unhovered.emit(i)

    def _target_index(self):
        if self._follow and self._hover is not None:
            return self._hover
        return self._active

    def _geom_for(self, i):
        g = self.items[i].geometry()
        if self._style == "underline":
            return (float(g.x() + 8), float(g.bottom() - 1), float(g.width() - 16), 2.0)
        return (float(g.x()), float(g.y()), float(g.width()), float(g.height()))

    def _retarget(self):
        idx = self._target_index()
        if idx is None:
            self._alpha.set(0.0)
            return
        geom = self._geom_for(idx)
        if not self._placed or self._alpha.value < 0.02:
            # appear in place (Framer: layoutId has no previous box to morph from)
            self._rect.jump(geom)
            self._placed = True
        else:
            self._rect.set(geom)
        self._alpha.set(1.0)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        idx = self._target_index()
        if idx is not None:
            self._rect.jump(self._geom_for(idx))

    def showEvent(self, e):
        super().showEvent(e)
        idx = self._target_index()
        if idx is not None:
            self._rect.jump(self._geom_for(idx))

    # -- paint -------------------------------------------------------------
    def paintEvent(self, _e):
        a = self._alpha.value
        if a <= 0.01:
            return
        x, y, w, h = self._rect.value
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        p.setPen(Qt.NoPen)
        if self._style == "underline":
            c = QColor(T.TEXT); c.setAlphaF(a)
            p.setBrush(c)
            p.drawRoundedRect(QRectF(x, y, w, h), 1, 1)
        else:
            fill = QColor(255, 255, 255, round(22 * a))
            p.setBrush(fill)
            p.drawRoundedRect(QRectF(x, y, w, h), h / 2, h / 2)
            p.setPen(QPen(QColor(255, 255, 255, round(18 * a)), 1))
            p.setBrush(Qt.NoBrush)
            p.drawRoundedRect(QRectF(x + 0.5, y + 0.5, w - 1, h - 1), h / 2, h / 2)
        p.end()
