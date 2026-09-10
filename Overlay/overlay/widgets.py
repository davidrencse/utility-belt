"""
Custom HUD widgets drawn with QPainter (no pyqtgraph/numpy) - a rolling
Sparkline and a circular Gauge, both wired to theme.py.

Design intent: minimal. No boxed containers or heavy fills - each graph is a
label, a value, a thin line and a single hairline baseline, separated by
whitespace. Monochrome throughout; the gauge encodes load by brightness.
"""
from collections import deque

from PySide6.QtCore import Qt, QRectF, QPointF, QVariantAnimation, QEasingCurve
from PySide6.QtGui import (QColor, QPainter, QPainterPath, QPen, QFont,
                           QLinearGradient)
from PySide6.QtWidgets import QWidget

from . import theme as T

# back-compat re-exports
ACCENT = T.ACCENT
ACCENT2 = T.G_CPU
WARN = T.WARN
INK = T.TEXT
MUTE = T.TEXT_MUTED


def _ramp(pct):
    """Monochrome severity ramp - brightness rises with load."""
    if pct >= 90:
        return T.DANGER
    if pct >= 72:
        return T.WARN
    return T.POSITIVE


class Sparkline(QWidget):
    """Rolling line graph: a small uppercase label (left), current value
    (right), a thin line and one hairline baseline. push(value) adds a point;
    autoscales to [0, max(peak, floor)]."""

    def __init__(self, capacity=160, color=None, floor=1.0, unit="",
                 fill=True, parent=None):
        super().__init__(parent)
        self._data = deque(maxlen=capacity)
        self._color = QColor(color) if color else QColor(T.ACCENT)
        self._floor = floor
        self._unit = unit
        self._fill = fill
        self._label = ""
        self._value = ""
        self.setMinimumHeight(46)

    def set_fill(self, on):
        self._fill = bool(on)
        self.update()

    def push(self, value):
        try:
            self._data.append(float(value))
        except (TypeError, ValueError):
            self._data.append(0.0)
        self.update()

    def set_label(self, text, value=""):
        self._label = text
        self._value = value
        self.update()

    def latest(self):
        return self._data[-1] if self._data else 0.0

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        r = self.rect()

        # header row: label left, value right (font scales with height = zoom)
        hpt = max(7, min(15, int(r.height() * 0.16)))
        p.setFont(QFont(T.MONO, hpt, QFont.Bold))
        p.setPen(T.TEXT_DIM)
        p.drawText(r.adjusted(1, 1, -1, 0), Qt.AlignLeft | Qt.AlignTop,
                   self._label.upper())
        if self._value:
            p.setPen(T.TEXT)
            p.drawText(r.adjusted(1, 1, -1, 0), Qt.AlignRight | Qt.AlignTop,
                       self._value)

        top = hpt + 9
        plot = QRectF(r.left() + 1, r.top() + top, r.width() - 2, r.height() - top - 4)
        # hairline baseline
        p.setPen(QPen(QColor(255, 255, 255, 20), 1))
        p.drawLine(QPointF(plot.left(), plot.bottom()),
                   QPointF(plot.right(), plot.bottom()))

        if len(self._data) >= 2:
            peak = max(max(self._data), self._floor)
            step = plot.width() / (self._data.maxlen - 1)
            x0 = plot.right() - (len(self._data) - 1) * step
            pts = []
            for i, v in enumerate(self._data):
                x = x0 + i * step
                y = plot.bottom() - (v / peak) * plot.height()
                pts.append((x, y))

            path = QPainterPath()
            path.moveTo(*pts[0])
            for x, y in pts[1:]:
                path.lineTo(x, y)

            if self._fill:
                grad = QLinearGradient(0, plot.top(), 0, plot.bottom())
                c = QColor(self._color); c.setAlpha(34)
                grad.setColorAt(0.0, c)
                c2 = QColor(self._color); c2.setAlpha(0)
                grad.setColorAt(1.0, c2)
                fillp = QPainterPath(path)
                fillp.lineTo(pts[-1][0], plot.bottom())
                fillp.lineTo(pts[0][0], plot.bottom())
                fillp.closeSubpath()
                p.fillPath(fillp, grad)

            pen = QPen(self._color, 1.4)
            pen.setJoinStyle(Qt.RoundJoin)
            pen.setCapStyle(Qt.RoundCap)
            p.setPen(pen)
            p.drawPath(path)

            # small leading dot
            lx, ly = pts[-1]
            p.setPen(Qt.NoPen)
            p.setBrush(self._color)
            p.drawEllipse(QRectF(lx - 1.8, ly - 1.8, 3.6, 3.6))
        p.end()


class Gauge(QWidget):
    """Minimal circular gauge 0-100%, easing toward new values: a thin track,
    a single progress arc (brightness = load), a numeric readout, a sub-value
    and a title. No glow."""

    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self._value = 0.0
        self._shown = 0.0
        self._title = title
        self._sub = ""
        self.setMinimumSize(88, 96)
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(460)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self._anim.valueChanged.connect(self._on_anim)

    def set_value(self, pct, sub=""):
        self._value = max(0.0, min(100.0, float(pct or 0)))
        self._sub = sub
        self._anim.stop()
        self._anim.setStartValue(float(self._shown))
        self._anim.setEndValue(float(self._value))
        self._anim.start()

    def _on_anim(self, v):
        self._shown = float(v)
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        side = min(self.width(), self.height() - 12)
        # fonts + stroke scale with the gauge size, so resizing zooms it
        aw = max(4.0, side * 0.055)
        num_pt = max(9, int(side * 0.16))
        small_pt = max(6, int(side * 0.085))
        off = side * 0.075
        rect = QRectF((self.width() - side) / 2 + aw, aw - 2,
                      side - 2 * aw, side - 2 * aw)
        col = _ramp(self._shown)
        span = int(-270 * 16 * (self._shown / 100.0))

        # track
        pen_bg = QPen(QColor(255, 255, 255, 22), aw)
        pen_bg.setCapStyle(Qt.RoundCap)
        p.setPen(pen_bg)
        p.drawArc(rect, 225 * 16, -270 * 16)

        # progress
        pen_fg = QPen(col, aw)
        pen_fg.setCapStyle(Qt.RoundCap)
        p.setPen(pen_fg)
        p.drawArc(rect, 225 * 16, span)

        # numeric (nudged up so the sub-value fits beneath)
        fnum = QFont(T.UI, num_pt); fnum.setBold(True)
        p.setPen(T.TEXT)
        p.setFont(fnum)
        p.drawText(rect.adjusted(0, -off, 0, -off), Qt.AlignCenter, f"{self._shown:.0f}%")

        if self._sub:
            p.setPen(T.TEXT_DIM)
            p.setFont(QFont(T.MONO, small_pt))
            p.drawText(rect.adjusted(0, off * 2, 0, off * 2),
                       Qt.AlignHCenter | Qt.AlignVCenter, self._sub)

        # title beneath the gauge
        ftitle = QFont(T.MONO, small_pt, QFont.Bold)
        ftitle.setLetterSpacing(QFont.AbsoluteSpacing, 1.5)
        p.setPen(T.TEXT_MUTED)
        p.setFont(ftitle)
        p.drawText(self.rect().adjusted(0, self.height() - 12, 0, 0),
                   Qt.AlignHCenter | Qt.AlignTop, self._title)
        p.end()
