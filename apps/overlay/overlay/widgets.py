"""
Custom HUD widgets drawn with QPainter (no pyqtgraph/numpy) - a rolling
Sparkline, a circular Gauge and an animated Switch, all wired to theme.py
and motion.py.

Design intent: minimal. No boxed containers or heavy fills - each graph is a
label, a value, a thin line and a single hairline baseline, separated by
whitespace. Monochrome throughout; the gauge encodes load by brightness.

Motion: values never jump. Gauges ride a spring toward each new reading,
sparklines glide one sample-width left instead of stepping, and the switch
knob springs across its track.
"""
from collections import deque
from functools import lru_cache

from PySide6.QtCore import Qt, QRectF, QPointF, QSize
from PySide6.QtGui import (QColor, QPainter, QPainterPath, QPen, QFont, QFontMetricsF,
                           QLinearGradient)
from PySide6.QtWidgets import QWidget, QAbstractButton

from . import motion
from . import theme as T

# back-compat re-exports
ACCENT = T.ACCENT
ACCENT2 = T.G_CPU
WARN = T.WARN
INK = T.TEXT
MUTE = T.TEXT_MUTED


def _ramp(pct):
    """Monochrome severity ramp - brightness rises with load, blended so the
    arc brightens continuously as the spring carries it past a threshold."""
    if pct >= 90:
        return T.DANGER
    if pct >= 72:
        return motion.blend(T.WARN, T.DANGER, (pct - 72) / 18)
    return motion.blend(T.POSITIVE, T.WARN, max(0.0, (pct - 55) / 17))



# Paint handlers run every animation frame; building QFont/QFontMetricsF there
# each time is avoidable work, so share instances per (family, size, weight).
@lru_cache(maxsize=64)
def _font(family, pt, weight=QFont.Normal, spacing=None):
    f = QFont(family, pt, weight)
    if spacing is not None:
        f.setLetterSpacing(QFont.AbsoluteSpacing, spacing)
    return f


@lru_cache(maxsize=64)
def _metrics(family, pt, weight=QFont.Normal):
    return QFontMetricsF(_font(family, pt, weight))

class Sparkline(QWidget):
    """Rolling line graph: a small uppercase label (left), current value
    (right), a thin line and one hairline baseline. push(value) adds a point;
    autoscales to [0, max(peak, floor)] with the scale itself on a spring so
    a spike doesn't make the whole line lurch."""

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
        self._shift = motion.Spring(0.0, T.SPRING_SOFT, owner=self,
                                    on_change=lambda _v: self.update())
        self._peak = motion.Spring(float(floor), T.SPRING_GENTLE, owner=self,
                                   on_change=lambda _v: self.update())
        self.setMinimumHeight(46)

    def set_fill(self, on):
        self._fill = bool(on)
        self.update()

    def push(self, value):
        try:
            self._data.append(float(value))
        except (TypeError, ValueError):
            self._data.append(0.0)
        # glide: start one step to the right, spring back to rest
        if len(self._data) > 2 and self.isVisible():
            self._shift.jump(1.0)
            self._shift.set(0.0)
        self._peak.set(max(max(self._data), self._floor))
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

        # header row: eyebrow label left, value right. Sizes step gently with
        # height (zoom) but stay inside the type scale.
        big = r.height() > 90
        lab = _font(T.MONO, 8 if big else 7, QFont.Bold, 1.5)
        val = _font(T.MONO, 11 if big else 9, QFont.DemiBold)
        p.setFont(lab)
        p.setPen(T.TEXT_DIM)
        head_h = 18 if big else 15
        p.drawText(QRectF(r.left() + 1, r.top(), r.width() / 2, head_h),
                   Qt.AlignLeft | Qt.AlignVCenter, self._label.upper())
        if self._value:
            p.setFont(val)
            p.setPen(T.TEXT)
            p.drawText(QRectF(r.left(), r.top(), r.width() - 1, head_h),
                       Qt.AlignRight | Qt.AlignVCenter, self._value)

        top = head_h + 6
        plot = QRectF(r.left() + 1, r.top() + top, r.width() - 2, r.height() - top - 3)
        # hairline baseline
        p.setPen(QPen(T.HAIRLINE, 1))
        p.drawLine(QPointF(plot.left(), plot.bottom()),
                   QPointF(plot.right(), plot.bottom()))

        if len(self._data) >= 2 and plot.height() > 2:
            peak = max(self._peak.value, 1e-6)
            step = plot.width() / (self._data.maxlen - 1)
            x0 = plot.right() - (len(self._data) - 1) * step + self._shift.value * step
            pts = []
            for i, v in enumerate(self._data):
                x = x0 + i * step
                y = plot.bottom() - min(1.0, v / peak) * plot.height()
                pts.append((x, y))

            p.save()
            p.setClipRect(plot.adjusted(0, -4, 0, 1))
            path = QPainterPath()
            path.moveTo(*pts[0])
            for x, y in pts[1:]:
                path.lineTo(x, y)

            if self._fill:
                grad = QLinearGradient(0, plot.top(), 0, plot.bottom())
                c = QColor(self._color); c.setAlpha(40)
                grad.setColorAt(0.0, c)
                c2 = QColor(self._color); c2.setAlpha(0)
                grad.setColorAt(1.0, c2)
                fillp = QPainterPath(path)
                fillp.lineTo(pts[-1][0], plot.bottom())
                fillp.lineTo(pts[0][0], plot.bottom())
                fillp.closeSubpath()
                p.fillPath(fillp, grad)

            pen = QPen(self._color, 1.5)
            pen.setJoinStyle(Qt.RoundJoin)
            pen.setCapStyle(Qt.RoundCap)
            p.setPen(pen)
            p.drawPath(path)
            p.restore()

            # leading dot with a faint halo
            lx, ly = pts[-1]
            p.setPen(Qt.NoPen)
            halo = QColor(self._color); halo.setAlpha(46)
            p.setBrush(halo)
            p.drawEllipse(QRectF(lx - 4.5, ly - 4.5, 9, 9))
            p.setBrush(self._color)
            p.drawEllipse(QRectF(lx - 2, ly - 2, 4, 4))
        p.end()


class Gauge(QWidget):
    """Minimal circular gauge 0-100% on a spring: a thin track, a single
    progress arc (brightness = load), a numeric readout, a sub-value and a
    title. No glow."""

    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self._value = 0.0
        self._title = title
        self._sub = ""
        self.setMinimumSize(88, 100)
        self._spring = motion.Spring(0.0, T.SPRING_GENTLE, owner=self, rest=0.05,
                                     on_change=lambda _v: self.update())

    @property
    def _shown(self):
        return max(0.0, min(100.0, self._spring.value))

    def set_value(self, pct, sub=""):
        self._value = max(0.0, min(100.0, float(pct or 0)))
        self._sub = sub
        self._spring.set(self._value)
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        title_h = 16
        side = min(self.width(), self.height() - title_h)
        # fonts + stroke scale with the gauge size, so resizing zooms it
        aw = max(4.0, side * 0.06)
        num_pt = max(10, int(side * 0.17))
        small_pt = max(7, int(side * 0.075))
        rect = QRectF((self.width() - side) / 2 + aw, aw / 2 + 2,
                      side - 2 * aw, side - 2 * aw)
        shown = self._shown
        col = _ramp(shown)

        # track
        pen_bg = QPen(QColor(255, 255, 255, 20), aw)
        pen_bg.setCapStyle(Qt.RoundCap)
        p.setPen(pen_bg)
        p.drawArc(rect, 225 * 16, -270 * 16)

        # progress
        if shown > 0.3:
            pen_fg = QPen(col, aw)
            pen_fg.setCapStyle(Qt.RoundCap)
            p.setPen(pen_fg)
            p.drawArc(rect, 225 * 16, int(-270 * 16 * (shown / 100.0)))

        # numeric - big number, small % so the figure leads
        fnum = _font(T.UI, num_pt, QFont.DemiBold)
        fpct = _font(T.UI, max(7, int(num_pt * 0.5)), QFont.DemiBold)
        num = f"{shown:.0f}"
        mnum = _metrics(T.UI, num_pt, QFont.DemiBold)
        wn = mnum.horizontalAdvance(num)
        wp = _metrics(T.UI, max(7, int(num_pt * 0.5)), QFont.DemiBold).horizontalAdvance("%")
        cx = rect.center().x() - (wn + wp) / 2
        base_y = rect.center().y() + mnum.capHeight() / 2 - (
            side * 0.04 if self._sub else 0)
        p.setPen(T.TEXT)
        p.setFont(fnum)
        p.drawText(QPointF(cx, base_y), num)
        p.setPen(T.TEXT_MUTED)
        p.setFont(fpct)
        p.drawText(QPointF(cx + wn + 1, base_y), "%")

        if self._sub:
            p.setPen(T.TEXT_DIM)
            p.setFont(_font(T.MONO, small_pt))
            p.drawText(QRectF(rect.left(), base_y + side * 0.05, rect.width(), side * 0.14),
                       Qt.AlignHCenter | Qt.AlignTop, self._sub)

        # title beneath the gauge
        ftitle = _font(T.MONO, 7, QFont.Bold, 1.8)
        p.setPen(T.TEXT_MUTED)
        p.setFont(ftitle)
        p.drawText(QRectF(0, self.height() - title_h, self.width(), title_h),
                   Qt.AlignHCenter | Qt.AlignVCenter, self._title)
        p.end()


class Switch(QAbstractButton):
    """iOS/Framer-style toggle. Drop-in for a QCheckBox used as a boolean
    (isChecked / setChecked / toggled). The knob springs across; the track
    brightness follows the same spring so both move as one."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self._pos = motion.Spring(0.0, T.SPRING_SNAPPY, owner=self,
                                  on_change=lambda _v: self.update())
        self._hover = False
        self.toggled.connect(lambda on: self._pos.set(1.0 if on else 0.0))

    def setChecked(self, on):
        was = self.isChecked()
        super().setChecked(on)
        if not self.isVisible() and was != bool(on):
            self._pos.jump(1.0 if on else 0.0)

    def showEvent(self, e):
        super().showEvent(e)
        self._pos.jump(1.0 if self.isChecked() else 0.0)

    def sizeHint(self):
        return QSize(34, 20)

    def enterEvent(self, e):
        self._hover = True; self.update(); super().enterEvent(e)

    def leaveEvent(self, e):
        self._hover = False; self.update(); super().leaveEvent(e)

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        t = max(0.0, min(1.0, self._pos.value))
        w, h = 32.0, 18.0
        track = QRectF((self.width() - w) / 2, (self.height() - h) / 2, w, h)
        enabled = self.isEnabled()

        off_col = T.SURFACE_HOVER if not self._hover else QColor(46, 46, 52)
        on_col = T.ACCENT
        col = motion.blend(off_col, on_col, t)
        if not enabled:
            col = T.SURFACE_2
        p.setPen(QPen(motion.blend(T.BORDER_STRONG, on_col, t) if enabled else T.BORDER, 1))
        p.setBrush(col)
        p.drawRoundedRect(track.adjusted(0.5, 0.5, -0.5, -0.5), h / 2, h / 2)

        d = h - 6
        kx = track.left() + 3 + (w - 6 - d) * t
        knob = QRectF(kx, track.top() + 3, d, d)
        p.setPen(Qt.NoPen)
        p.setBrush(motion.blend(T.TEXT_MUTED, T.ACCENT_INK, t) if enabled else T.TEXT_DIM)
        p.drawEllipse(knob)

        if self.hasFocus():
            p.setPen(QPen(T.TEXT_MUTED, 1))
            p.setBrush(Qt.NoBrush)
            p.drawRoundedRect(track.adjusted(-2.5, -2.5, 2.5, 2.5), h / 2 + 2, h / 2 + 2)
        p.end()
