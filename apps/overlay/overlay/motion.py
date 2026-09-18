"""
Framer-Motion-style motion for Qt widgets.

Qt's QPropertyAnimation is duration-based, which is why interrupted
animations in Qt usually feel wrong: retargeting mid-flight restarts the
clock and drops velocity. Framer Motion's feel comes from *physics* - a
damped spring that carries its velocity when the target changes - plus a
few presence conventions (enter with ease-out, exit faster with ease-in,
shared-layout indicators that glide between items).

This module provides exactly that, with no dependencies:

  Spring   - interruptible damped spring over a float or a tuple of floats
  Tween    - short duration/easing animation (opacity fades, colour blends)
  present / dismiss - window enter/exit (opacity + a small y/x offset)
  reveal   - in-place content crossfade + slide for a swapped child widget
  enabled  - False when the user chose Reduce motion (settings) or Windows
             has client-area animations switched off; everything then snaps.

All animations share one 120 Hz ticker that stops itself when idle, so an
idle HUD costs zero timer wake-ups.
"""
import ctypes
import platform
import time

from PySide6.QtCore import QObject, QTimer, Qt, QPoint, QPointF, QEasingCurve
from PySide6.QtWidgets import QGraphicsOpacityEffect

from . import theme as T

_IS_WINDOWS = platform.system().lower().startswith("win")


# -------------------------------------------------------- reduced motion ---
def _system_animations_on():
    if not _IS_WINDOWS:
        return True
    try:
        SPI_GETCLIENTAREAANIMATION = 0x1042
        val = ctypes.c_bool(True)
        if ctypes.windll.user32.SystemParametersInfoW(
                SPI_GETCLIENTAREAANIMATION, 0, ctypes.byref(val), 0):
            return bool(val.value)
    except Exception:
        pass
    return True


_SYSTEM_ON = None


def enabled():
    global _SYSTEM_ON
    if _SYSTEM_ON is None:
        _SYSTEM_ON = _system_animations_on()
    try:
        from .settings import settings
        if settings.get("reduce_motion"):
            return False
    except Exception:
        pass
    return _SYSTEM_ON


# -------------------------------------------------------------- easing ----
def _bezier(x1, y1, x2, y2):
    c = QEasingCurve(QEasingCurve.BezierSpline)
    c.addCubicBezierSegment(QPointF(x1, y1), QPointF(x2, y2), QPointF(1, 1))
    return c


EASE_OUT = _bezier(0.16, 1.0, 0.3, 1.0)      # expo-out: enters
EASE_IN = _bezier(0.4, 0.0, 1.0, 1.0)        # exits
EASE_IN_OUT = _bezier(0.65, 0.0, 0.35, 1.0)  # crossfades


# -------------------------------------------------------------- ticker ----
class _Ticker(QObject):
    def __init__(self):
        super().__init__()
        self._timer = QTimer(self)
        # 60 Hz matches typical displays; PreciseTimer at 8 ms raised the OS
        # timer resolution and doubled the Python work per animated second.
        self._timer.setTimerType(Qt.CoarseTimer)
        self._timer.setInterval(16)
        self._timer.timeout.connect(self._tick)
        self._active = []
        self._last = 0.0

    def add(self, anim):
        if anim not in self._active:
            self._active.append(anim)
        if not self._timer.isActive():
            self._last = time.perf_counter()
            self._timer.start()

    def remove(self, anim):
        if anim in self._active:
            self._active.remove(anim)

    def _tick(self):
        now = time.perf_counter()
        dt = min(0.05, now - self._last)     # clamp after stalls / sleep
        self._last = now
        for anim in list(self._active):
            try:
                alive = anim._step(dt)
            except RuntimeError:             # owner's C++ object is gone
                alive = False
            if not alive:
                self.remove(anim)
        if not self._active:
            self._timer.stop()


_TICKER = None


def _ticker():
    global _TICKER
    if _TICKER is None:
        _TICKER = _Ticker()
    return _TICKER


class _Anim:
    def __init__(self, owner, on_change, on_done):
        self._on_change = on_change
        self._on_done = on_done
        self._running = False
        if owner is not None:
            try:
                owner.destroyed.connect(self.stop)
            except (AttributeError, RuntimeError):
                pass

    def stop(self, *_):
        self._running = False
        _ticker().remove(self)

    @property
    def running(self):
        return self._running

    def _emit(self, v):
        if self._on_change:
            self._on_change(v)

    def _finish(self):
        self._running = False
        cb, self._on_done = self._on_done, None
        if cb:
            cb()


# -------------------------------------------------------------- spring ----
class Spring(_Anim):
    """Damped spring. `value` may be a float or a tuple of floats (e.g. a
    rect). set(target) retargets without losing velocity - exactly what
    makes a hover indicator feel alive when you sweep across items."""

    def __init__(self, value=0.0, config=T.SPRING_SOFT, on_change=None,
                 on_done=None, owner=None, rest=0.01):
        super().__init__(owner, on_change, on_done)
        self._scalar = not isinstance(value, (tuple, list))
        vals = [float(value)] if self._scalar else [float(v) for v in value]
        self._x = vals
        self._v = [0.0] * len(vals)
        self._t = list(vals)
        self.k, self.c, self.m = config
        self._rest = rest

    @property
    def value(self):
        return self._x[0] if self._scalar else tuple(self._x)

    @property
    def target(self):
        return self._t[0] if self._scalar else tuple(self._t)

    def set(self, target, immediate=False, on_done=None):
        t = [float(target)] if self._scalar else [float(v) for v in target]
        self._t = t
        if on_done is not None:
            self._on_done = on_done
        if immediate or not enabled():
            self._x = list(t)
            self._v = [0.0] * len(t)
            self.stop()
            self._emit(self.value)
            self._finish()
            return
        if not self._running:
            self._running = True
            _ticker().add(self)

    def jump(self, value):
        """Teleport (e.g. set an 'initial' state) with no animation."""
        self.set(value, immediate=True)

    def _step(self, dt):
        if not self._running:
            return False
        sub = 0.004                          # 4 ms substeps keep it stable
        n = max(1, int(dt / sub + 0.5))
        h = dt / n
        for _ in range(n):
            for i in range(len(self._x)):
                a = (-self.k * (self._x[i] - self._t[i]) - self.c * self._v[i]) / self.m
                self._v[i] += a * h
                self._x[i] += self._v[i] * h
        settled = all(abs(self._v[i]) < self._rest * 10 and
                      abs(self._x[i] - self._t[i]) < self._rest
                      for i in range(len(self._x)))
        if settled:
            self._x = list(self._t)
            self._v = [0.0] * len(self._x)
        self._emit(self.value)
        if settled:
            self._finish()
            return False
        return True


# --------------------------------------------------------------- tween ----
class Tween(_Anim):
    def __init__(self, start, end, duration=T.DUR_BASE, easing=EASE_OUT,
                 on_change=None, on_done=None, owner=None, delay=0):
        super().__init__(owner, on_change, on_done)
        self._a, self._b = float(start), float(end)
        self._dur = max(1, duration) / 1000.0
        self._delay = delay / 1000.0
        self._easing = easing
        self._elapsed = 0.0

    def start(self):
        if not enabled():
            self._emit(self._b)
            self._finish()
            return self
        self._elapsed = -self._delay
        self._running = True
        _ticker().add(self)
        return self

    def _step(self, dt):
        if not self._running:
            return False
        self._elapsed += dt
        if self._elapsed < 0:
            return True
        p = min(1.0, self._elapsed / self._dur)
        self._emit(self._a + (self._b - self._a) * self._easing.valueForProgress(p))
        if p >= 1.0:
            self._finish()
            return False
        return True


def blend(c1, c2, t):
    """Linear colour blend - for tweening text/indicator brightness."""
    from PySide6.QtGui import QColor
    t = max(0.0, min(1.0, t))
    return QColor(
        round(c1.red() + (c2.red() - c1.red()) * t),
        round(c1.green() + (c2.green() - c1.green()) * t),
        round(c1.blue() + (c2.blue() - c1.blue()) * t),
        round(c1.alpha() + (c2.alpha() - c1.alpha()) * t))


# ------------------------------------------------------------ presence ----
def _stop_presence(win):
    for attr in ("_mx_fade", "_mx_move"):
        a = getattr(win, attr, None)
        if a is not None:
            a.stop()
        setattr(win, attr, None)


def present(win, at: QPoint, offset=(0, -10), duration=T.DUR_BASE,
            opacity=1.0):
    """Show a top-level window with Framer's `initial={{opacity:0, y:-10}}
    animate={{opacity:1, y:0}}`: opacity eases out, position springs.
    `opacity` is the resting opacity (translucent windows)."""
    _stop_presence(win)
    dx, dy = offset
    if not enabled() or (dx == 0 and dy == 0 and duration <= 0):
        win.move(at)
        win.setWindowOpacity(opacity)
        win.show()
        return
    start_opacity = win.windowOpacity() if win.isVisible() else 0.0
    if not win.isVisible():
        win.move(at.x() + dx, at.y() + dy)
    win.setWindowOpacity(start_opacity)
    win.show()
    win._mx_fade = Tween(start_opacity, opacity, duration, EASE_OUT,
                         on_change=win.setWindowOpacity, owner=win).start()
    base = (float(win.x() - at.x()), float(win.y() - at.y()))
    win._mx_move = Spring(base, T.SPRING_SOFT, owner=win, rest=0.3,
                          on_change=lambda v: win.move(at.x() + round(v[0]),
                                                       at.y() + round(v[1])))
    win._mx_move.set((0.0, 0.0))


def dismiss(win, offset=(0, -6), duration=T.DUR_FAST, on_done=None):
    """Exit: faster than enter, ease-in, then actually hide()."""
    if is_leaving(win):                      # already on its way out
        return
    _stop_presence(win)
    if not win.isVisible():
        if on_done:
            on_done()
        return
    rest = win.windowOpacity()
    if not enabled():
        win.hide()
        win.setWindowOpacity(rest)
        if on_done:
            on_done()
        return
    origin = win.pos()
    dx, dy = offset

    def _change(p):
        win.setWindowOpacity(rest * (1.0 - p))
        win.move(origin.x() + round(dx * p), origin.y() + round(dy * p))

    def _done():
        win.hide()
        win.move(origin)
        win.setWindowOpacity(rest)
        if on_done:
            on_done()

    win._mx_fade = Tween(0.0, 1.0, duration, EASE_IN, on_change=_change,
                         on_done=_done, owner=win).start()


def fade_window(win, opacity, duration=T.DUR_BASE):
    """Glide a visible window's opacity to a new resting value (e.g. when a
    translucency setting changes) instead of snapping."""
    prev = getattr(win, "_mx_opacity", None)
    if prev is not None:
        prev.stop()
    start = win.windowOpacity()
    if not win.isVisible() or not enabled() or abs(start - opacity) < 0.005:
        win.setWindowOpacity(opacity)
        return
    win._mx_opacity = Tween(start, opacity, duration, EASE_IN_OUT,
                            on_change=win.setWindowOpacity, owner=win).start()


def is_leaving(win):
    a = getattr(win, "_mx_fade", None)
    return a is not None and a.running and getattr(a, "_easing", None) is EASE_IN


# --------------------------------------------------------------- reveal ---
def _has_webview(widget):
    for child in [widget] + widget.findChildren(QObject):
        try:
            if child.metaObject().className() == "QWebEngineView":
                return True
        except RuntimeError:
            continue
    return False


def reveal(widget, dx=0, dy=6, duration=T.DUR_BASE):
    """Crossfade + slide a freshly-shown child in place. Skips WebEngine
    views (an opacity effect over Chromium's surface corrupts rendering)."""
    if not enabled() or _has_webview(widget):
        return
    prev = getattr(widget, "_mx_reveal", None)
    start = 0.0
    if prev is not None and prev.running:
        # interrupted mid-flight: restore the true resting position (pos()
        # is still offset) and continue from the current opacity, no flash
        prev.stop()
        base = widget._mx_base
        old = widget.graphicsEffect()
        if isinstance(old, QGraphicsOpacityEffect):
            start = old.opacity()
    else:
        base = widget.pos()
    widget._mx_base = base
    effect = QGraphicsOpacityEffect(widget)
    effect.setOpacity(start)
    widget.setGraphicsEffect(effect)

    def _change(p):
        effect.setOpacity(p)
        widget.move(base.x() + round(dx * (1 - p)), base.y() + round(dy * (1 - p)))

    def _done():
        widget.move(base)
        widget.setGraphicsEffect(None)

    widget._mx_reveal = Tween(start, 1.0, duration, EASE_OUT, on_change=_change,
                              on_done=_done, owner=widget).start()


def appear(widget, visible=True):
    """setVisible() that fades a widget in when it becomes visible. Opacity
    only - layout-managed widgets must not be moved."""
    was = widget.isVisible()
    widget.setVisible(visible)
    if visible and not was and widget.isVisible():
        reveal(widget, dx=0, dy=0, duration=T.DUR_FAST)
