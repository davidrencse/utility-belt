"""
Weather panel - current conditions for your location, no API key.

Location: ip-api.com. Weather + hourly forecast: Open-Meteo. Air quality:
Open-Meteo air-quality API. A hero (drawn condition icon + big temperature +
feels-like), an hourly temperature curve, a wind compass, and a row of tiles
(humidity, wind, UV, pressure, visibility, air quality, sunrise, sunset).
Everything is fetched on a worker thread and painted in the monochrome theme.
"""
import json
import math
import urllib.parse
import urllib.request
from datetime import datetime

from PySide6.QtCore import QThread, Signal, Qt, QRectF, QPointF
from PySide6.QtGui import QPainter, QPen, QColor, QFont, QPolygonF, QPainterPath, QBrush
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                               QLabel, QPushButton)

from .. import theme as T

_WMO = {
    0: "Clear", 1: "Mainly clear", 2: "Partly cloudy", 3: "Overcast",
    45: "Fog", 48: "Rime fog", 51: "Light drizzle", 53: "Drizzle",
    55: "Dense drizzle", 56: "Freezing drizzle", 57: "Freezing drizzle",
    61: "Light rain", 63: "Rain", 65: "Heavy rain", 66: "Freezing rain",
    67: "Freezing rain", 71: "Light snow", 73: "Snow", 75: "Heavy snow",
    77: "Snow grains", 80: "Rain showers", 81: "Rain showers",
    82: "Violent showers", 85: "Snow showers", 86: "Snow showers",
    95: "Thunderstorm", 96: "Thunderstorm, hail", 99: "Thunderstorm, hail",
}


def _category(code):
    if code in (0,):
        return "clear"
    if code in (1, 2):
        return "partly"
    if code == 3:
        return "cloud"
    if code in (45, 48):
        return "fog"
    if code in (71, 73, 75, 77, 85, 86):
        return "snow"
    if code in (95, 96, 99):
        return "storm"
    if code in (51, 53, 55, 56, 57, 61, 63, 65, 66, 67, 80, 81, 82):
        return "rain"
    return "cloud"


def _get_json(url, timeout=12):
    req = urllib.request.Request(url, headers={"User-Agent": "sysmon-overlay"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _compass(deg):
    return ["N", "NE", "E", "SE", "S", "SW", "W", "NW"][int((deg % 360) / 45 + 0.5) % 8]


def _aqi_label(aqi):
    if aqi is None:
        return "—"
    for hi, name in ((50, "Good"), (100, "Moderate"), (150, "Poor"),
                     (200, "Unhealthy"), (300, "Very bad")):
        if aqi <= hi:
            return f"{aqi:.0f} {name}"
    return f"{aqi:.0f} Hazardous"


def _hhmm(iso):
    try:
        return iso.split("T")[1][:5]
    except (IndexError, AttributeError):
        return "—"


# ------------------------------------------------------------- widgets ----
def _draw_condition(p, rect, cat, day, color):
    """Draw a clean line weather icon inside rect."""
    p.save()
    p.setRenderHint(QPainter.Antialiasing, True)
    cx, cy = rect.center().x(), rect.center().y()
    s = min(rect.width(), rect.height())
    pen = QPen(color, max(2.0, s * 0.045))
    pen.setCapStyle(Qt.RoundCap); pen.setJoinStyle(Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)

    def cloud(ox, oy, scale=1.0, fill=False):
        w = s * 0.6 * scale; h = w * 0.62
        r = QRectF(cx - w / 2 + ox, cy - h / 2 + oy, w, h)
        path = QPainterPath()
        path.addRoundedRect(QRectF(r.left(), r.center().y(), r.width(), r.height() / 2),
                            h * 0.35, h * 0.35)
        path.addEllipse(QRectF(r.left() + r.width() * 0.05, r.top() + h * 0.15,
                               w * 0.5, h * 0.6))
        path.addEllipse(QRectF(r.center().x() - w * 0.1, r.top(), w * 0.55, h * 0.7))
        if fill:
            p.fillPath(path, QBrush(QColor(color.red(), color.green(), color.blue(), 40)))
        p.drawPath(path)

    def sun(ox, oy, scale=1.0):
        rad = s * 0.16 * scale
        p.drawEllipse(QPointF(cx + ox, cy + oy), rad, rad)
        for i in range(8):
            a = i * math.pi / 4
            x1 = cx + ox + math.cos(a) * rad * 1.5
            y1 = cy + oy + math.sin(a) * rad * 1.5
            x2 = cx + ox + math.cos(a) * rad * 2.1
            y2 = cy + oy + math.sin(a) * rad * 2.1
            p.drawLine(QPointF(x1, y1), QPointF(x2, y2))

    def moon(ox, oy):
        rad = s * 0.2
        path = QPainterPath()
        path.addEllipse(QPointF(cx + ox, cy + oy), rad, rad)
        sub = QPainterPath()
        sub.addEllipse(QPointF(cx + ox + rad * 0.55, cy + oy - rad * 0.3), rad, rad)
        p.drawPath(path.subtracted(sub))

    if cat == "clear":
        (sun(0, 0) if day else moon(0, 0))
    elif cat == "partly":
        sun(-s * 0.18, -s * 0.16, 0.7)
        cloud(s * 0.08, s * 0.1)
    elif cat == "cloud":
        cloud(0, 0, 1.1)
    elif cat == "fog":
        cloud(0, -s * 0.1, 1.0)
        for i in range(3):
            y = cy + s * (0.18 + i * 0.12)
            p.drawLine(QPointF(cx - s * 0.28, y), QPointF(cx + s * 0.28, y))
    elif cat in ("rain", "storm", "snow"):
        cloud(0, -s * 0.12, 1.0)
        for i in range(3):
            x = cx + (i - 1) * s * 0.18
            y0 = cy + s * 0.12
            if cat == "snow":
                p.drawEllipse(QPointF(x, y0 + s * 0.12), s * 0.02, s * 0.02)
            elif cat == "storm" and i == 1:
                bolt = QPolygonF([QPointF(x, y0), QPointF(x - s * 0.06, y0 + s * 0.16),
                                  QPointF(x + s * 0.01, y0 + s * 0.16),
                                  QPointF(x - s * 0.04, y0 + s * 0.3)])
                p.drawPolyline(bolt)
            else:
                p.drawLine(QPointF(x, y0), QPointF(x - s * 0.05, y0 + s * 0.18))
    p.restore()


class WeatherIcon(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._cat, self._day = "cloud", True
        self.setMinimumSize(72, 72)

    def set(self, cat, day):
        self._cat, self._day = cat, day
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        _draw_condition(p, QRectF(self.rect()).adjusted(6, 6, -6, -6),
                        self._cat, self._day, T.TEXT)
        p.end()


class HourlyGraph(QWidget):
    """Temperature curve for the next hours, with a filled area and a few
    hour ticks; the first (now) point is marked."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._pts = []          # list of (label, temp)
        self._unit = "°"
        self.setMinimumHeight(96)

    def set_series(self, series, unit="°"):
        self._pts = series
        self._unit = unit
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        r = QRectF(self.rect()).adjusted(2, 4, -2, -2)
        p.setPen(T.TEXT_DIM)
        p.setFont(QFont(T.MONO, 7, QFont.Bold))
        p.drawText(r, Qt.AlignLeft | Qt.AlignTop, "NEXT HOURS")
        if len(self._pts) < 2:
            return
        temps = [t for _, t in self._pts]
        lo, hi = min(temps), max(temps)
        span = max(1.0, hi - lo)
        plot = r.adjusted(0, 18, 0, -16)
        n = len(self._pts)
        step = plot.width() / (n - 1)
        pts = []
        for i, (_, t) in enumerate(self._pts):
            x = plot.left() + i * step
            y = plot.bottom() - (t - lo) / span * plot.height()
            pts.append((x, y))
        path = QPainterPath(); path.moveTo(*pts[0])
        for x, y in pts[1:]:
            path.lineTo(x, y)
        fillp = QPainterPath(path)
        fillp.lineTo(pts[-1][0], plot.bottom()); fillp.lineTo(pts[0][0], plot.bottom())
        fillp.closeSubpath()
        grad_c = QColor(T.TEXT); grad_c.setAlpha(26)
        p.fillPath(fillp, QBrush(grad_c))
        pen = QPen(T.TEXT, 1.8); pen.setJoinStyle(Qt.RoundJoin); pen.setCapStyle(Qt.RoundCap)
        p.setPen(pen); p.drawPath(path)
        # now marker
        p.setBrush(T.TEXT); p.setPen(Qt.NoPen)
        p.drawEllipse(QPointF(*pts[0]), 3, 3)
        # hour ticks + temps every ~4 hours
        p.setFont(QFont(T.MONO, 7))
        for i in range(0, n, max(1, n // 5)):
            x, y = pts[i]
            p.setPen(T.TEXT_MUTED)
            p.drawText(QRectF(x - 20, plot.bottom() + 2, 40, 12),
                       Qt.AlignHCenter, self._pts[i][0])
            p.setPen(T.TEXT_DIM)
            p.drawText(QRectF(x - 20, y - 16, 40, 12),
                       Qt.AlignHCenter, f"{round(self._pts[i][1])}{self._unit}")
        p.end()


class WindCompass(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._deg, self._speed = 0.0, ""
        self.setMinimumSize(92, 92)

    def set_wind(self, deg, speed_text):
        self._deg, self._speed = float(deg or 0), speed_text
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        side = min(self.width(), self.height()) - 22
        cx, cy = self.width() / 2, self.height() / 2 + 2
        rad = side / 2
        p.setPen(QPen(QColor(255, 255, 255, 38), 1.4))
        p.drawEllipse(QPointF(cx, cy), rad, rad)
        p.setPen(T.TEXT_DIM); p.setFont(QFont(T.MONO, 7, QFont.Bold))
        p.drawText(QRectF(cx - 10, cy - rad - 13, 20, 12), Qt.AlignCenter, "N")
        ang = math.radians(self._deg + 180)
        tip = QPointF(cx + math.sin(ang) * (rad - 7), cy - math.cos(ang) * (rad - 7))
        back = QPointF(cx - math.sin(ang) * (rad - 13), cy + math.cos(ang) * (rad - 13))
        perp = ang + math.pi / 2
        poly = QPolygonF([tip,
                          QPointF(back.x() + math.sin(perp) * 6, back.y() - math.cos(perp) * 6),
                          QPointF(back.x() - math.sin(perp) * 6, back.y() + math.cos(perp) * 6)])
        p.setPen(Qt.NoPen); p.setBrush(T.TEXT); p.drawPolygon(poly)
        p.setPen(T.TEXT_MUTED); p.setFont(QFont(T.MONO, 7))
        p.drawText(QRectF(0, self.height() - 14, self.width(), 12),
                   Qt.AlignCenter, self._speed)
        p.end()


class _Tile(QWidget):
    def __init__(self, label, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(11, 8, 11, 8)
        lay.setSpacing(1)
        self._k = QLabel(label.upper())
        self._k.setStyleSheet(
            f"color:{T.hexs(T.TEXT_DIM)};font:700 7pt '{T.MONO}';letter-spacing:1px;")
        self._v = QLabel("—")
        self._v.setStyleSheet(f"color:{T.hexs(T.TEXT)};font:600 13pt '{T.UI}';")
        lay.addWidget(self._k)
        lay.addWidget(self._v)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setStyleSheet(
            f"background:{T.rgba(QColor(255,255,255,10))};border-radius:8px;")

    def set(self, v):
        self._v.setText(str(v))


class WeatherWorker(QThread):
    done = Signal(dict)
    fail = Signal(str)

    def run(self):
        try:
            loc = _get_json("http://ip-api.com/json/?fields=status,city,"
                            "regionName,country,lat,lon")
            if loc.get("status") != "success":
                self.fail.emit("could not locate you by IP")
                return
            lat, lon = loc["lat"], loc["lon"]
            fq = urllib.parse.urlencode({
                "latitude": lat, "longitude": lon,
                "current": "temperature_2m,relative_humidity_2m,apparent_temperature,"
                           "weather_code,pressure_msl,wind_speed_10m,wind_direction_10m,"
                           "visibility,uv_index,is_day",
                "hourly": "temperature_2m",
                "daily": "sunrise,sunset",
                "forecast_days": 2, "timezone": "auto",
            })
            wx = _get_json("https://api.open-meteo.com/v1/forecast?" + fq)
            aqi = None
            try:
                aq = _get_json(
                    "https://air-quality-api.open-meteo.com/v1/air-quality?"
                    + urllib.parse.urlencode({"latitude": lat, "longitude": lon,
                                              "current": "us_aqi"}))
                aqi = aq.get("current", {}).get("us_aqi")
            except Exception:
                pass
            self.done.emit({"loc": loc, "wx": wx, "aqi": aqi})
        except Exception as exc:
            self.fail.emit(f"{type(exc).__name__}: {exc}")


class WeatherPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self._build()
        self.refresh()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(12)

        top = QHBoxLayout()
        self.loc = QLabel("locating…")
        self.loc.setStyleSheet(f"color:{T.hexs(T.TEXT)};font:700 13pt '{T.UI}';")
        top.addWidget(self.loc)
        top.addStretch(1)
        self.updated = QLabel("")
        self.updated.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:8pt '{T.MONO}';")
        top.addWidget(self.updated)
        self.refresh_btn = QPushButton("↻")
        self.refresh_btn.setFixedSize(26, 24)
        self.refresh_btn.setCursor(Qt.PointingHandCursor)
        self.refresh_btn.setToolTip("Refresh")
        self.refresh_btn.setStyleSheet(T.ghost_btn_qss())
        self.refresh_btn.clicked.connect(self.refresh)
        top.addWidget(self.refresh_btn)
        root.addLayout(top)

        hero = QHBoxLayout()
        hero.setSpacing(14)
        self.icon = WeatherIcon()
        self.icon.setFixedSize(84, 84)
        hero.addWidget(self.icon)
        temp_col = QVBoxLayout(); temp_col.setSpacing(0)
        self.temp = QLabel("—")
        self.temp.setStyleSheet(f"color:{T.hexs(T.TEXT)};font:200 46pt '{T.UI}';")
        temp_col.addStretch(1); temp_col.addWidget(self.temp); temp_col.addStretch(1)
        hero.addLayout(temp_col)
        cond_col = QVBoxLayout(); cond_col.setSpacing(2)
        cond_col.addStretch(1)
        self.cond = QLabel("—")
        self.cond.setStyleSheet(f"color:{T.hexs(T.TEXT)};font:600 14pt '{T.UI}';")
        self.feels = QLabel("")
        self.feels.setStyleSheet(f"color:{T.hexs(T.TEXT_MUTED)};font:9pt '{T.MONO}';")
        cond_col.addWidget(self.cond); cond_col.addWidget(self.feels); cond_col.addStretch(1)
        hero.addLayout(cond_col)
        hero.addStretch(1)
        self.graph = HourlyGraph()
        hero.addWidget(self.graph, 2)
        self.compass = WindCompass()
        self.compass.setFixedWidth(100)
        hero.addWidget(self.compass)
        root.addLayout(hero, 1)

        grid = QGridLayout()
        grid.setSpacing(8)
        self.tiles = {}
        specs = ["Humidity", "Wind", "UV index", "Pressure",
                 "Visibility", "Air quality", "Sunrise", "Sunset"]
        for i, name in enumerate(specs):
            t = _Tile(name)
            self.tiles[name] = t
            grid.addWidget(t, i // 4, i % 4)
        root.addLayout(grid)

        self.status = QLabel("")
        self.status.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:8pt '{T.MONO}';")
        root.addWidget(self.status)

    def refresh(self):
        if self.worker and self.worker.isRunning():
            return
        self.status.setText("fetching…")
        self.worker = WeatherWorker(self)
        self.worker.done.connect(self._show)
        self.worker.fail.connect(lambda m: self.status.setText("error: " + m))
        self.worker.start()

    def _show(self, data):
        loc, wx, aqi = data["loc"], data["wx"], data["aqi"]
        cur = wx.get("current", {})
        units = wx.get("current_units", {})
        daily = wx.get("daily", {})
        tu = units.get("temperature_2m", "°")
        city = loc.get("city") or loc.get("regionName") or "Unknown"
        self.loc.setText(f"{city}, {loc.get('country', '')}".strip(", "))
        self.temp.setText(f"{round(cur.get('temperature_2m', 0))}{tu}")
        code = cur.get("weather_code")
        self.cond.setText(_WMO.get(code, "—"))
        self.feels.setText(f"feels like {round(cur.get('apparent_temperature', 0))}{tu}")
        self.icon.set(_category(code), bool(cur.get("is_day", 1)))

        wdir = cur.get("wind_direction_10m", 0)
        wspd = cur.get("wind_speed_10m", 0)
        wsu = units.get("wind_speed_10m", "")
        self.compass.set_wind(wdir, f"{round(wspd)} {wsu}")

        # hourly series from the current hour forward
        hrs = wx.get("hourly", {})
        times = hrs.get("time", []); temps = hrs.get("temperature_2m", [])
        series = []
        if times and temps:
            now = datetime.now()
            start = 0
            for i, ts in enumerate(times):
                try:
                    if datetime.fromisoformat(ts) >= now.replace(minute=0, second=0, microsecond=0):
                        start = i; break
                except ValueError:
                    pass
            for ts, t in list(zip(times, temps))[start:start + 14]:
                series.append((_hhmm(ts)[:2] + "h", t))
        self.graph.set_series(series, tu)

        self.tiles["Humidity"].set(f"{cur.get('relative_humidity_2m', '—')}%")
        self.tiles["Wind"].set(f"{round(wspd)} {wsu} {_compass(wdir)}")
        self.tiles["UV index"].set(round(cur.get("uv_index", 0)))
        self.tiles["Pressure"].set(f"{round(cur.get('pressure_msl', 0))} hPa")
        vis = cur.get("visibility")
        self.tiles["Visibility"].set(f"{vis/1000:.1f} km" if vis is not None else "—")
        self.tiles["Air quality"].set(_aqi_label(aqi))
        self.tiles["Sunrise"].set(_hhmm((daily.get("sunrise") or ["—"])[0]))
        self.tiles["Sunset"].set(_hhmm((daily.get("sunset") or ["—"])[0]))
        self.updated.setText("updated " + datetime.now().strftime("%H:%M"))
        self.status.setText("open-meteo · ip-api")

    def shutdown(self):
        if self.worker and self.worker.isRunning():
            self.worker.wait(2500)
