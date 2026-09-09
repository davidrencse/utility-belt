#!/usr/bin/env python3
"""
Tkinter dashboard for the concurrent TCP/UDP port scanner + host recon
toolkit. Black / white / orange, dotted-readout style. Five tabs:

  Port Scan    - TCP/UDP port sweep with a live port-grid heatmap (one
                 dot per port/port-bucket, lighting up as results come
                 in), a scan-progress ring, a response-time sparkline,
                 stat cards, a sortable results table, and a live log.
                 Double-click a row for full detail (TLS/HTTP included
                 when "Deep probe" is on).
  3D View      - the scene rendered in-window by viz3d_tk's software
                 renderer, plus a button for the richer WebGL version
                 that viz3d.py opens in the browser.
  System       - this machine's specs with live CPU/memory/disk gauges.
  Host Recon   - ping status/latency/TTL, OS guess, MAC + vendor guess
                 (local subnet only), reverse/forward DNS, traceroute.
  Local Network- this machine's own hostname/IP/adapter info.

All the heavy lifting (sockets, subprocess calls to ping/arp/tracert,
spec probing) lives in port_scanner.py, net_recon.py and system_info.py —
this file is presentation, custom Canvas widgets, and thread orchestration.
"""

import concurrent.futures
import math
import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, font as tkfont, messagebox, ttk

import geoip
import net_recon
import port_scanner as ps
import system_info
import viz3d
import viz3d_tk
import viz_geo

# ---------------------------------------------------------------- palette --

C = {
    "bg": "#0a0a0c",       # near-black ground, not a pure void — lets cards read as surfaces
    "panel": "#141418",
    "card": "#17171c",
    "border": "#2a2a31",
    "fg": "#f4f2ec",
    "muted": "#8a8a93",
    "dim": "#44444d",
    "accent": "#ff5a1f",
    "accent_dim": "#7a2e10",
    "amber": "#d68a2e",
    "red": "#ff3b30",
    "white": "#f4f2ec",
}

# One radius + spacing scale, applied everywhere for a consistent rounded feel.
RADIUS = 16
PAD = 12

STATUS_COLOR = {
    "open": C["accent"],
    "closed": C["dim"],
    "filtered": C["amber"],
    "open|filtered": C["amber"],
    "error": C["red"],
}
STATUS_PRIORITY = {"pending": 0, "closed": 1, "filtered": 2, "open|filtered": 2, "error": 2, "open": 3}
GRID_COLORS = {0: C["dim"], 1: C["dim"], 2: C["amber"], 3: C["accent"]}

MONO = "Consolas"
UI_FONT = "Segoe UI"


_MONO_FONTS = {}


def _mono(size):
    """Cached bold mono font — StatCard measures these on every redraw."""
    if size not in _MONO_FONTS:
        _MONO_FONTS[size] = tkfont.Font(family=MONO, size=size, weight="bold")
    return _MONO_FONTS[size]


def _stripe(tree):
    """Alternating row tag, so banding survives incremental inserts."""
    return "even" if len(tree.get_children()) % 2 == 0 else "odd"


def round_rect(canvas, x1, y1, x2, y2, r, **kwargs):
    """Rounded-rectangle polygon — the shared card shape used by every
    custom Canvas widget so corners match across the whole dashboard."""
    r = min(r, abs(x2 - x1) / 2, abs(y2 - y1) / 2)
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(pts, smooth=True, **kwargs)


# --------------------------------------------------------- canvas widgets --

class StatCard(tk.Canvas):
    """Dark rounded card with a small status dot, a label, and a big
    value — the DeerFlow-style readout tile."""

    def __init__(self, parent, title, value="0", dot_color=None, **kwargs):
        super().__init__(parent, bg=C["bg"], highlightthickness=0, **kwargs)
        self.title = title
        self.value = str(value)
        self.dot_color = dot_color or C["muted"]
        self.bind("<Configure>", lambda e: self._redraw())
        self._redraw()

    def _redraw(self):
        self.delete("all")
        w, h = self.winfo_width() or 170, self.winfo_height() or 74
        round_rect(self, 1, 1, w - 1, h - 1, RADIUS, fill=C["card"], outline=C["border"])
        self.create_oval(16, 16, 23, 23, fill=self.dot_color, outline="")
        self.create_text(30, 19, text=self.title, anchor="w", fill=C["muted"],
                          font=(MONO, 8, "bold"))
        # Fit the value to the card. Shrinking the type alone bottoms out at
        # 8pt and then just clips (a full CPU or OS name ran off the edge), so
        # try wrapping across 1..3 lines too and keep whichever layout affords
        # the largest legible type.
        top_y, bottom_pad, left = 34, 12, 16
        avail_w = max(30, w - left - 12)
        avail_h = max(14, h - top_y - bottom_pad)

        # Measure the real font rather than estimating glyph widths — the
        # point-to-pixel ratio made a guessed constant wrong by ~30%, which is
        # what let long values overflow the card instead of wrapping.
        best = None
        for lines in self._layouts(self.value):
            longest = max(lines, key=len, default="")
            for size in range(16, 6, -1):
                font = _mono(size)
                if (font.measure(longest) <= avail_w
                        and len(lines) * font.metrics("linespace") <= avail_h):
                    break
            if best is None or size > best[0]:
                best = (size, lines, font)
        size, lines, font = best

        block_h = len(lines) * font.metrics("linespace")
        y = top_y + max(0, (avail_h - block_h) / 2)        # vertically centered in the value area
        self.create_text(left, y, text="\n".join(lines), anchor="nw", fill=C["fg"],
                          font=font)

    @staticmethod
    def _layouts(value):
        """Candidate line-splits for a value: the caller's own line breaks
        first, then greedy word-wraps into 2 and 3 lines."""
        explicit = value.split("\n")
        yield explicit
        if len(explicit) > 1:
            return
        words = value.split()
        for target in (2, 3):
            if len(words) < target:
                continue
            width = max(len(w) for w in words)
            width = max(width, -(-len(value) // target))   # ceil, so lines balance
            lines, cur = [], ""
            for word in words:
                cand = f"{cur} {word}".strip()
                if cur and len(cand) > width:
                    lines.append(cur)
                    cur = word
                else:
                    cur = cand
            if cur:
                lines.append(cur)
            if 1 < len(lines) <= target:
                yield lines

    def set(self, value, dot_color=None):
        self.value = str(value)
        if dot_color:
            self.dot_color = dot_color
        self._redraw()


class DotRing(tk.Canvas):
    """A ring of dots that fill in clockwise — the donut-gauge look."""

    def __init__(self, parent, dots=44, label="PROGRESS", **kwargs):
        super().__init__(parent, bg=C["bg"], highlightthickness=0, **kwargs)
        self.dots = dots
        self.label = label
        self.dot_ids = []
        self.big_text_id = None
        self.small_text_id = None
        self.fraction = 0.0
        self.big_text = "0"
        self.bind("<Configure>", lambda e: self._redraw())
        self._redraw()

    def _redraw(self):
        self.delete("all")
        w, h = self.winfo_width() or 150, self.winfo_height() or 150
        round_rect(self, 1, 1, w - 1, h - 1, RADIUS, fill=C["card"], outline=C["border"])
        cx, cy = w / 2, h / 2
        r = min(w, h) / 2 - 12
        self.dot_ids = []
        lit = round(self.fraction * self.dots)
        for i in range(self.dots):
            angle = 2 * math.pi * i / self.dots - math.pi / 2
            x = cx + r * math.cos(angle)
            y = cy + r * math.sin(angle)
            color = C["accent"] if i < lit else C["dim"]
            rad = 3 if i < lit else 2
            d = self.create_oval(x - rad, y - rad, x + rad, y + rad, fill=color, outline="")
            self.dot_ids.append(d)
        self.big_text_id = self.create_text(cx, cy - 6, text=self.big_text, fill=C["fg"],
                                             font=(MONO, 18, "bold"))
        self.small_text_id = self.create_text(cx, cy + 15, text=self.label, fill=C["muted"],
                                               font=(UI_FONT, 8))

    def set_value(self, fraction, big_text, label=None):
        self.fraction = max(0.0, min(1.0, fraction))
        self.big_text = big_text
        if label is not None:
            self.label = label
        self._redraw()


class Sparkline(tk.Canvas):
    """Rolling line+dot trace, used for per-port response times."""

    def __init__(self, parent, maxpoints=50, **kwargs):
        super().__init__(parent, bg=C["bg"], highlightthickness=0, **kwargs)
        self.maxpoints = maxpoints
        self.values = []
        self.bind("<Configure>", lambda e: self._redraw())

    def add(self, value, redraw=True):
        if value is None:
            return
        self.values.append(value)
        if len(self.values) > self.maxpoints:
            self.values.pop(0)
        if redraw:
            self._redraw()

    def flush(self):
        self._redraw()

    def clear(self):
        self.values = []
        self._redraw()

    def _redraw(self):
        self.delete("all")
        w, h = self.winfo_width() or 220, self.winfo_height() or 90
        round_rect(self, 1, 1, w - 1, h - 1, RADIUS, fill=C["card"], outline=C["border"])
        pad_top, pad_bottom, pad_x = 34, 26, 14

        self.create_text(pad_x, 15, text="RESPONSE TIME", anchor="w", fill=C["muted"],
                          font=(MONO, 8, "bold"))
        if not self.values:
            self.create_text(w / 2, h / 2 + 6, text="—", fill=C["dim"], font=(MONO, 14))
            return

        top, floor = pad_top, h - pad_bottom
        lo, hi = min(self.values), max(self.values)
        # Log scale: latencies here run from a fraction of a millisecond up to
        # the full timeout, and only a log axis shows both ends at once.
        llo, lhi = math.log10(max(lo, 0.05)), math.log10(max(hi, 0.05))
        if lhi - llo < 0.3:                       # near-flat trace — keep it off the edges
            mid = (lhi + llo) / 2
            llo, lhi = mid - 0.3, mid + 0.3

        def yof(v):
            f = (math.log10(max(v, 0.05)) - llo) / (lhi - llo)
            return floor - max(0.0, min(1.0, f)) * (floor - top)

        self.create_line(pad_x, floor, w - pad_x, floor, fill=C["border"])

        n = self.maxpoints
        step = (w - 2 * pad_x) / max(1, n - 1)
        start_i = n - len(self.values)
        pts = [(pad_x + (start_i + i) * step, yof(v)) for i, v in enumerate(self.values)]

        if len(pts) > 1:                          # soft area under the trace
            poly = [c for xy in pts for c in xy]
            poly += [pts[-1][0], floor, pts[0][0], floor]
            self.create_polygon(poly, fill=C["accent_dim"], outline="", stipple="gray25")
            for i in range(len(pts) - 1):
                self.create_line(*pts[i], *pts[i + 1], fill=C["accent"], width=1.6)
        x, y = pts[-1]
        self.create_oval(x - 3, y - 3, x + 3, y + 3, fill=C["accent"], outline=C["card"], width=1)

        self.create_text(w - pad_x, 15, text=self._fmt(self.values[-1]), anchor="e",
                          fill=C["fg"], font=(MONO, 9, "bold"))
        self.create_text(pad_x, floor + 11, text=f"lo {self._fmt(lo)}", anchor="w",
                          fill=C["dim"], font=(MONO, 7))
        self.create_text(w - pad_x, floor + 11, text=f"hi {self._fmt(hi)}", anchor="e",
                          fill=C["dim"], font=(MONO, 7))

    @staticmethod
    def _fmt(v):
        return f"{v:.1f} ms" if v < 100 else f"{v:.0f} ms"


class PortGridViz(tk.Canvas):
    """The centerpiece: a grid of dots, one per port (or per port-bucket
    when the range is large), that lights up live as the scan runs.
    Dim = not yet scanned, gray = closed, amber = filtered, orange = open.
    """

    MAX_CELLS = 1024

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=C["bg"], highlightthickness=0, **kwargs)
        self.ports = []
        self.bucket_size = 1
        self.bucket_count = 0
        self.cols = 1
        self.rows = 1
        self.bucket_state = []
        self.cell_ids = []
        self.port_labels = {}
        self.bind("<Configure>", lambda e: self._layout())
        self._empty_state()

    def _empty_state(self):
        self.delete("all")
        w, h = self.winfo_width() or 500, self.winfo_height() or 300
        round_rect(self, 1, 1, w - 1, h - 1, RADIUS, fill=C["card"], outline=C["border"])
        self.create_text(16, 16, text="PORT MAP", anchor="w", fill=C["muted"],
                          font=(MONO, 8, "bold"))
        self.create_text(w / 2, h / 2, text="run a scan to populate", fill=C["dim"],
                          font=(UI_FONT, 9))

    def reset(self, ports):
        self.ports = ports
        total = len(ports)
        self.bucket_size = max(1, math.ceil(total / self.MAX_CELLS))
        self.bucket_count = max(1, math.ceil(total / self.bucket_size))
        self.cols = min(40, self.bucket_count)
        self.rows = max(1, math.ceil(self.bucket_count / self.cols))
        self.bucket_state = [0] * self.bucket_count
        self._layout()

    def _layout(self):
        if not self.ports:
            self._empty_state()
            return
        self.delete("all")
        w, h = self.winfo_width() or 500, self.winfo_height() or 300
        round_rect(self, 1, 1, w - 1, h - 1, RADIUS, fill=C["card"], outline=C["border"])
        self.create_text(16, 16, text=f"PORT MAP  ({len(self.ports)} ports"
                          + (f", {self.bucket_size}/dot)" if self.bucket_size > 1 else ")"),
                          anchor="w", fill=C["muted"], font=(MONO, 8, "bold"))
        top_pad, side_pad, bottom_pad = 32, 16, 14
        avail_w = max(20, w - side_pad * 2)
        avail_h = max(20, h - top_pad - bottom_pad)
        cell_w = avail_w / self.cols
        cell_h = avail_h / self.rows
        size = max(2.0, min(cell_w, cell_h) * 0.62)
        self.cell_ids = []
        for i in range(self.bucket_count):
            col = i % self.cols
            row = i // self.cols
            cx = side_pad + col * cell_w + cell_w / 2
            cy = top_pad + row * cell_h + cell_h / 2
            r = size / 2
            color = GRID_COLORS[self.bucket_state[i]]
            outline = "" if self.bucket_state[i] else C["border"]
            item = self.create_oval(cx - r, cy - r, cx + r, cy + r, fill=color,
                                     outline=outline, width=1, tags="cell")
            self.cell_ids.append(item)

    def mark(self, port_index, status):
        if not self.bucket_size or port_index is None:
            return
        bucket = port_index // self.bucket_size
        if bucket >= len(self.bucket_state):
            return
        priority = STATUS_PRIORITY.get(status, 1)
        if priority > self.bucket_state[bucket]:
            self.bucket_state[bucket] = priority
            if bucket < len(self.cell_ids):
                self.itemconfig(self.cell_ids[bucket], fill=GRID_COLORS[priority],
                                 outline="")


# ---------------------------------------------------------------- main UI --

class TabBar(tk.Canvas):
    """Underline-style tab strip driven by a hidden ttk.Notebook. Draws the
    labels itself so the selected tab gets an accent rule rather than the
    bevelled box ttk insists on."""

    HEIGHT = 42
    GAP = 26

    def __init__(self, parent, labels, on_select, **kwargs):
        super().__init__(parent, bg=C["bg"], highlightthickness=0,
                         height=self.HEIGHT, **kwargs)
        self.labels = list(labels)
        self.on_select = on_select
        self.active = 0
        self.hover = -1
        self._spans = []          # (x0, x1) per tab, filled in by _redraw
        self.bind("<Configure>", lambda e: self._redraw())
        self.bind("<Button-1>", self._on_click)
        self.bind("<Motion>", self._on_motion)
        self.bind("<Leave>", lambda e: self._set_hover(-1))
        self._redraw()

    def select(self, index):
        if index != self.active:
            self.active = index
            self._redraw()

    def _hit(self, x):
        for i, (x0, x1) in enumerate(self._spans):
            if x0 <= x <= x1:
                return i
        return -1

    def _set_hover(self, i):
        if i != self.hover:
            self.hover = i
            self._redraw()

    def _on_motion(self, event):
        i = self._hit(event.x)
        self._set_hover(i)
        self.configure(cursor="hand2" if i >= 0 else "")

    def _on_click(self, event):
        i = self._hit(event.x)
        if i >= 0:
            self.select(i)
            self.on_select(i)

    def _redraw(self):
        self.delete("all")
        w = self.winfo_width() or 900
        baseline = self.HEIGHT - 1
        self.create_line(0, baseline, w, baseline, fill=C["border"])

        self._spans = []
        x = 2
        for i, label in enumerate(self.labels):
            item = self.create_text(x, self.HEIGHT / 2 - 2, text=label, anchor="w",
                                    font=(MONO, 9, "bold"),
                                    fill=C["accent"] if i == self.active
                                    else (C["fg"] if i == self.hover else C["muted"]))
            x0, _, x1, _ = self.bbox(item)
            self._spans.append((x0 - self.GAP / 2, x1 + self.GAP / 2))
            if i == self.active:
                self.create_line(x0 - 2, baseline, x1 + 2, baseline,
                                 fill=C["accent"], width=2)
            x = x1 + self.GAP


class PortScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Port Scanner Dashboard")
        self.geometry("1320x840")
        self.minsize(1080, 680)
        self.configure(bg=C["bg"])

        self.scan_thread = None
        self.cancel_event = threading.Event()
        self.result_queue = queue.Queue()
        self.total_ports = 0
        self.done_ports = 0
        self.open_count = 0
        self.closed_count = 0
        self.filtered_count = 0
        self.start_time = 0
        self.row_data = {}
        self.port_index = {}
        self._current_results = []

        self.recon_thread = None
        self.trace_thread = None
        self.specs = {}
        self.scan_meta = {}
        self.geo = None
        self.geo_thread = None

        self._build_style()
        self._build_widgets()
        self.after(0, self._enable_dark_titlebar)
        self._poll_queue()
        self._load_local_network_info()
        self.refresh_system_specs()

    # ---------------------------------------------------------------- UI --

    def _enable_dark_titlebar(self):
        """Ask DWM for the dark window frame so the OS title bar matches the
        app instead of sitting on top of it as a white band."""
        try:
            import ctypes
            self.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            val = ctypes.c_int(1)
            for attr in (20, 19):   # USE_IMMERSIVE_DARK_MODE, and the pre-20H1 id
                if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                        hwnd, attr, ctypes.byref(val), ctypes.sizeof(val)) == 0:
                    break
            # Win11 22000+ also lets us tint the caption, its text and the border.
            for attr, color in ((35, C["bg"]), (36, C["muted"]), (34, C["bg"])):
                bgr = int(color[5:7] + color[3:5] + color[1:3], 16)
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(ctypes.c_int(bgr)), 4)
        except Exception:
            pass   # non-Windows or older DWM — just keep the default frame

    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        # clam paints a 3D bevel on nearly every element out of lightcolor /
        # darkcolor / bordercolor. Left at their defaults those are near-white,
        # which is where all the stray light edges came from — so they get
        # flattened to the ground colour once, globally, here.
        style.configure(".", background=C["bg"], foreground=C["fg"],
                        fieldbackground=C["panel"], bordercolor=C["bg"],
                        lightcolor=C["bg"], darkcolor=C["bg"], troughcolor=C["panel"],
                        focuscolor=C["bg"], borderwidth=0, relief="flat")

        style.configure("TFrame", background=C["bg"])
        style.configure("TLabel", background=C["bg"], foreground=C["fg"], font=(UI_FONT, 9))
        style.configure("Sub.TLabel", background=C["bg"], foreground=C["muted"], font=(UI_FONT, 9))
        style.configure("Field.TLabel", background=C["bg"], foreground=C["muted"],
                        font=(MONO, 8, "bold"))
        style.configure("SectionTitle.TLabel", background=C["bg"], foreground=C["accent"],
                        font=(MONO, 9, "bold"))

        style.configure("TButton", font=(MONO, 9, "bold"), padding=(14, 9), background=C["panel"],
                        foreground=C["fg"], borderwidth=0, relief="flat",
                        bordercolor=C["panel"], lightcolor=C["panel"], darkcolor=C["panel"])
        style.map("TButton",
                  background=[("pressed", C["card"]), ("active", C["border"]),
                              ("disabled", C["card"])],
                  lightcolor=[("active", C["border"]), ("disabled", C["card"])],
                  darkcolor=[("active", C["border"]), ("disabled", C["card"])],
                  foreground=[("disabled", C["dim"])])
        style.configure("Accent.TButton", background=C["accent"], foreground="#120600",
                        bordercolor=C["accent"], lightcolor=C["accent"], darkcolor=C["accent"])
        style.map("Accent.TButton",
                  background=[("pressed", "#c8451a"), ("active", "#ff7440"), ("disabled", C["card"])],
                  lightcolor=[("active", "#ff7440"), ("disabled", C["card"])],
                  darkcolor=[("active", "#ff7440"), ("disabled", C["card"])],
                  foreground=[("disabled", C["dim"])])

        style.configure("TEntry", fieldbackground=C["panel"], foreground=C["fg"],
                        insertcolor=C["accent"], bordercolor=C["panel"],
                        lightcolor=C["panel"], darkcolor=C["panel"],
                        borderwidth=0, relief="flat", padding=(8, 7))
        style.map("TEntry",
                  fieldbackground=[("focus", C["card"])],
                  bordercolor=[("focus", C["accent"])], lightcolor=[("focus", C["accent"])],
                  darkcolor=[("focus", C["accent"])])
        style.configure("TSpinbox", fieldbackground=C["panel"], foreground=C["fg"],
                        background=C["panel"], arrowcolor=C["muted"], arrowsize=11,
                        bordercolor=C["panel"], lightcolor=C["panel"], darkcolor=C["panel"],
                        borderwidth=0, relief="flat", padding=(6, 6))
        style.map("TSpinbox",
                  fieldbackground=[("focus", C["card"])],
                  bordercolor=[("focus", C["accent"])], lightcolor=[("focus", C["accent"])],
                  darkcolor=[("focus", C["accent"])],
                  arrowcolor=[("active", C["accent"])])

        for kind in ("TCheckbutton", "TRadiobutton"):
            style.configure(kind, background=C["bg"], foreground=C["muted"],
                            font=(UI_FONT, 9), focuscolor=C["bg"], padding=(0, 3),
                            indicatorbackground=C["panel"], indicatorforeground=C["accent"],
                            indicatormargin=(0, 0, 7, 0),
                            bordercolor=C["border"], lightcolor=C["border"], darkcolor=C["border"])
            style.map(kind,
                      foreground=[("selected", C["fg"]), ("active", C["fg"])],
                      indicatorbackground=[("selected", C["accent"]), ("active", C["card"])],
                      bordercolor=[("selected", C["accent"]), ("active", C["muted"])],
                      lightcolor=[("selected", C["accent"]), ("active", C["muted"])],
                      darkcolor=[("selected", C["accent"]), ("active", C["muted"])])

        # Tabs: no box, no focus ring — just a label that lights up when active.
        style.configure("TNotebook", background=C["bg"], borderwidth=0,
                        bordercolor=C["bg"], lightcolor=C["bg"], darkcolor=C["bg"],
                        tabmargins=(0, 0, 0, 0))
        style.layout("TNotebook", [("Notebook.client", {"sticky": "nswe"})])
        style.configure("TNotebook.Tab", background=C["bg"], foreground=C["dim"],
                        padding=(16, 10), font=(MONO, 9, "bold"), borderwidth=0,
                        bordercolor=C["bg"], lightcolor=C["bg"], darkcolor=C["bg"])
        style.map("TNotebook.Tab",
                  background=[("selected", C["bg"]), ("active", C["bg"])],
                  foreground=[("selected", C["accent"]), ("active", C["fg"])],
                  expand=[("selected", (0, 0, 0, 0))])
        style.layout("TNotebook.Tab", [])   # hidden — TabBar draws the strip

        style.configure("Treeview", background=C["panel"], fieldbackground=C["panel"],
                        foreground=C["fg"], rowheight=27, borderwidth=0, relief="flat",
                        font=(MONO, 9))
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])  # drop the field border
        style.configure("Treeview.Heading", background=C["bg"], foreground=C["muted"],
                        font=(MONO, 8, "bold"), borderwidth=0, relief="flat", padding=(8, 8),
                        bordercolor=C["bg"], lightcolor=C["bg"], darkcolor=C["bg"])
        style.map("Treeview.Heading",
                  background=[("active", C["card"])], foreground=[("active", C["accent"])])
        style.map("Treeview", background=[("selected", C["accent_dim"])],
                  foreground=[("selected", C["fg"])])

        # Thin, arrow-less scrollbars in both orientations.
        for orient in ("Vertical", "Horizontal"):
            style.layout(orient + ".TScrollbar", [
                (orient + ".Scrollbar.trough", {"sticky": "nswe", "children": [
                    (orient + ".Scrollbar.thumb", {"sticky": "nswe", "unit": "1"})]})])
            style.configure(orient + ".TScrollbar", background=C["border"], troughcolor=C["bg"],
                            bordercolor=C["bg"], lightcolor=C["border"], darkcolor=C["border"],
                            arrowsize=0, borderwidth=0, relief="flat", width=8)
            style.map(orient + ".TScrollbar",
                      background=[("pressed", C["accent"]), ("active", C["muted"])],
                      lightcolor=[("pressed", C["accent"]), ("active", C["muted"])],
                      darkcolor=[("pressed", C["accent"]), ("active", C["muted"])])

        style.configure("Horizontal.TProgressbar", background=C["accent"], troughcolor=C["panel"],
                        bordercolor=C["panel"], lightcolor=C["accent"], darkcolor=C["accent"],
                        borderwidth=0, thickness=6)
        style.configure("TPanedwindow", background=C["bg"])
        style.configure("Sash", sashthickness=10, gripcount=0, background=C["bg"],
                        bordercolor=C["bg"], lightcolor=C["bg"], darkcolor=C["bg"])
        style.configure("TSeparator", background=C["border"])

    def _build_widgets(self):
        root = ttk.Frame(self, padding=(18, 14, 18, 16))
        root.pack(fill="both", expand=True)

        # No banner header — the tab bar is the top of the app now.
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

        scan_tab = ttk.Frame(self.notebook)
        view3d_tab = ttk.Frame(self.notebook)
        geo_tab = ttk.Frame(self.notebook)
        system_tab = ttk.Frame(self.notebook)
        recon_tab = ttk.Frame(self.notebook)
        local_tab = ttk.Frame(self.notebook)
        self.notebook.add(scan_tab, text="Port Scan")
        self.notebook.add(view3d_tab, text="3D View")
        self.notebook.add(geo_tab, text="Geo / Map")
        self.notebook.add(system_tab, text="System")
        self.notebook.add(recon_tab, text="Host Recon")
        self.notebook.add(local_tab, text="Local Network")

        # The strip is built from the notebook's own tabs and packed above it,
        # so adding a tab above is all it takes — the labels can't drift.
        self.tabbar = TabBar(root,
                             [self.notebook.tab(t, "text").upper()
                              for t in self.notebook.tabs()],
                             self._on_tab_click)
        self.tabbar.pack(fill="x", pady=(0, 16), before=self.notebook)

        self._build_scan_tab(scan_tab)
        self._build_3d_tab(view3d_tab)
        self._build_geo_tab(geo_tab)
        self._build_system_tab(system_tab)
        self._build_recon_tab(recon_tab)
        self._build_local_tab(local_tab)

        # keep the strip in sync if a tab is changed programmatically
        self.notebook.bind("<<NotebookTabChanged>>",
                           lambda e: self.tabbar.select(self.notebook.index("current")))

    def _on_tab_click(self, index):
        self.notebook.select(index)

    # ---------------------------------------------------------- scan tab --

    def _build_scan_tab(self, root):
        bar = ttk.Frame(root, padding=(0, 0, 0, 10))
        bar.pack(fill="x")

        # Buttons are packed first and to the right, so they always keep their
        # full width; the field grid to their left is what gives when the
        # window narrows (previously EXPORT just fell off the edge).
        btn_frame = ttk.Frame(bar)
        btn_frame.pack(side="right", anchor="s", padx=(16, 0))
        form = ttk.Frame(bar)
        form.pack(side="left", fill="x", expand=True)

        ttk.Label(form, text="TARGET", style="Field.TLabel").grid(row=0, column=0, sticky="w",
                                                                  pady=(0, 4))
        self.target_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(form, textvariable=self.target_var, width=18).grid(row=1, column=0, sticky="w", padx=(0, 12))

        ttk.Label(form, text="PORTS", style="Field.TLabel").grid(row=0, column=1, sticky="w",
                                                       pady=(0, 4))
        self.ports_var = tk.StringVar(value="1-1024")
        ttk.Entry(form, textvariable=self.ports_var, width=18).grid(row=1, column=1, sticky="w", padx=(0, 12))

        ttk.Label(form, text="TIMEOUT (S)", style="Field.TLabel").grid(row=0, column=2, sticky="w",
                                                       pady=(0, 4))
        self.timeout_var = tk.DoubleVar(value=2.0)
        ttk.Spinbox(form, from_=0.1, to=10.0, increment=0.1, textvariable=self.timeout_var,
                    width=6).grid(row=1, column=2, sticky="w", padx=(0, 12))

        ttk.Label(form, text="THREADS", style="Field.TLabel").grid(row=0, column=3, sticky="w",
                                                       pady=(0, 4))
        self.threads_var = tk.IntVar(value=150)
        ttk.Spinbox(form, from_=1, to=500, textvariable=self.threads_var,
                    width=6).grid(row=1, column=3, sticky="w", padx=(0, 12))

        ttk.Label(form, text="PROTOCOL", style="Field.TLabel").grid(row=0, column=4, sticky="w",
                                                       pady=(0, 4))
        proto_frame = ttk.Frame(form)
        proto_frame.grid(row=1, column=4, sticky="w", padx=(0, 12))
        self.protocol_var = tk.StringVar(value="tcp")
        for text, value in (("TCP", "tcp"), ("UDP", "udp"), ("Both", "both")):
            ttk.Radiobutton(proto_frame, text=text, variable=self.protocol_var,
                            value=value).pack(side="left", padx=(0, 14))

        # --- second row: scan behaviour + hygiene (avoid tripping IDS/firewalls) ---
        opts = ttk.Frame(root, padding=(0, 0, 0, 12))
        opts.pack(fill="x")

        self.banner_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Grab banners", variable=self.banner_var).pack(side="left",
                                                                                  padx=(0, 18))
        self.deep_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Deep probe (HTTP/TLS)", variable=self.deep_var).pack(side="left",
                                                                                         padx=(0, 18))
        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Show closed/filtered", variable=self.verbose_var,
                        command=self._refresh_table_visibility).pack(side="left", padx=(0, 18))
        self.random_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Randomize order", variable=self.random_var).pack(side="left",
                                                                                     padx=(0, 18))
        self.polite_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Polite (50/s + random)",
                        variable=self.polite_var).pack(side="left", padx=(0, 24))

        ttk.Separator(opts, orient="vertical").pack(side="left", fill="y", padx=(0, 18))
        ttk.Label(opts, text="RATE /s", style="Field.TLabel").pack(side="left", padx=(0, 8))
        self.rate_var = tk.IntVar(value=0)
        ttk.Spinbox(opts, from_=0, to=10000, increment=50, textvariable=self.rate_var,
                    width=7).pack(side="left")
        ttk.Label(opts, text="0 = unthrottled", style="Sub.TLabel").pack(side="left", padx=(10, 0))

        self.scan_btn = ttk.Button(btn_frame, text="▶ SCAN", style="Accent.TButton", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=(0, 6))
        self.stop_btn = ttk.Button(btn_frame, text="■ STOP", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 6))
        self.view3d_btn = ttk.Button(btn_frame, text="⛶ 3D VIEW", command=self.open_3d_view, state="disabled")
        self.view3d_btn.pack(side="left", padx=(0, 6))
        self.export_btn = ttk.Button(btn_frame, text="⤓ EXPORT", command=self.export_3d_view, state="disabled")
        self.export_btn.pack(side="left")

        form.columnconfigure(7, weight=1)   # the elastic gap before the buttons

        cards = ttk.Frame(root)
        cards.pack(fill="x", pady=(0, 10))
        for i in range(7):
            cards.columnconfigure(i, weight=1)

        self.card_target = StatCard(cards, "TARGET", "—")
        self.card_scanned = StatCard(cards, "SCANNED", "0 / 0")
        self.card_open = StatCard(cards, "OPEN", "0")
        self.card_closed = StatCard(cards, "CLOSED", "0")
        self.card_filtered = StatCard(cards, "FILTERED", "0")
        self.card_hosts = StatCard(cards, "HOSTS SCANNED", "0")
        self.card_elapsed = StatCard(cards, "ELAPSED", "0.0s")

        for i, card in enumerate([self.card_target, self.card_scanned, self.card_open, self.card_closed,
                                   self.card_filtered, self.card_hosts, self.card_elapsed]):
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            card.configure(height=84)

        # ---- visualization row: port grid | progress ring | sparkline ----
        viz_row = ttk.Frame(root)
        viz_row.pack(fill="x", pady=(0, 10))
        viz_row.columnconfigure(0, weight=3)
        viz_row.columnconfigure(1, weight=1)
        viz_row.columnconfigure(2, weight=1)

        self.port_grid = PortGridViz(viz_row, height=170)
        self.port_grid.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        self.progress_ring = DotRing(viz_row, dots=44, label="0 / 0", height=170, width=170)
        self.progress_ring.grid(row=0, column=1, sticky="nsew", padx=8)

        self.sparkline = Sparkline(viz_row, height=170, width=220)
        self.sparkline.grid(row=0, column=2, sticky="nsew", padx=(8, 0))

        status_frame = ttk.Frame(root)
        status_frame.pack(fill="x", pady=(0, 10))
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(status_frame, textvariable=self.status_var, style="Sub.TLabel",
                  width=34, anchor="e").pack(side="right")
        self.progress = ttk.Progressbar(status_frame, mode="determinate")
        self.progress.pack(fill="x", side="left", expand=True, padx=(0, 14), pady=(6, 6))

        body = ttk.Panedwindow(root, orient="horizontal")
        body.pack(fill="both", expand=True)

        table_frame = ttk.Frame(body, padding=(0, 0, 8, 0))
        ttk.Label(table_frame, text="RESULTS", style="SectionTitle.TLabel").pack(anchor="w",
                                                                                 pady=(0, 6))
        columns = ("port", "protocol", "status", "service", "version", "response", "banner")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        headings = {"port": "Port", "protocol": "Proto", "status": "Status", "service": "Service",
                    "version": "Version", "response": "Resp(ms)", "banner": "Banner"}
        widths = {"port": 55, "protocol": 55, "status": 90, "service": 130,
                  "version": 150, "response": 75, "banner": 260}
        for col in columns:
            self.tree.heading(col, text=headings[col], anchor="w",
                              command=lambda cc=col: self._sort_by(cc))
            self.tree.column(col, width=widths[col], anchor="w")
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y", padx=(6, 0))
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-1>", self._on_row_double_click)

        self.tree.tag_configure("even", background=C["panel"])
        self.tree.tag_configure("odd", background=C["card"])
        for status, color in STATUS_COLOR.items():
            self.tree.tag_configure(status, foreground=color)

        log_frame = ttk.Frame(body, padding=(8, 0, 0, 0))
        ttk.Label(log_frame, text="LIVE ACTIVITY LOG", style="SectionTitle.TLabel").pack(anchor="w",
                                                                                         pady=(0, 6))
        log_box = ttk.Frame(log_frame)
        log_box.pack(fill="both", expand=True)
        self.log_text = tk.Text(
            log_box, width=42, bg=C["panel"], fg=C["fg"], insertbackground=C["accent"],
            font=(MONO, 9), relief="flat", wrap="word", borderwidth=0,
            highlightthickness=0, padx=12, pady=10, spacing1=1, selectbackground=C["accent_dim"],
        )
        log_vsb = ttk.Scrollbar(log_box, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_vsb.set)
        log_vsb.pack(side="right", fill="y", padx=(6, 0))
        self.log_text.pack(side="left", fill="both", expand=True)
        self.log_text.tag_configure("open", foreground=C["accent"])
        self.log_text.tag_configure("closed", foreground=C["muted"])
        self.log_text.tag_configure("filtered", foreground=C["amber"])
        self.log_text.tag_configure("info", foreground=C["white"])
        self.log_text.configure(state="disabled")

        body.add(table_frame, weight=3)
        body.add(log_frame, weight=2)

        self.summary_var = tk.StringVar(value="Enter a target and click Scan to begin.")
        ttk.Separator(root, orient="horizontal").pack(fill="x", pady=(12, 0))
        ttk.Label(root, textvariable=self.summary_var, style="Sub.TLabel").pack(fill="x", pady=(8, 0))

    # ------------------------------------------------------------ 3d tab --

    def _build_3d_tab(self, root):
        top = ttk.Frame(root)
        top.pack(fill="x", pady=(0, 8))
        ttk.Label(top, text="3D SYSTEM VIEW", style="SectionTitle.TLabel").pack(side="left")
        ttk.Label(top, text="   rendered in-app · drag to orbit · scroll to zoom",
                  style="Sub.TLabel").pack(side="left")

        ttk.Button(top, text="⛶ OPEN WEBGL VERSION", command=self.open_3d_view).pack(side="right")
        ttk.Button(top, text="⟳ RESET VIEW",
                   command=lambda: self.scene3d.reset_view()).pack(side="right", padx=(0, 6))

        scene_theme = {
            "bg": C["bg"], "grid": "#1d1b18", "metal": "#3c3c46", "dark": "#232329",
            "part": "#3a3a46", "part_lit": "#575765", "board": "#1f4a30", "heat": "#7c828e",
            "blade": "#2c2c34", "accent": C["accent"], "led": "#ffd0b0",
            "open": C["accent"], "filtered": C["amber"], "closed": "#4a4844",
            "label": "#ffd9c4",
        }
        self.scene3d = viz3d_tk.Scene3D(root, scene_theme)
        self.scene3d.pack(fill="both", expand=True)

        self.scene3d_hint = ttk.Label(
            root, text="Run a scan to populate the port field. The WebGL version "
                       "(browser) adds glass, glow and hover detail.", style="Sub.TLabel")
        self.scene3d_hint.pack(fill="x", pady=(8, 0))

    # -------------------------------------------------------- system tab --

    def _build_system_tab(self, root):
        top = ttk.Frame(root)
        top.pack(fill="x")
        ttk.Label(top, text="THIS MACHINE", style="SectionTitle.TLabel").pack(side="left")
        self.sys_status_var = tk.StringVar(value="Reading specs...")
        ttk.Label(top, textvariable=self.sys_status_var, style="Sub.TLabel").pack(side="right")
        ttk.Button(top, text="⟳ REFRESH", command=self.refresh_system_specs).pack(side="right", padx=(0, 12))

        gauges = ttk.Frame(root)
        gauges.pack(fill="x", pady=(12, 12))
        for i in range(3):
            gauges.columnconfigure(i, weight=1)
        self.gauge_cpu = DotRing(gauges, dots=48, label="CPU LOAD", height=170)
        self.gauge_ram = DotRing(gauges, dots=48, label="MEMORY", height=170)
        self.gauge_disk = DotRing(gauges, dots=48, label="DISK", height=170)
        self.gauge_cpu.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.gauge_ram.grid(row=0, column=1, sticky="nsew", padx=8)
        self.gauge_disk.grid(row=0, column=2, sticky="nsew", padx=(8, 0))

        cards = ttk.Frame(root)
        cards.pack(fill="both", expand=True)
        for i in range(4):
            cards.columnconfigure(i, weight=1)

        self.sys_cards = {}
        layout = [
            ("model", "MODEL"), ("hostname", "HOSTNAME"), ("os", "OPERATING SYSTEM"), ("arch", "ARCHITECTURE"),
            ("cpu", "PROCESSOR"), ("cpu_cores", "CORES / THREADS"), ("gpu", "GRAPHICS"), ("board", "MAINBOARD"),
            ("ram", "MEMORY"), ("disk", "STORAGE"), ("uptime", "UPTIME"), ("python", "PYTHON RUNTIME"),
        ]
        for idx, (key, title) in enumerate(layout):
            card = StatCard(cards, title, "—")
            card.configure(height=90)
            card.grid(row=idx // 4, column=idx % 4, sticky="nsew",
                      padx=(0 if idx % 4 == 0 else 8, 0), pady=(0, 8))
            self.sys_cards[key] = card

    def refresh_system_specs(self):
        self.sys_status_var.set("Reading specs...")
        threading.Thread(target=self._system_specs_worker, daemon=True).start()

    def _system_specs_worker(self):
        try:
            specs = system_info.gather()
        except Exception as exc:  # never let a spec probe kill the app
            specs = {"error": str(exc)}
        self.result_queue.put(("system_specs", specs))

    def _handle_system_specs(self, specs):
        self.specs = specs
        if specs.get("error"):
            self.sys_status_var.set(f"Spec read failed: {specs['error']}")
            return

        def show(key, value):
            self.sys_cards[key].set(value if value not in (None, "") else "—")

        show("model", specs.get("model"))
        show("hostname", specs.get("hostname"))
        show("os", specs.get("os"))
        show("arch", specs.get("arch"))
        show("cpu", specs.get("cpu"))
        show("cpu_cores", specs.get("cpu_cores"))
        show("gpu", specs.get("gpu"))
        show("board", specs.get("board"))
        show("uptime", specs.get("uptime"))
        show("python", specs.get("python"))

        ram_total = specs.get("ram_total_gb")
        ram_avail = specs.get("ram_available_gb")
        if ram_total:
            used = round(ram_total - (ram_avail or 0), 1)
            show("ram", f"{used} / {ram_total} GB")
        else:
            show("ram", None)

        disk_total = specs.get("disk_total_gb")
        if disk_total:
            show("disk", f"{specs.get('disk_used_gb')} / {disk_total} GB")
        else:
            show("disk", None)

        cpu_pct = specs.get("cpu_load_pct")
        ram_pct = specs.get("ram_used_pct")
        disk_pct = specs.get("disk_used_pct")
        self.gauge_cpu.set_value((cpu_pct or 0) / 100, f"{cpu_pct}%" if cpu_pct is not None else "—",
                                  "CPU LOAD")
        self.gauge_ram.set_value((ram_pct or 0) / 100, f"{ram_pct}%" if ram_pct is not None else "—",
                                  "MEMORY USED")
        self.gauge_disk.set_value((disk_pct or 0) / 100, f"{disk_pct}%" if disk_pct is not None else "—",
                                   "DISK USED")
        self.sys_status_var.set(f"Updated {datetime.now().strftime('%H:%M:%S')}")

    # --------------------------------------------------------- recon tab --

    def _build_geo_tab(self, root):
        top = ttk.Frame(root)
        top.pack(fill="x")
        ttk.Label(top, text="TARGET", style="Field.TLabel").pack(side="left", padx=(0, 10))
        ttk.Entry(top, textvariable=self.target_var, width=22).pack(side="left", padx=(6, 12))
        self.geo_btn = ttk.Button(top, text="◎ LOCATE", style="Accent.TButton", command=self.start_geo)
        self.geo_btn.pack(side="left", padx=(0, 6))
        self.geo_map_btn = ttk.Button(top, text="◱ OPEN 3D MAP", command=self.open_geo_map,
                                      state="disabled")
        self.geo_map_btn.pack(side="left")
        self.geo_status_var = tk.StringVar(value="Idle.")
        ttk.Label(top, textvariable=self.geo_status_var, style="Sub.TLabel").pack(side="right")

        cards = ttk.Frame(root, padding=(0, 14, 0, 10))
        cards.pack(fill="x")
        for i in range(4):
            cards.columnconfigure(i, weight=1)
        self.geo_cards = {}
        layout = [
            ("city", "CITY"), ("regionName", "REGION"), ("country", "COUNTRY"), ("coords", "LAT / LON"),
            ("org", "ORGANIZATION"), ("as", "ASN"), ("isp", "ISP"), ("timezone", "TIMEZONE"),
        ]
        for idx, (key, title) in enumerate(layout):
            card = StatCard(cards, title, "—")
            card.configure(height=84)
            card.grid(row=idx // 4, column=idx % 4, sticky="nsew",
                      padx=(0 if idx % 4 == 0 else 8, 0), pady=(0, 8))
            self.geo_cards[key] = card

        note = ("IP geolocation is approximate — it resolves the network/ISP's registered city, "
                "not a street address or building, and private/LAN targets have no public location. "
                "The 3D map's street/building view is a stylized representation of these coordinates. "
                "'LOCATE' makes one outbound lookup (ip-api.com) containing the target IP.")
        ttk.Label(root, text=note, style="Sub.TLabel", wraplength=1100).pack(fill="x", pady=(10, 10))

        ttk.Label(root, text="3D MAP", style="SectionTitle.TLabel").pack(anchor="w")
        ttk.Label(root, text="Opens a browser scene: a geopinned globe, a stylized street/building "
                             "descent, and 3D infrastructure models (your laptop, the target server, "
                             "a data-center row). WebGL — needs a browser.",
                  style="Sub.TLabel", wraplength=1100).pack(fill="x", pady=(6, 0))

    def _build_recon_tab(self, root):
        top = ttk.Frame(root)
        top.pack(fill="x")
        ttk.Label(top, text="TARGET", style="Field.TLabel").pack(side="left", padx=(0, 10))
        ttk.Entry(top, textvariable=self.target_var, width=22).pack(side="left", padx=(6, 12))
        self.recon_btn = ttk.Button(top, text="◎ RUN HOST RECON", style="Accent.TButton",
                                     command=self.start_recon)
        self.recon_btn.pack(side="left", padx=(0, 6))
        self.trace_btn = ttk.Button(top, text="⟶ TRACEROUTE", command=self.start_traceroute)
        self.trace_btn.pack(side="left")
        self.recon_status_var = tk.StringVar(value="Idle.")
        ttk.Label(top, textvariable=self.recon_status_var, style="Sub.TLabel").pack(side="right")

        cards = ttk.Frame(root, padding=(0, 14, 0, 10))
        cards.pack(fill="x")
        for i in range(4):
            cards.columnconfigure(i, weight=1)

        self.rc_status = StatCard(cards, "HOST STATUS", "—")
        self.rc_latency = StatCard(cards, "PING LATENCY", "—")
        self.rc_ttl = StatCard(cards, "TTL", "—")
        self.rc_os = StatCard(cards, "OS GUESS", "—")
        self.rc_status.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=(0, 8))
        self.rc_latency.grid(row=0, column=1, sticky="nsew", padx=8, pady=(0, 8))
        self.rc_ttl.grid(row=0, column=2, sticky="nsew", padx=8, pady=(0, 8))
        self.rc_os.grid(row=0, column=3, sticky="nsew", padx=(8, 0), pady=(0, 8))
        for c in (self.rc_status, self.rc_latency, self.rc_ttl, self.rc_os):
            c.configure(height=84)

        self.rc_mac = StatCard(cards, "MAC ADDRESS", "—")
        self.rc_vendor = StatCard(cards, "VENDOR GUESS", "—")
        self.rc_hostname = StatCard(cards, "HOSTNAME (PTR)", "—")
        self.rc_dns = StatCard(cards, "DNS A/AAAA", "—")
        self.rc_mac.grid(row=1, column=0, sticky="nsew", padx=(0, 8))
        self.rc_vendor.grid(row=1, column=1, sticky="nsew", padx=8)
        self.rc_hostname.grid(row=1, column=2, sticky="nsew", padx=8)
        self.rc_dns.grid(row=1, column=3, sticky="nsew", padx=(8, 0))
        for c in (self.rc_mac, self.rc_vendor, self.rc_hostname, self.rc_dns):
            c.configure(height=84)

        note = ("MAC/vendor lookup only works for hosts on your local subnet, using the OS ARP "
                "cache after a ping. OS/vendor guesses are heuristics, not certainties.")
        ttk.Label(root, text=note, style="Sub.TLabel", wraplength=1100).pack(fill="x", pady=(10, 10))

        ttk.Label(root, text="TRACEROUTE", style="SectionTitle.TLabel").pack(anchor="w")
        trace_frame = ttk.Frame(root)
        trace_frame.pack(fill="both", expand=True, pady=(6, 0))
        columns = ("hop", "ip", "latency")
        self.trace_tree = ttk.Treeview(trace_frame, columns=columns, show="headings", height=10)
        for col, text, width in (("hop", "Hop", 60), ("ip", "IP Address", 200), ("latency", "Latency", 120)):
            self.trace_tree.heading(col, text=text, anchor="w")
            self.trace_tree.column(col, width=width, anchor="w")
        vsb = ttk.Scrollbar(trace_frame, orient="vertical", command=self.trace_tree.yview)
        self.trace_tree.configure(yscrollcommand=vsb.set)
        self.trace_tree.tag_configure("even", background=C["panel"])
        self.trace_tree.tag_configure("odd", background=C["card"])
        self.trace_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

    # --------------------------------------------------------- local tab --

    def _build_local_tab(self, root):
        cards = ttk.Frame(root)
        cards.pack(fill="x")
        self.local_hostname_card = StatCard(cards, "THIS MACHINE'S HOSTNAME", "—")
        self.local_ip_card = StatCard(cards, "PRIMARY IP", "—")
        self.local_hostname_card.configure(height=84)
        self.local_ip_card.configure(height=84)
        self.local_hostname_card.pack(side="left", padx=(0, 8), fill="x", expand=True)
        self.local_ip_card.pack(side="left", padx=(8, 0), fill="x", expand=True)

        ttk.Label(root, text="NETWORK ADAPTERS", style="SectionTitle.TLabel").pack(anchor="w", pady=(14, 6))
        columns = ("name", "ipv4", "mask", "gateway", "mac", "dns")
        self.adapters_tree = ttk.Treeview(root, columns=columns, show="headings", height=12)
        headings = {"name": "Adapter", "ipv4": "IPv4 Address", "mask": "Subnet Mask",
                    "gateway": "Default Gateway", "mac": "MAC Address", "dns": "DNS Servers"}
        widths = {"name": 220, "ipv4": 130, "mask": 130, "gateway": 130, "mac": 150, "dns": 220}
        for col in columns:
            self.adapters_tree.heading(col, text=headings[col], anchor="w")
            self.adapters_tree.column(col, width=widths[col], anchor="w")
        self.adapters_tree.tag_configure("even", background=C["panel"])
        self.adapters_tree.tag_configure("odd", background=C["card"])
        self.adapters_tree.pack(fill="both", expand=True)

    # ------------------------------------------------------------ helpers --

    def _log(self, message, tag="info"):
        self.log_text.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{ts}] {message}\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _sort_by(self, col):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        try:
            items.sort(key=lambda t: float(t[0]))
        except ValueError:
            items.sort(key=lambda t: t[0])
        for index, (_, k) in enumerate(items):
            self.tree.move(k, "", index)

    def _on_row_double_click(self, _event):
        item = self.tree.selection()
        if not item:
            return
        r = self.row_data.get(item[0])
        if not r:
            return

        lines = [
            f"Port: {r['port']}",
            f"Protocol: {r.get('protocol', 'tcp')}",
            f"Status: {r['status']}",
            f"Service: {r['service']}",
            f"Version: {r.get('version') or '(unknown)'}",
        ]
        if r.get("response_ms") is not None:
            lines.append(f"Response time: {r['response_ms']} ms")
        lines.append(f"\nBanner:\n{r.get('banner') or '(none)'}")

        tls = r.get("tls")
        if tls:
            lines.append("\n--- TLS / Certificate ---")
            if tls.get("error"):
                lines.append(f"TLS probe failed: {tls['error']}")
            else:
                lines.append(f"TLS version: {tls.get('tls_version', '?')}")
                lines.append(f"Cipher: {tls.get('cipher', '?')}")
                if tls.get("subject_cn"):
                    lines.append(f"Certificate subject: {tls['subject_cn']}")
                    lines.append(f"Certificate issuer: {tls.get('issuer_cn', '?')}")
                    lines.append(f"Valid from: {tls.get('not_before', '?')}")
                    lines.append(f"Valid until: {tls.get('not_after', '?')}")

        http = r.get("http")
        if http:
            lines.append("\n--- HTTP ---")
            if http.get("error"):
                lines.append(f"HTTP probe failed: {http['error']}")
            else:
                lines.append(f"Status line: {http.get('status_line', '?')}")
                lines.append(f"Server header: {http.get('server') or '(none)'}")
                lines.append(f"Page title: {http.get('title') or '(none)'}")

        messagebox.showinfo(f"Port {r['port']} detail", "\n".join(lines))

    def _refresh_table_visibility(self):
        self.tree.delete(*self.tree.get_children())
        self.row_data.clear()
        for r in self._current_results:
            if r["status"] == "open" or self.verbose_var.get():
                self._insert_row(r)

    def _insert_row(self, r):
        stripe = "even" if len(self.tree.get_children()) % 2 == 0 else "odd"
        item = self.tree.insert("", "end", values=(
            r["port"], r.get("protocol", "tcp"), r["status"], r["service"],
            r.get("version", ""), r.get("response_ms", ""), r.get("banner", ""),
        ), tags=(stripe, r["status"]))
        self.row_data[item] = r

    # -------------------------------------------------------- scan action --

    def start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            return

        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Port Scanner", "Please enter a target IP or hostname.")
            return

        try:
            ports = ps.parse_ports(self.ports_var.get().strip())
        except ValueError as exc:
            messagebox.showerror("Port Scanner", str(exc))
            return
        if not ports:
            messagebox.showerror("Port Scanner", "No ports specified.")
            return

        try:
            ip = ps.resolve_target(target)
        except ValueError as exc:
            messagebox.showerror("Port Scanner", str(exc))
            return

        if ip not in ("127.0.0.1", "::1") and target.lower() != "localhost":
            proceed = messagebox.askyesno(
                "Authorization required",
                f"You are about to scan {target} ({ip}), which is not localhost.\n\n"
                "Port scanning systems you do not own or lack explicit permission to "
                "test may violate the law and the target's acceptable use policy.\n\n"
                "Do you have explicit authorization to scan this target?",
                icon="warning",
            )
            if not proceed:
                self.status_var.set("Scan not authorized.")
                self._log("Scan aborted — authorization declined.", "filtered")
                return

        self.tree.delete(*self.tree.get_children())
        self.row_data.clear()
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self._current_results = []
        self.summary_var.set("")
        self.sparkline.clear()
        self.port_index = {p: i for i, p in enumerate(ports)}
        self.port_grid.reset(ports)

        protocol = self.protocol_var.get()
        passes = ["tcp", "udp"] if protocol == "both" else [protocol]
        self.total_ports = len(ports) * len(passes)
        self.done_ports = 0
        self.open_count = 0
        self.closed_count = 0
        self.filtered_count = 0
        self.progress.configure(maximum=self.total_ports, value=0)
        self.status_var.set(f"Scanning 0/{self.total_ports}...")
        self.progress_ring.set_value(0, "0", f"/ {self.total_ports}")

        self.card_target.set(f"{target}\n({ip})", C["fg"])
        self.card_scanned.set(f"0 / {self.total_ports}")
        self.card_open.set("0")
        self.card_closed.set("0")
        self.card_filtered.set("0")
        self.card_hosts.set("1")
        self.card_elapsed.set("0.0s")

        self.cancel_event.clear()
        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.view3d_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")

        timeout = self.timeout_var.get()
        max_workers = max(1, min(self.threads_var.get(), len(ports)))
        do_banner = self.banner_var.get()
        deep_probe = self.deep_var.get()

        # Rate limiting + randomized order keep the source under IDS/firewall
        # thresholds so the target doesn't rate-limit or block this machine.
        polite = self.polite_var.get()
        rate = 50 if (polite and not self.rate_var.get()) else self.rate_var.get()
        randomize = polite or self.random_var.get()
        rate_note = f", {rate}/s cap" if rate > 0 else ""
        order_note = ", randomized" if randomize else ""

        self._log(f"Starting scan of {target} ({ip}) — {len(ports)} ports x {len(passes)} "
                   f"protocol(s), {max_workers} threads, {timeout}s timeout{rate_note}{order_note}.",
                   "info")

        self.start_time = time.time()
        self.scan_thread = threading.Thread(
            target=self._run_scan_worker,
            args=(ip, ports, timeout, max_workers, do_banner, deep_probe, passes, rate, randomize),
            daemon=True,
        )
        self.scan_thread.start()
        self._tick_elapsed()

    def _run_scan_worker(self, ip, ports, timeout, max_workers, do_banner, deep_probe, passes,
                         rate=0, randomize=False):
        limiter = ps.RateLimiter(rate)
        for protocol in passes:
            if self.cancel_event.is_set():
                break
            scan_ports = list(ports)
            if randomize:
                import random as _random
                _random.shuffle(scan_ports)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                if protocol == "udp":
                    futures = {pool.submit(ps.scan_udp_port, ip, p, timeout, limiter): p
                               for p in scan_ports}
                else:
                    futures = {pool.submit(ps.scan_port, ip, p, timeout, do_banner, deep_probe,
                                           limiter): p
                               for p in scan_ports}
                for future in concurrent.futures.as_completed(futures):
                    if self.cancel_event.is_set():
                        for f in futures:
                            f.cancel()
                        break
                    port = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {"port": port, "protocol": protocol, "status": "error",
                                  "service": "", "banner": str(exc), "version": "", "response_ms": None,
                                  "tls": None, "http": None}
                    self.result_queue.put(("result", result))

        self.result_queue.put(("done", None))

    def stop_scan(self):
        self.cancel_event.set()
        self.status_var.set("Stopping...")
        self._log("Stop requested — finishing in-flight connections...", "filtered")

    def open_3d_view(self):
        if not self._current_results:
            messagebox.showinfo("3D View", "Run a scan first — there's nothing to visualize yet.")
            return
        target = self.target_var.get().strip()
        try:
            ip = ps.resolve_target(target)
        except ValueError:
            ip = target
        try:
            viz3d.open_3d_view(target, ip, list(self._current_results),
                               specs=self.specs, scan_meta=self.scan_meta)
            self._log("Opened 3D system view in your browser.", "info")
        except Exception as exc:
            messagebox.showerror("3D View", f"Couldn't open the 3D view: {exc}")

    def export_3d_view(self):
        """Save a single self-contained .html of the 3D view (Three.js
        embedded) that opens anywhere, offline, with no sibling files."""
        if not self._current_results:
            messagebox.showinfo("Export", "Run a scan first — there's nothing to export yet.")
            return
        target = self.target_var.get().strip()
        try:
            ip = ps.resolve_target(target)
        except ValueError:
            ip = target

        default_name = f"port_scan_3d_{target.replace(':', '_')}.html"
        path = filedialog.asksaveasfilename(
            title="Export 3D view", defaultextension=".html",
            initialfile=default_name, filetypes=[("HTML file", "*.html")])
        if not path:
            return
        try:
            viz3d.export_portable(target, ip, list(self._current_results),
                                  specs=self.specs, scan_meta=self.scan_meta, path=path)
            self._log(f"Exported portable 3D view → {path}", "info")
            messagebox.showinfo("Export", f"Saved a self-contained 3D view to:\n\n{path}")
        except Exception as exc:
            messagebox.showerror("Export", f"Couldn't export the 3D view: {exc}")

    def _tick_elapsed(self):
        if self.scan_thread and self.scan_thread.is_alive():
            elapsed = time.time() - self.start_time
            self.card_elapsed.set(f"{elapsed:.1f}s")
            self.after(200, self._tick_elapsed)

    # ------------------------------------------------------------- recon --

    def start_recon(self):
        if self.recon_thread and self.recon_thread.is_alive():
            return
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Host Recon", "Please enter a target IP or hostname.")
            return
        try:
            ip = ps.resolve_target(target)
        except ValueError as exc:
            messagebox.showerror("Host Recon", str(exc))
            return

        self.recon_btn.configure(state="disabled")
        self.recon_status_var.set("Running recon...")
        for card in (self.rc_status, self.rc_latency, self.rc_ttl, self.rc_os,
                     self.rc_mac, self.rc_vendor, self.rc_hostname, self.rc_dns):
            card.set("…", C["muted"])

        self.recon_thread = threading.Thread(target=self._run_recon_worker, args=(target, ip), daemon=True)
        self.recon_thread.start()

    def _run_recon_worker(self, target, ip):
        ping = net_recon.ping_host(ip)
        mac = net_recon.get_mac_address(ip) if ping["status"] == "online" else None
        vendor = net_recon.guess_vendor(mac) if mac else None
        hostname = net_recon.reverse_dns(ip)
        addrs = net_recon.forward_dns(target)
        self.result_queue.put(("recon_result", {
            "ping": ping, "mac": mac, "vendor": vendor, "hostname": hostname, "addrs": addrs,
        }))

    def _handle_recon_result(self, data):
        ping = data["ping"]
        online = ping["status"] == "online"
        self.rc_status.set(ping["status"].upper(), C["accent"] if online else C["red"])
        self.rc_latency.set(f"{ping['latency_ms']} ms" if ping["latency_ms"] is not None else "—")
        self.rc_ttl.set(ping["ttl"] if ping["ttl"] is not None else "—")
        self.rc_os.set(net_recon.guess_os_from_ttl(ping["ttl"]))
        self.rc_mac.set(data["mac"] or "N/A (off-subnet / no ARP entry)")
        self.rc_vendor.set(data["vendor"] or "—")
        self.rc_hostname.set(data["hostname"] or "(no PTR record)")
        self.rc_dns.set(", ".join(data["addrs"]) if data["addrs"] else "—")
        self.recon_status_var.set(f"Last run: {datetime.now().strftime('%H:%M:%S')}")
        self.recon_btn.configure(state="normal")

    # ------------------------------------------------------------- geo --

    def start_geo(self):
        if self.geo_thread and self.geo_thread.is_alive():
            return
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Geo", "Please enter a target IP or hostname.")
            return
        try:
            ip = ps.resolve_target(target)
        except ValueError as exc:
            messagebox.showerror("Geo", str(exc))
            return
        self.geo_btn.configure(state="disabled")
        self.geo_status_var.set("Locating (ip-api.com)...")
        for card in self.geo_cards.values():
            card.set("…", C["muted"])
        self.geo_thread = threading.Thread(target=self._run_geo_worker, args=(ip,), daemon=True)
        self.geo_thread.start()

    def _run_geo_worker(self, ip):
        geo = geoip.locate(ip)
        self.result_queue.put(("geo_result", geo))

    def _handle_geo_result(self, geo):
        self.geo = geo
        self.geo_btn.configure(state="normal")
        if geo.get("ok"):
            self.geo_cards["city"].set(geo.get("city") or "—", C["accent"])
            self.geo_cards["regionName"].set(geo.get("regionName") or "—")
            self.geo_cards["country"].set(geo.get("country") or "—")
            self.geo_cards["coords"].set(f"{geo.get('lat')}, {geo.get('lon')}")
            self.geo_cards["org"].set(geo.get("org") or geo.get("isp") or "—")
            self.geo_cards["as"].set(geo.get("as") or "—")
            self.geo_cards["isp"].set(geo.get("isp") or "—")
            self.geo_cards["timezone"].set(geo.get("timezone") or "—")
            self.geo_status_var.set(f"Located {datetime.now().strftime('%H:%M:%S')}")
        else:
            msg = "Private / LAN" if geo.get("private") else "Unavailable"
            for k, card in self.geo_cards.items():
                card.set(msg if k == "city" else "—", C["muted"])
            self.geo_status_var.set(geo.get("message", "lookup failed"))
        # the 3D map still works (globe shows 'no geo'); enable it either way
        self.geo_map_btn.configure(state="normal")

    def open_geo_map(self):
        target = self.target_var.get().strip()
        try:
            ip = ps.resolve_target(target)
        except ValueError:
            ip = target
        geo = self.geo or geoip.locate(ip)
        scan = {
            "open": self.open_count, "closed": self.closed_count,
            "filtered": self.filtered_count, "total": self.total_ports,
        }
        try:
            viz_geo.open_geo_view(target, ip, geo, scan=scan, specs=self.specs)
            self._log("Opened 3D geo/infra map in your browser.", "info")
        except Exception as exc:
            messagebox.showerror("3D Map", f"Couldn't open the 3D map: {exc}")

    def start_traceroute(self):
        if self.trace_thread and self.trace_thread.is_alive():
            return
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Traceroute", "Please enter a target IP or hostname.")
            return
        self.trace_tree.delete(*self.trace_tree.get_children())
        self.trace_btn.configure(state="disabled")
        self.recon_status_var.set("Tracing route (this can take up to ~30s)...")
        self.trace_thread = threading.Thread(target=self._run_traceroute_worker, args=(target,), daemon=True)
        self.trace_thread.start()

    def _run_traceroute_worker(self, target):
        result = net_recon.traceroute(target)
        self.result_queue.put(("trace_result", result))

    def _handle_trace_result(self, result):
        self.trace_btn.configure(state="normal")
        if result["error"]:
            self.recon_status_var.set(f"Traceroute failed: {result['error']}")
            return
        for hop in result["hops"]:
            if hop["timeout"]:
                self.trace_tree.insert("", "end", values=(hop["hop"], "* * *", "no response"),
                                       tags=(_stripe(self.trace_tree),))
            else:
                lat = f"{hop['latency_ms']:.1f} ms" if hop["latency_ms"] is not None else "?"
                self.trace_tree.insert("", "end", values=(hop["hop"], hop["ip"], lat),
                                       tags=(_stripe(self.trace_tree),))
        self.recon_status_var.set(f"Traceroute complete — {len(result['hops'])} hop(s).")

    # --------------------------------------------------------- local net --

    def _load_local_network_info(self):
        threading.Thread(target=self._local_net_worker, daemon=True).start()

    def _local_net_worker(self):
        info = net_recon.get_local_network_info()
        self.result_queue.put(("local_net_info", info))

    def _handle_local_net_info(self, info):
        self.local_hostname_card.set(info["hostname"])
        self.local_ip_card.set(info["primary_ip"] or "—")
        for adapter in info["adapters"]:
            self.adapters_tree.insert("", "end", values=(
                adapter["name"], adapter["ipv4"] or "—", adapter["subnet_mask"] or "—",
                adapter["gateway"] or "—", adapter["mac"] or "—",
                ", ".join(adapter["dns_servers"]) if adapter["dns_servers"] else "—",
            ), tags=(_stripe(self.adapters_tree),))

    # -------------------------------------------------------------- queue --

    def _poll_queue(self):
        scan_dirty = False
        try:
            while True:
                kind, payload = self.result_queue.get_nowait()
                if kind == "result":
                    self._handle_result(payload)
                    scan_dirty = True
                elif kind == "done":
                    self._handle_done()
                elif kind == "recon_result":
                    self._handle_recon_result(payload)
                elif kind == "trace_result":
                    self._handle_trace_result(payload)
                elif kind == "local_net_info":
                    self._handle_local_net_info(payload)
                elif kind == "system_specs":
                    self._handle_system_specs(payload)
                elif kind == "geo_result":
                    self._handle_geo_result(payload)
        except queue.Empty:
            pass
        # One draw of the stat cards / ring / sparkline per poll tick instead
        # of once per result: a fast scan drains hundreds of results in a
        # single tick, and only the final state is ever painted anyway.
        if scan_dirty:
            self._flush_scan_ui()
        self.after(60, self._poll_queue)

    def _handle_result(self, r):
        """Accumulate one result. Cheap, per-result work only — the
        expensive full-canvas widget redraws are batched in _flush_scan_ui."""
        self.done_ports += 1
        self._current_results.append(r)
        if len(self._current_results) == 1:
            self.view3d_btn.configure(state="normal")
            self.export_btn.configure(state="normal")

        idx = self.port_index.get(r["port"])
        self.port_grid.mark(idx, r["status"])   # single itemconfig, cheap
        if r.get("response_ms") is not None:
            self.sparkline.add(r["response_ms"], redraw=False)

        if r["status"] == "open":
            self.open_count += 1
            proto_tag = r.get("protocol", "tcp").upper()
            self._log(f"{proto_tag} {r['port']:<6} OPEN     {r['service']}", "open")
            self._insert_row(r)
        elif r["status"] in ("filtered", "open|filtered"):
            self.filtered_count += 1
            if self.verbose_var.get():
                self._insert_row(r)
        else:
            self.closed_count += 1
            if self.verbose_var.get():
                self._insert_row(r)

    def _flush_scan_ui(self):
        """Redraw the live scan widgets once, from the current counters."""
        self.progress.configure(value=self.done_ports)
        self.status_var.set(f"Scanning {self.done_ports}/{self.total_ports}...")
        self.card_scanned.set(f"{self.done_ports} / {self.total_ports}")
        self.card_open.set(self.open_count, C["accent"] if self.open_count else C["fg"])
        self.card_closed.set(self.closed_count)
        self.card_filtered.set(self.filtered_count, C["amber"] if self.filtered_count else C["fg"])
        self.progress_ring.set_value(self.done_ports / max(1, self.total_ports), str(self.done_ports),
                                      f"/ {self.total_ports}")
        self.sparkline.flush()

    def _handle_done(self):
        elapsed = time.time() - self.start_time
        self._flush_scan_ui()   # paint the final counts even if done arrives alone
        self.scene3d.set_results(self._current_results)
        self.scene3d_hint.configure(
            text=f"{self.open_count} open · {self.filtered_count} filtered · "
                 f"{self.total_ports} ports mapped around the tower. "
                 f"The WebGL version (browser) adds glass, glow and hover detail.")
        self.scan_meta = {
            "duration": round(elapsed, 2),
            "finished": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.card_elapsed.set(f"{elapsed:.2f}s")
        self.status_var.set(f"Done in {elapsed:.2f}s")
        self.summary_var.set(
            f"{self.open_count} open · {self.closed_count} closed · {self.filtered_count} filtered "
            f"— {self.total_ports} scan(s) across 1 host in {elapsed:.2f}s."
        )
        self._log(f"Scan complete — {self.open_count} open / {self.total_ports} scanned in {elapsed:.2f}s.",
                   "info")
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")


def main():
    app = PortScannerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
