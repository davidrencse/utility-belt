#!/usr/bin/env python3
"""
A small software 3D renderer that draws straight onto a Tkinter Canvas,
so the 3D system view lives *inside* the dashboard window instead of a
browser.

Tkinter has no WebGL/OpenGL surface, so this does the work by hand:
perspective projection, backface culling, painter's-algorithm depth
sorting and flat shading, drawing the result as filled canvas polygons.
It renders the same scene as viz3d.py — the PC tower plus a field of
port pins — with two deliberate simplifications the canvas can't do:
no transparency (the side panel is simply left open so you can see the
components) and no glow (accents are drawn at full brightness instead).

Item pools: the polygons are created once and then reused every frame by
rewriting their coordinates. Canvas stacking order is creation order, so
writing the depth-sorted faces into the pool in back-to-front order gets
correct occlusion for free — no per-frame tag_raise, no item churn.
"""

import math
import tkinter as tk

LIGHT_DIR = (0.42, 0.80, 0.43)
AMBIENT = 0.34
FOV_DEG = 48.0

# --------------------------------------------------------------- helpers --


def _norm(v):
    length = math.sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]) or 1.0
    return (v[0] / length, v[1] / length, v[2] / length)


def _cross(a, b):
    return (a[1] * b[2] - a[2] * b[1],
            a[2] * b[0] - a[0] * b[2],
            a[0] * b[1] - a[1] * b[0])


def _dot(a, b):
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]


_LIGHT = _norm(LIGHT_DIR)
_shade_cache = {}


def shade(hex_color, factor):
    """Scale a #rrggbb colour by a brightness factor, memoised because a
    redraw asks for the same handful of colour/angle pairs constantly."""
    key = (hex_color, round(factor, 2))
    hit = _shade_cache.get(key)
    if hit:
        return hit
    r = int(hex_color[1:3], 16)
    g = int(hex_color[3:5], 16)
    b = int(hex_color[5:7], 16)
    f = max(0.0, min(1.6, factor))
    out = "#%02x%02x%02x" % (min(255, int(r * f)), min(255, int(g * f)), min(255, int(b * f)))
    _shade_cache[key] = out
    return out


def box_faces(cx, cy, cz, w, h, d, color, emissive=False):
    """Six quads for an axis-aligned box, wound so normals point outward."""
    x0, x1 = cx - w / 2, cx + w / 2
    y0, y1 = cy - h / 2, cy + h / 2
    z0, z1 = cz - d / 2, cz + d / 2
    p = [(x0, y0, z0), (x1, y0, z0), (x1, y1, z0), (x0, y1, z0),
         (x0, y0, z1), (x1, y0, z1), (x1, y1, z1), (x0, y1, z1)]
    quads = [
        (p[4], p[5], p[6], p[7]),   # +Z front
        (p[1], p[0], p[3], p[2]),   # -Z back
        (p[5], p[1], p[2], p[6]),   # +X right
        (p[0], p[4], p[7], p[3]),   # -X left
        (p[3], p[7], p[6], p[2]),   # +Y top
        (p[0], p[1], p[5], p[4]),   # -Y bottom
    ]
    return [{"pts": q, "color": color, "emissive": emissive} for q in quads]


# ----------------------------------------------------------------- scene --

CASE_W, CASE_H, CASE_D = 3.9, 7.5, 7.8


def build_tower(theme):
    """Static geometry for the PC tower. The +X wall is intentionally
    omitted — that is the 'open side panel' the viewer looks through."""
    metal = theme["metal"]
    dark = theme["dark"]
    part = theme["part"]
    part_lit = theme["part_lit"]
    board = theme["board"]
    accent = theme["accent"]
    heat = theme["heat"]

    W, H, D, t = CASE_W, CASE_H, CASE_D, 0.18
    faces = []
    faces += box_faces(0, t / 2, 0, W, t, D, metal)                       # floor
    faces += box_faces(0, H - t / 2, 0, W, t, D, metal)                   # roof
    faces += box_faces(0, H / 2, -D / 2 + t / 2, W, H, t, dark)           # back
    faces += box_faces(-W / 2 + t / 2, H / 2, 0, t, H, D, metal)          # left wall
    faces += box_faces(0, H / 2, D / 2 - t / 2, W, H, t, dark)            # front

    # interior
    faces += box_faces(-W / 2 + 0.55, H * 0.56, -0.3, 0.14, H * 0.62, D * 0.68, board)
    faces += box_faces(0, 0.85, 0, W * 0.84, 1.1, D * 0.84, part)         # psu shroud
    faces += box_faces(0, 1.45, 2.4, W * 0.7, 0.07, 0.09, accent, True)   # shroud strip
    faces += box_faces(0, H - 0.42, -0.3, 0.08, 0.08, D * 0.66, accent, True)

    faces += box_faces(-W / 2 + 1.35, H * 0.72, -0.4, 1.2, 1.5, 1.2, heat)   # cooler
    for i in range(3):
        faces += box_faces(-W / 2 + 1.35, H * 0.72 - 0.45 + i * 0.45, -0.4, 1.25, 0.06, 1.25, heat)

    faces += box_faces(-W / 2 + 1.5, H * 0.42, 0.15, 1.6, 0.55, 3.7, part)   # gpu
    # Light strip on the GPU's outer edge. Kept as a thin sliver on purpose:
    # emissive faces skip shading, so a broad one reads as a flat orange slab.
    faces += box_faces(-W / 2 + 2.28, H * 0.42 + 0.16, 0.15, 0.07, 0.13, 3.2, accent, True)
    for z in (1.15, -0.6):
        faces += box_faces(-W / 2 + 1.5, H * 0.42 + 0.02, z, 0.66, 0.42, 0.66, part_lit)

    for i in range(3):                                                       # ram
        z = -1.5 + i * 0.4
        faces += box_faces(-W / 2 + 0.85, H * 0.7, z, 0.17, 1.25, 0.18, part_lit)
        faces += box_faces(-W / 2 + 0.85, H * 0.7 + 0.66, z, 0.18, 0.08, 0.19, accent, True)

    # front accents + power LED
    faces += box_faces(-W / 2 + 0.14, H / 2, D / 2 + 0.02, 0.08, H * 0.78, 0.05, accent, True)
    faces += box_faces(W / 2 - 0.14, H / 2, D / 2 + 0.02, 0.08, H * 0.78, 0.05, accent, True)
    faces += box_faces(0, H * 0.88, D / 2 + 0.03, 0.16, 0.16, 0.05, theme["led"], True)
    return faces


def fan_faces(cx, cy, cz, radius, angle, color, blades=6):
    """Blades for one front-mounted fan, regenerated each frame."""
    out = []
    for i in range(blades):
        a = angle + (i / blades) * math.tau
        ca, sa = math.cos(a), math.sin(a)
        inner, outer, half = radius * 0.22, radius * 0.92, 0.16
        p1 = (cx + ca * inner - sa * half, cy + sa * inner + ca * half, cz)
        p2 = (cx + ca * outer - sa * half, cy + sa * outer + ca * half, cz)
        p3 = (cx + ca * outer + sa * half, cy + sa * outer - ca * half, cz)
        p4 = (cx + ca * inner + sa * half, cy + sa * inner - ca * half, cz)
        # double: a blade is a flat quad, so whichever way it is wound one
        # side would otherwise be culled and the fan would vanish.
        out.append({"pts": (p1, p2, p3, p4), "color": color, "emissive": False, "double": True})
    return out


def layout_pins(results, max_dots=600):
    """Phyllotaxis spiral around the tower, same idea as the WebGL view."""
    ordered = sorted(results, key=lambda r: r["port"])
    interesting = [r for r in ordered if r["status"] != "closed"]
    closed = [r for r in ordered if r["status"] == "closed"]
    if len(closed) > max_dots:
        step = len(closed) / max_dots
        closed = [closed[int(i * step)] for i in range(max_dots)]

    pins_src = sorted(interesting + closed, key=lambda r: r["port"])
    n = max(1, len(pins_src))
    r_min, r_max = 8.0, min(30.0, 12.0 + math.sqrt(n) * 0.5)
    golden = math.pi * (3 - math.sqrt(5))

    pins = []
    for i, r in enumerate(pins_src):
        frac = (i + 0.5) / n
        radius = r_min + math.sqrt(frac) * (r_max - r_min)
        a = i * golden
        pins.append({
            "x": math.cos(a) * radius,
            "z": math.sin(a) * radius,
            "port": r["port"],
            "status": r["status"],
            "service": r.get("service", "") or "",
            "protocol": r.get("protocol", "tcp"),
            "ms": r.get("response_ms"),
        })
    return pins, r_max


# ---------------------------------------------------------------- widget --

class Scene3D(tk.Canvas):
    def __init__(self, parent, theme, **kwargs):
        super().__init__(parent, highlightthickness=0, bg=theme["bg"], **kwargs)
        self.theme = theme
        self.results = []
        self.pins = []
        self.extent = 20.0

        self.theta = 0.62
        self.phi = 1.02
        self.radius = 30.0
        self.target = (0.0, 3.6, 0.0)
        self.auto_rotate = True

        self._static = build_tower(theme)
        self._angle = 0.0
        self._drag = None
        self._running = True

        # item pools (creation order == stacking order)
        self._grid_items = []
        self._dot_items = []
        self._poly_items = []
        self._orb_items = []
        self._text_items = []

        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<B1-Motion>", self._on_drag)
        self.bind("<ButtonRelease-1>", lambda e: setattr(self, "_drag", None))
        self.bind("<MouseWheel>", self._on_wheel)
        self.bind("<Destroy>", lambda e: setattr(self, "_running", False))

        self.after(40, self._tick)

    # ---- public ----

    def set_results(self, results):
        self.results = list(results or [])
        self.pins, self.extent = layout_pins(self.results)
        self.radius = max(22.0, min(58.0, self.extent * 1.55))

    def reset_view(self):
        self.theta, self.phi = 0.62, 1.02
        self.radius = max(22.0, min(58.0, self.extent * 1.55))
        self.auto_rotate = True

    # ---- interaction ----

    def _on_press(self, event):
        self._drag = (event.x, event.y)
        self.auto_rotate = False

    def _on_drag(self, event):
        if not self._drag:
            return
        dx, dy = event.x - self._drag[0], event.y - self._drag[1]
        self.theta -= dx * 0.008
        self.phi = max(0.18, min(1.45, self.phi - dy * 0.006))
        self._drag = (event.x, event.y)

    def _on_wheel(self, event):
        step = 0.9 if event.delta > 0 else 1.1
        self.radius = max(9.0, min(90.0, self.radius * step))

    # ---- camera ----

    def _camera(self):
        tx, ty, tz = self.target
        sp, cp = math.sin(self.phi), math.cos(self.phi)
        eye = (tx + self.radius * sp * math.cos(self.theta),
               ty + self.radius * cp,
               tz + self.radius * sp * math.sin(self.theta))
        forward = _norm((tx - eye[0], ty - eye[1], tz - eye[2]))
        right = _norm(_cross(forward, (0.0, 1.0, 0.0)))
        up = _cross(right, forward)
        return eye, forward, right, up

    # ---- render loop ----

    def _tick(self):
        if not self._running:
            return
        try:
            if self.winfo_viewable():        # don't burn CPU on a hidden tab
                self._angle += 0.16
                if self.auto_rotate:
                    self.theta += 0.006
                self._render()
        except tk.TclError:
            return
        self.after(45, self._tick)

    def _render(self):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 20 or h < 20:
            return

        eye, fwd, right, up = self._camera()
        focal = (h / 2) / math.tan(math.radians(FOV_DEG) / 2)
        cx, cy = w / 2, h / 2 + h * 0.06

        def to_cam(p):
            v = (p[0] - eye[0], p[1] - eye[1], p[2] - eye[2])
            return (_dot(v, right), _dot(v, up), _dot(v, fwd))

        def project(c):
            if c[2] <= 0.15:
                return None
            return (cx + focal * c[0] / c[2], cy - focal * c[1] / c[2])

        self._draw_grid(to_cam, project)
        self._draw_dots(to_cam, project)
        self._draw_faces(to_cam, project, eye)
        self._draw_orbs(to_cam, project)

    # ---- pooled drawing helpers ----

    def _pool(self, items, factory, needed):
        while len(items) < needed:
            items.append(factory())
        return items

    def _draw_grid(self, to_cam, project):
        span = max(14.0, self.extent + 4)
        step = span / 7.0
        segs = []
        i = -7
        while i <= 7:
            v = i * step
            segs.append(((-span, 0.0, v), (span, 0.0, v)))
            segs.append(((v, 0.0, -span), (v, 0.0, span)))
            i += 1

        self._pool(self._grid_items, lambda: self.create_line(0, 0, 0, 0, fill=self.theme["grid"]),
                   len(segs))
        idx = 0
        for a, b in segs:
            pa, pb = project(to_cam(a)), project(to_cam(b))
            item = self._grid_items[idx]
            if pa and pb:
                self.coords(item, pa[0], pa[1], pb[0], pb[1])
                self.itemconfigure(item, state="normal")
            else:
                self.itemconfigure(item, state="hidden")
            idx += 1
        for item in self._grid_items[idx:]:
            self.itemconfigure(item, state="hidden")

    def _draw_dots(self, to_cam, project):
        dots = [p for p in self.pins if p["status"] == "closed"]
        self._pool(self._dot_items,
                   lambda: self.create_oval(0, 0, 0, 0, fill=self.theme["closed"], outline=""),
                   len(dots))
        idx = 0
        for p in dots:
            c = to_cam((p["x"], 0.05, p["z"]))
            pt = project(c)
            item = self._dot_items[idx]
            if pt:
                r = max(0.8, 26.0 / max(2.0, c[2]))
                self.coords(item, pt[0] - r, pt[1] - r, pt[0] + r, pt[1] + r)
                self.itemconfigure(item, state="normal")
            else:
                self.itemconfigure(item, state="hidden")
            idx += 1
        for item in self._dot_items[idx:]:
            self.itemconfigure(item, state="hidden")

    def _draw_faces(self, to_cam, project, eye):
        faces = list(self._static)
        # spinning front fans
        faces += fan_faces(-0.2, CASE_H * 0.33, CASE_D / 2 + 0.06, 0.72,
                           self._angle, self.theme["blade"])
        faces += fan_faces(-0.2, CASE_H * 0.63, CASE_D / 2 + 0.06, 0.72,
                           -self._angle * 0.85, self.theme["blade"])

        # port beams as camera-facing billboards so they read as solid bars
        _, _, right, _ = self._camera()
        for p in self.pins:
            if p["status"] == "closed":
                continue
            is_open = p["status"] == "open"
            height = 4.2 if is_open else 1.8
            half = 0.09 if is_open else 0.06
            ox, oz = right[0] * half, right[2] * half
            x, z = p["x"], p["z"]
            faces.append({
                "pts": ((x - ox, 0.0, z - oz), (x + ox, 0.0, z + oz),
                        (x + ox, height, z + oz), (x - ox, height, z - oz)),
                "color": self.theme["open"] if is_open else self.theme["filtered"],
                "emissive": True,
            })

        drawn = []
        for f in faces:
            cam_pts = [to_cam(p) for p in f["pts"]]
            if any(c[2] <= 0.15 for c in cam_pts):
                continue
            if not f["emissive"]:
                a, b, c = f["pts"][0], f["pts"][1], f["pts"][2]
                normal = _norm(_cross((b[0] - a[0], b[1] - a[1], b[2] - a[2]),
                                      (c[0] - b[0], c[1] - b[1], c[2] - b[2])))
                view = (a[0] - eye[0], a[1] - eye[1], a[2] - eye[2])
                facing = _dot(normal, view)
                double = f.get("double")
                if facing > 0 and not double:      # backface
                    continue
                incidence = _dot(normal, _LIGHT)
                if double:
                    incidence = abs(incidence)
                lit = AMBIENT + (1.0 - AMBIENT) * max(0.0, incidence)
                color = shade(f["color"], lit)
            else:
                color = f["color"]
            depth = sum(c[2] for c in cam_pts) / len(cam_pts)
            screen = [project(c) for c in cam_pts]
            if any(s is None for s in screen):
                continue
            drawn.append((depth, screen, color))

        drawn.sort(key=lambda item: -item[0])   # far to near

        self._pool(self._poly_items,
                   lambda: self.create_polygon(0, 0, 0, 0, 0, 0, fill="", outline=""),
                   len(drawn))
        for i, (_, screen, color) in enumerate(drawn):
            flat = []
            for sx, sy in screen:
                flat.extend((sx, sy))
            item = self._poly_items[i]
            self.coords(item, *flat)
            self.itemconfigure(item, fill=color, state="normal")
        for item in self._poly_items[len(drawn):]:
            self.itemconfigure(item, state="hidden")

    def _draw_orbs(self, to_cam, project):
        live = [p for p in self.pins if p["status"] != "closed"]
        self._pool(self._orb_items,
                   lambda: self.create_oval(0, 0, 0, 0, fill=self.theme["open"], outline=""),
                   len(live))
        labels = [p for p in live if p["status"] == "open"][:14]
        self._pool(self._text_items,
                   lambda: self.create_text(0, 0, text="", fill=self.theme["label"],
                                            font=("Consolas", 8, "bold")),
                   len(labels))

        pulse = 1.0 + math.sin(self._angle * 0.9) * 0.12
        for i, p in enumerate(live):
            is_open = p["status"] == "open"
            height = 4.2 if is_open else 1.8
            c = to_cam((p["x"], height + 0.25, p["z"]))
            pt = project(c)
            item = self._orb_items[i]
            if pt:
                base = 46.0 if is_open else 26.0
                r = max(1.5, base / max(2.0, c[2])) * (pulse if is_open else 1.0)
                self.coords(item, pt[0] - r, pt[1] - r, pt[0] + r, pt[1] + r)
                self.itemconfigure(item, state="normal",
                                   fill=self.theme["open"] if is_open else self.theme["filtered"])
            else:
                self.itemconfigure(item, state="hidden")
        for item in self._orb_items[len(live):]:
            self.itemconfigure(item, state="hidden")

        for i, p in enumerate(labels):
            pt = project(to_cam((p["x"], 4.2 + 0.85, p["z"])))
            item = self._text_items[i]
            if pt:
                text = f"{p['port']} {p['service'][:12]}".strip()
                self.coords(item, pt[0], pt[1])
                self.itemconfigure(item, text=text, state="normal")
            else:
                self.itemconfigure(item, state="hidden")
        for item in self._text_items[len(labels):]:
            self.itemconfigure(item, state="hidden")
