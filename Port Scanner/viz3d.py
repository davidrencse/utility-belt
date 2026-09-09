#!/usr/bin/env python3
"""
Builds a standalone Three.js visualization of this machine plus the
results of a port scan.

The scene renders an actual 3D PC tower — case panels, tempered-glass
side, motherboard, GPU, RAM sticks, CPU cooler, spinning case fans,
power LED — standing in a field of port pins laid out in a phyllotaxis
spiral: open ports rise as glowing orange beams with orbs and labels,
filtered ports as shorter amber beams, closed ports as a dim dot field.
This machine's real specs (CPU, GPU, RAM, disk, OS, uptime) are read by
system_info.py and shown in the HUD.

Three.js is vendored at ./vendor/three.min.js and copied next to the
generated HTML so the page works fully offline; if that file is missing
the page falls back to loading Three.js from cdnjs.
"""

import json
import math
import os
import shutil
import tempfile
import webbrowser

VENDOR_THREE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor", "three.min.js")
THREE_CDN = "https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"

MAX_PINS = 3000
STATUS_PRIORITY = {"closed": 1, "filtered": 2, "open|filtered": 2, "error": 2, "open": 3}


def _layout_ports(results):
    """Spread every scanned port over a phyllotaxis spiral around the
    tower, so density stays even and open ports never overlap the case."""
    ordered = sorted(results, key=lambda r: (r["port"], r.get("protocol", "tcp")))

    # Keep every interesting port; thin out closed ones if there are a lot.
    interesting = [r for r in ordered if r["status"] != "closed"]
    closed = [r for r in ordered if r["status"] == "closed"]
    budget = max(0, MAX_PINS - len(interesting))
    if len(closed) > budget and budget > 0:
        step = len(closed) / budget
        closed = [closed[int(i * step)] for i in range(budget)]
    elif budget <= 0:
        closed = []

    pins_src = sorted(interesting + closed, key=lambda r: r["port"])
    n = max(1, len(pins_src))

    r_min = 7.5
    r_max = min(30.0, 11.0 + math.sqrt(n) * 0.46)
    golden = math.pi * (3 - math.sqrt(5))

    pins = []
    for i, r in enumerate(pins_src):
        t = (i + 0.5) / n
        radius = r_min + math.sqrt(t) * (r_max - r_min)
        angle = i * golden
        status = r["status"] if r["status"] in STATUS_PRIORITY else "closed"
        pins.append({
            "x": round(math.cos(angle) * radius, 3),
            "z": round(math.sin(angle) * radius, 3),
            "port": r["port"],
            "protocol": r.get("protocol", "tcp"),
            "status": status,
            "service": r.get("service", "") or "",
            "version": (r.get("version") or "")[:48],
            "ms": r.get("response_ms"),
        })
    return pins, r_max


_HTML = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>__TARGET__ — 3D System &amp; Port View</title>
<style>
  :root {
    --bg:#040404; --panel:rgba(12,12,13,0.82); --border:#26241f;
    --fg:#f4f2ec; --muted:#8a877f; --dim:#403d38; --accent:#ff5a1f; --amber:#d68a2e;
  }
  html,body { margin:0; padding:0; height:100%; background:var(--bg); color:var(--fg);
              font-family:Consolas,"Courier New",monospace; overflow:hidden; }
  #scene { display:block; width:100vw; height:100vh; cursor:grab; }
  #scene:active { cursor:grabbing; }
  .overlay { position:fixed; pointer-events:none; }
  #topbar { top:0; left:0; right:0; padding:16px 20px; display:flex;
            justify-content:space-between; align-items:flex-start; }
  .brand { font-size:15px; font-weight:bold; letter-spacing:2px; }
  .brand .dot { color:var(--accent); }
  .sub { font-size:11px; color:var(--muted); margin-top:4px; letter-spacing:.5px; }
  #counters { display:flex; gap:22px; text-align:right; }
  #counters .n { font-size:20px; font-weight:bold; line-height:1; }
  #counters .l { font-size:9px; color:var(--muted); letter-spacing:1.5px; margin-top:5px; }
  .panel { background:var(--panel); border:1px solid var(--border); border-radius:10px;
           padding:12px 14px; backdrop-filter:blur(3px); width:290px; }
  .panel h2 { margin:0 0 10px; font-size:9px; letter-spacing:2px; color:var(--accent);
              font-weight:bold; }
  .row { display:flex; justify-content:space-between; gap:10px; padding:3px 0; font-size:11px; }
  .row .k { color:var(--muted); white-space:nowrap; }
  .row .v { color:var(--fg); text-align:right; overflow:hidden; text-overflow:ellipsis;
            white-space:nowrap; max-width:190px; }
  .bar { height:4px; background:#1a1917; border-radius:2px; margin:5px 0 9px; overflow:hidden; }
  .bar i { display:block; height:100%; background:var(--accent); }
  #left { left:20px; top:96px; }
  #right { right:20px; top:96px; }
  #ports { margin-top:8px; max-height:38vh; overflow-y:auto; pointer-events:auto; }
  #ports::-webkit-scrollbar { width:5px; }
  #ports::-webkit-scrollbar-thumb { background:#2e2b26; border-radius:3px; }
  .pline { display:flex; justify-content:space-between; font-size:11px; padding:3px 0;
           border-bottom:1px solid #171614; }
  .pline .p { color:var(--accent); font-weight:bold; }
  .pline .s { color:var(--muted); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
              max-width:150px; text-align:right; }
  #legend { bottom:16px; left:20px; display:flex; gap:18px; font-size:11px; color:#cfcdc6; }
  .sw { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:6px;
        vertical-align:middle; }
  #hint { bottom:16px; right:20px; font-size:10px; color:#4a4844; letter-spacing:1px; }
  #tip { position:fixed; display:none; background:#0c0c0d; border:1px solid var(--border);
         border-radius:6px; padding:8px 10px; font-size:11px; white-space:nowrap; z-index:9; }
  #tip .p { color:var(--accent); font-weight:bold; }
  #fallback { position:fixed; inset:0; display:none; align-items:center; justify-content:center;
              text-align:center; padding:40px; font-size:13px; color:var(--muted); }
</style>
</head>
<body>
<canvas id="scene"></canvas>

<div class="overlay" id="topbar">
  <div>
    <div class="brand"><span class="dot">●</span> SYSTEM // PORT SCAN — 3D VIEW</div>
    <div class="sub" id="subtitle"></div>
  </div>
  <div id="counters"></div>
</div>

<div class="overlay panel" id="left"></div>
<div class="overlay panel" id="right"></div>

<div class="overlay" id="legend">
  <span><span class="sw" style="background:#ff5a1f"></span>Open</span>
  <span><span class="sw" style="background:#d68a2e"></span>Filtered</span>
  <span><span class="sw" style="background:#4a4844"></span>Closed</span>
</div>
<div class="overlay" id="hint">drag to orbit · scroll to zoom · hover a beam for detail</div>
<div id="tip"></div>
<div id="fallback">Three.js could not be loaded.<br><br>
  Expected <code>three.min.js</code> next to this file, or an internet connection for the CDN.</div>

<script src="three.min.js"></script>
<script>
if (typeof THREE === 'undefined') {
  document.write('<scr' + 'ipt src="__THREE_CDN__"><\/scr' + 'ipt>');
}
</script>
<script>
const DATA = __DATA_JSON__;

/* ------------------------------------------------------------------ HUD */
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}
function row(k, v) {
  return v == null || v === '' ? '' :
    `<div class="row"><span class="k">${esc(k)}</span><span class="v" title="${esc(v)}">${esc(v)}</span></div>`;
}
function bar(pct) {
  return pct == null ? '' : `<div class="bar"><i style="width:${Math.max(2, Math.min(100, pct))}%"></i></div>`;
}

function buildHUD() {
  const s = DATA.specs || {};
  const scan = DATA.scan;

  document.getElementById('subtitle').textContent =
    `${DATA.target} (${DATA.ip})   ·   ${s.hostname || ''} ${s.model ? '· ' + s.model : ''}`;

  document.getElementById('counters').innerHTML = [
    ['#ff5a1f', scan.open, 'OPEN'],
    ['#8a877f', scan.closed, 'CLOSED'],
    ['#d68a2e', scan.filtered, 'FILTERED'],
    ['#f4f2ec', scan.total, 'SCANNED'],
  ].map(([c, n, l]) =>
    `<div><div class="n" style="color:${c}">${n}</div><div class="l">${l}</div></div>`).join('');

  document.getElementById('left').innerHTML =
    '<h2>THIS MACHINE</h2>'
    + row('MODEL', s.model) + row('HOST', s.hostname) + row('OS', s.os)
    + row('CPU', s.cpu) + row('CORES', s.cpu_cores)
    + (s.cpu_load_pct != null ? row('CPU LOAD', s.cpu_load_pct + '%') + bar(s.cpu_load_pct) : '')
    + row('GPU', s.gpu)
    + (s.ram_total_gb ? row('MEMORY', `${(s.ram_total_gb - (s.ram_available_gb || 0)).toFixed(1)} / ${s.ram_total_gb} GB`) + bar(s.ram_used_pct) : '')
    + (s.disk_total_gb ? row('DISK', `${s.disk_used_gb} / ${s.disk_total_gb} GB`) + bar(s.disk_used_pct) : '')
    + row('UPTIME', s.uptime) + row('ARCH', s.arch);

  const openPorts = DATA.pins.filter(p => p.status === 'open');
  const others = DATA.pins.filter(p => p.status !== 'open' && p.status !== 'closed');
  const list = openPorts.concat(others).slice(0, 60).map(p =>
    `<div class="pline"><span class="p">${p.port}<span style="color:#4a4844">/${esc(p.protocol)}</span></span>`
    + `<span class="s" title="${esc(p.service + (p.version ? ' — ' + p.version : ''))}">${esc(p.version || p.service || '')}</span></div>`
  ).join('') || '<div class="row"><span class="k">no open ports found</span></div>';

  document.getElementById('right').innerHTML =
    '<h2>SCAN RESULT</h2>'
    + row('TARGET', DATA.target) + row('ADDRESS', DATA.ip)
    + row('PORTS SCANNED', scan.total) + row('PROTOCOLS', scan.protocols)
    + row('DURATION', scan.duration != null ? scan.duration.toFixed(2) + ' s' : null)
    + row('FINISHED', scan.finished)
    + '<h2 style="margin-top:12px">OPEN / FILTERED</h2><div id="ports">' + list + '</div>';
}
buildHUD();

/* --------------------------------------------------------------- SCENE */
if (typeof THREE === 'undefined') {
  document.getElementById('fallback').style.display = 'flex';
} else {
  boot();
}

function boot() {
  const canvas = document.getElementById('scene');
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  // sRGB output + deliberately dark authored colors: the gamma curve gives
  // the orange accents their punch without washing the case into pastel.
  renderer.outputEncoding = THREE.sRGBEncoding;

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x040404);
  scene.fog = new THREE.Fog(0x040404, 34, 96);

  const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 400);
  const target = new THREE.Vector3(0, 3.2, 0);
  // theta favours the +X side so the glass panel (and the internals behind
  // it) faces the viewer on load, with the front panel at a three-quarter angle.
  let camR = Math.min(44, Math.max(21, DATA.extent * 1.4)), camTheta = 0.45, camPhi = 0.95;
  let userMoved = false;

  function place() {
    camera.position.set(
      target.x + camR * Math.sin(camPhi) * Math.cos(camTheta),
      target.y + camR * Math.cos(camPhi),
      target.z + camR * Math.sin(camPhi) * Math.sin(camTheta));
    camera.lookAt(target);
  }
  function resize() {
    const w = window.innerWidth, h = window.innerHeight;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  window.addEventListener('resize', resize);
  resize(); place();

  /* ---- lights ---- */
  scene.add(new THREE.AmbientLight(0x2a2d36, 0.5));
  const key = new THREE.DirectionalLight(0xdfe6ff, 0.42); key.position.set(8, 14, 9); scene.add(key);
  const rim = new THREE.DirectionalLight(0xff5a1f, 0.4); rim.position.set(-9, 5, -7); scene.add(rim);
  // Tight interior pools only — the emissive strips supply most of the
  // visible glow, which keeps the case from blowing out into a lit box.
  // Ranges are kept short on purpose: there are no shadows here, so a
  // long-range interior light also lights the outside of the roof.
  const inner = new THREE.PointLight(0xff7a3a, 1.15, 5.5); inner.position.set(0.9, 3.1, 0.4); scene.add(inner);
  const inner2 = new THREE.PointLight(0xa8c4ff, 0.35, 5); inner2.position.set(1.0, 2.2, -0.4); scene.add(inner2);
  const under = new THREE.PointLight(0xff5a1f, 0.45, 5); under.position.set(0, 0.35, 0); scene.add(under);

  /* ---- floor ---- */
  const grid = new THREE.GridHelper(DATA.extent * 2.6, Math.round(DATA.extent * 2.6 / 2), 0x33302b, 0x171614);
  grid.material.transparent = true; grid.material.opacity = 0.5;
  scene.add(grid);

  /* ---- materials ---- */
  const matCase = new THREE.MeshStandardMaterial({ color: 0x131317, metalness: 0.86, roughness: 0.42 });
  const matCaseDark = new THREE.MeshStandardMaterial({ color: 0x0b0b0e, metalness: 0.6, roughness: 0.6 });
  // depthWrite:false keeps the glass from occluding the components behind it
  const matGlass = new THREE.MeshStandardMaterial({
    color: 0x8ea0b4, metalness: 0.0, roughness: 0.5, transparent: true, opacity: 0.08,
    depthWrite: false, side: THREE.DoubleSide,
  });
  // interior parts need to be light enough to actually read through the glass
  // Very dark base colors: sRGB output lifts them into a readable, moody
  // range, and a trace of emissive keeps parts visible through the glass.
  const matPart = new THREE.MeshStandardMaterial({
    color: 0x16161c, metalness: 0.55, roughness: 0.55, emissive: 0x08080c });
  const matPartLight = new THREE.MeshStandardMaterial({
    color: 0x282830, metalness: 0.5, roughness: 0.5, emissive: 0x0d0d13 });
  const matBoard = new THREE.MeshStandardMaterial({
    color: 0x0d2415, metalness: 0.3, roughness: 0.75, emissive: 0x06140b });
  const matHeat = new THREE.MeshStandardMaterial({ color: 0x4a4e57, metalness: 0.95, roughness: 0.3 });
  const matBlade = new THREE.MeshStandardMaterial({ color: 0x1b1b20, metalness: 0.4, roughness: 0.7 });
  const matAccent = new THREE.MeshBasicMaterial({ color: 0xff5a1f });
  const matAccentDim = new THREE.MeshBasicMaterial({ color: 0x8f3210 });

  function box(w, h, d, x, y, z, mat) {
    const m = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), mat);
    m.position.set(x, y, z);
    return m;
  }

  function glowTexture() {
    const c = document.createElement('canvas'); c.width = c.height = 128;
    const g = c.getContext('2d').createRadialGradient(64, 64, 0, 64, 64, 64);
    g.addColorStop(0, 'rgba(255,150,90,0.95)');
    g.addColorStop(0.35, 'rgba(255,90,31,0.45)');
    g.addColorStop(1, 'rgba(255,90,31,0)');
    const x = c.getContext('2d'); x.fillStyle = g; x.fillRect(0, 0, 128, 128);
    return new THREE.CanvasTexture(c);
  }
  const GLOW = glowTexture();

  function grillTexture() {
    const c = document.createElement('canvas'); c.width = c.height = 256;
    const x = c.getContext('2d');
    x.fillStyle = '#0a0a0c'; x.fillRect(0, 0, 256, 256);
    x.fillStyle = '#191920';
    for (let i = 9; i < 256; i += 13)
      for (let j = 9; j < 256; j += 13) { x.beginPath(); x.arc(i, j, 3.2, 0, 6.3); x.fill(); }
    return new THREE.CanvasTexture(c);
  }

  function label(text, color) {
    const pad = 12, size = 44;
    const c = document.createElement('canvas');
    let x = c.getContext('2d');
    x.font = `bold ${size}px Consolas, monospace`;
    const w = Math.ceil(x.measureText(text).width) + pad * 2;
    c.width = w; c.height = Math.round(size * 1.6);
    x = c.getContext('2d');
    x.font = `bold ${size}px Consolas, monospace`;
    x.fillStyle = color || '#f4f2ec';
    x.textBaseline = 'middle';
    x.fillText(text, pad, c.height / 2);
    const sp = new THREE.Sprite(new THREE.SpriteMaterial({
      map: new THREE.CanvasTexture(c), transparent: true, depthWrite: false,
    }));
    sp.scale.set((c.width / c.height) * 0.5, 0.5, 1);
    return sp;
  }

  /* ---- the PC tower ---- */
  const fans = [];
  function makeFan(r) {
    const g = new THREE.Group();
    g.add(new THREE.Mesh(new THREE.TorusGeometry(r, 0.05, 8, 28), matAccentDim));
    const hub = new THREE.Mesh(new THREE.CylinderGeometry(r * 0.2, r * 0.2, 0.1, 14), matCaseDark);
    hub.rotation.x = Math.PI / 2; g.add(hub);
    const blades = new THREE.Group();
    for (let i = 0; i < 7; i++) {
      const b = new THREE.Mesh(new THREE.BoxGeometry(r * 0.78, 0.022, 0.2), matBlade);
      const a = (i / 7) * Math.PI * 2;
      b.position.set(Math.cos(a) * r * 0.44, Math.sin(a) * r * 0.44, 0);
      b.rotation.z = a + 0.5;
      blades.add(b);
    }
    g.add(blades);
    fans.push(blades);
    return g;
  }

  function buildTower() {
    const g = new THREE.Group();
    const W = 2.9, H = 5.6, D = 5.8, t = 0.14;

    g.add(box(W, t, D, 0, t / 2, 0, matCase));                       // floor
    g.add(box(W, t, D, 0, H - t / 2, 0, matCase));                   // roof
    g.add(box(W, H, t, 0, H / 2, -D / 2 + t / 2, matCaseDark));      // back
    g.add(box(t, H, D, -W / 2 + t / 2, H / 2, 0, matCase));          // left wall

    const front = box(W, H, t, 0, H / 2, D / 2 - t / 2, new THREE.MeshStandardMaterial({
      map: grillTexture(), metalness: 0.5, roughness: 0.75,
    }));
    g.add(front);

    const glass = box(t * 0.4, H * 0.93, D * 0.93, W / 2 - t / 2, H / 2, 0, matGlass);
    g.add(glass);

    // interior
    g.add(box(0.1, H * 0.64, D * 0.7, -W / 2 + 0.42, H * 0.56, -0.25, matBoard));   // motherboard
    g.add(box(W * 0.84, 0.85, D * 0.84, 0, 0.62, 0, matPart));                      // psu shroud
    g.add(box(W * 0.8, 0.04, 0.06, 0, 1.06, 1.9, matAccent));                       // shroud light strip
    g.add(box(0.05, 0.05, D * 0.72, 0, H - 0.3, -0.2, matAccent));                  // interior top strip

    const cooler = box(0.95, 1.15, 0.95, -W / 2 + 1.05, H * 0.72, -0.3, matHeat);
    g.add(cooler);
    for (let i = 0; i < 7; i++) {   // heatsink fins
      g.add(box(0.98, 0.035, 0.98, -W / 2 + 1.05, H * 0.72 - 0.5 + i * 0.17, -0.3, matHeat));
    }
    const cpuFan = makeFan(0.4);
    cpuFan.rotation.y = Math.PI / 2;
    cpuFan.position.set(-W / 2 + 1.6, H * 0.72, -0.3);
    g.add(cpuFan);

    const gpu = box(1.25, 0.42, 2.9, -W / 2 + 1.15, H * 0.42, 0.1, matPart);
    g.add(gpu);
    g.add(box(1.26, 0.05, 2.5, -W / 2 + 1.15, H * 0.42 + 0.24, 0.1, matAccent));    // gpu light bar
    g.add(box(0.5, 0.34, 0.5, -W / 2 + 1.15, H * 0.42 - 0.02, 0.9, matPartLight));  // gpu fan hub
    g.add(box(0.5, 0.34, 0.5, -W / 2 + 1.15, H * 0.42 - 0.02, -0.5, matPartLight));

    for (let i = 0; i < 4; i++) {                                                   // ram
      const z = -1.15 + i * 0.3;
      g.add(box(0.13, 0.95, 0.14, -W / 2 + 0.62, H * 0.7, z, matPartLight));
      g.add(box(0.14, 0.06, 0.15, -W / 2 + 0.62, H * 0.7 + 0.5, z, matAccent));
    }

    const f1 = makeFan(0.56); f1.position.set(0.1, H * 0.33, D / 2 - 0.22); g.add(f1);
    const f2 = makeFan(0.56); f2.position.set(0.1, H * 0.63, D / 2 - 0.22); g.add(f2);
    const f3 = makeFan(0.5); f3.rotation.x = -Math.PI / 2; f3.position.set(0.1, H - 0.2, -0.4); g.add(f3);

    // front accents + power LED
    g.add(box(0.06, H * 0.8, 0.06, -W / 2 + 0.1, H / 2, D / 2 - 0.02, matAccent));
    g.add(box(0.06, H * 0.8, 0.06, W / 2 - 0.1, H / 2, D / 2 - 0.02, matAccent));
    const led = new THREE.Mesh(new THREE.CylinderGeometry(0.075, 0.075, 0.07, 16), matAccent);
    led.rotation.x = Math.PI / 2;
    led.position.set(0, H * 0.9, D / 2 + 0.01);
    g.add(led);

    const halo = new THREE.Sprite(new THREE.SpriteMaterial({
      map: GLOW, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false, opacity: 0.75,
    }));
    halo.scale.set(1.4, 1.4, 1); halo.position.set(0, H * 0.9, D / 2 + 0.12);
    g.add(halo);

    // pedestal ring
    const ring = new THREE.Mesh(new THREE.TorusGeometry(D * 0.62, 0.035, 8, 64), matAccentDim);
    ring.rotation.x = Math.PI / 2; ring.position.y = 0.02;
    g.add(ring);

    return g;
  }
  const tower = buildTower();
  tower.scale.setScalar(1.35);
  scene.add(tower);
  window.__viz = { scene, camera, renderer, tower };

  /* ---- port field ---- */
  const pickables = [];
  const pulsers = [];

  const closedPts = [];
  DATA.pins.forEach(p => { if (p.status === 'closed') closedPts.push(p.x, 0.03, p.z); });
  if (closedPts.length) {
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.Float32BufferAttribute(closedPts, 3));
    scene.add(new THREE.Points(geo, new THREE.PointsMaterial({
      color: 0x4a4844, size: 0.17, sizeAttenuation: true, transparent: true, opacity: 0.85,
    })));
  }

  const linkPts = [];
  let labelled = 0;
  DATA.pins.filter(p => p.status !== 'closed').forEach(p => {
    const isOpen = p.status === 'open';
    const color = isOpen ? 0xff5a1f : 0xd68a2e;
    const h = isOpen ? 3.0 : 1.2;
    const mat = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: isOpen ? 0.9 : 0.6 });

    const beam = new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.05, h, 8), mat);
    beam.position.set(p.x, h / 2, p.z);
    beam.userData = p;
    scene.add(beam);
    pickables.push(beam);

    const orb = new THREE.Mesh(new THREE.SphereGeometry(isOpen ? 0.22 : 0.13, 18, 14),
      new THREE.MeshBasicMaterial({ color }));
    orb.position.set(p.x, h + 0.22, p.z);
    orb.userData = p;
    scene.add(orb);
    pickables.push(orb);

    const halo = new THREE.Sprite(new THREE.SpriteMaterial({
      map: GLOW, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false,
      opacity: isOpen ? 0.85 : 0.5,
    }));
    const hs = isOpen ? 1.7 : 1.0;
    halo.scale.set(hs, hs, 1);
    halo.position.copy(orb.position);
    scene.add(halo);
    pulsers.push({ orb, halo, base: hs, phase: Math.random() * 6.28 });

    const ring = new THREE.Mesh(new THREE.TorusGeometry(0.3, 0.018, 6, 24),
      new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.55 }));
    ring.rotation.x = Math.PI / 2;
    ring.position.set(p.x, 0.02, p.z);
    scene.add(ring);

    if (isOpen && labelled < 40) {
      const text = `${p.port} ${(p.service || '').slice(0, 14)}`.trim();
      const sp = label(text, '#ffd9c4');
      sp.position.set(p.x, h + 0.75, p.z);
      scene.add(sp);
      labelled++;
      linkPts.push(0, 4.2, 0, p.x, h + 0.22, p.z);
    }
  });

  if (linkPts.length) {
    const lg = new THREE.BufferGeometry();
    lg.setAttribute('position', new THREE.Float32BufferAttribute(linkPts, 3));
    scene.add(new THREE.LineSegments(lg, new THREE.LineBasicMaterial({
      color: 0xff5a1f, transparent: true, opacity: 0.18,
    })));
  }

  /* ---- interaction ---- */
  let dragging = false, lastX = 0, lastY = 0;
  canvas.addEventListener('mousedown', e => { dragging = true; userMoved = true; lastX = e.clientX; lastY = e.clientY; });
  window.addEventListener('mouseup', () => { dragging = false; });
  window.addEventListener('mousemove', e => {
    if (dragging) {
      camTheta -= (e.clientX - lastX) * 0.006;
      camPhi = Math.max(0.12, Math.min(1.48, camPhi - (e.clientY - lastY) * 0.005));
      lastX = e.clientX; lastY = e.clientY;
      place();
    }
    hover(e.clientX, e.clientY);
  });
  canvas.addEventListener('wheel', e => {
    userMoved = true;
    camR = Math.max(7, Math.min(DATA.extent * 4 + 40, camR * (e.deltaY > 0 ? 1.08 : 0.92)));
    place();
    e.preventDefault();
  }, { passive: false });

  const ray = new THREE.Raycaster();
  const mouse = new THREE.Vector2();
  const tip = document.getElementById('tip');
  function hover(mx, my) {
    mouse.x = (mx / window.innerWidth) * 2 - 1;
    mouse.y = -(my / window.innerHeight) * 2 + 1;
    ray.setFromCamera(mouse, camera);
    const hit = ray.intersectObjects(pickables, false)[0];
    if (hit) {
      const p = hit.object.userData;
      tip.style.display = 'block';
      tip.style.left = (mx + 16) + 'px';
      tip.style.top = (my + 12) + 'px';
      tip.innerHTML = `<span class="p">Port ${p.port}</span> / ${esc(p.protocol)} — ${esc(p.status)}<br>`
        + `${esc(p.service || 'unknown')}${p.version ? '<br>' + esc(p.version) : ''}`
        + (p.ms != null ? `<br><span style="color:#8a877f">${p.ms} ms</span>` : '');
    } else {
      tip.style.display = 'none';
    }
  }

  /* ---- loop ---- */
  const clock = new THREE.Clock();
  function animate() {
    const t = clock.getElapsedTime();
    fans.forEach((b, i) => { b.rotation.z += 0.11 + i * 0.012; });
    pulsers.forEach(p => {
      const k = 1 + Math.sin(t * 2.4 + p.phase) * 0.14;
      p.orb.scale.setScalar(k);
      const s = p.base * (1 + Math.sin(t * 2.4 + p.phase) * 0.2);
      p.halo.scale.set(s, s, 1);
    });
    inner.intensity = 1.7 + Math.sin(t * 1.6) * 0.35;
    if (!userMoved) { camTheta += 0.0016; place(); }
    renderer.render(scene, camera);
    requestAnimationFrame(animate);
  }
  animate();
}
</script>
</body>
</html>
"""


def build_html(target, ip, results, specs=None, scan_meta=None, inline_three=False):
    pins, extent = _layout_ports(results)
    meta = scan_meta or {}
    protocols = sorted({r.get("protocol", "tcp") for r in results}) or ["tcp"]

    data = {
        "target": target,
        "ip": ip,
        "extent": round(extent, 2),
        "specs": specs or {},
        "scan": {
            "open": sum(1 for r in results if r["status"] == "open"),
            "closed": sum(1 for r in results if r["status"] == "closed"),
            "filtered": sum(1 for r in results if r["status"] in ("filtered", "open|filtered")),
            "total": len(results),
            "duration": meta.get("duration"),
            "finished": meta.get("finished"),
            "protocols": "/".join(p.upper() for p in protocols),
        },
        "pins": pins,
    }

    html = _HTML.replace("__DATA_JSON__", json.dumps(data))
    html = html.replace("__THREE_CDN__", THREE_CDN)
    html = html.replace("__TARGET__", target)

    if inline_three and os.path.isfile(VENDOR_THREE):
        # Embed the library so the file is a single portable artifact you
        # can move anywhere (or hand to someone) and still have it render.
        with open(VENDOR_THREE, encoding="utf-8", errors="replace") as f:
            lib = f.read()
        html = html.replace('<script src="three.min.js"></script>',
                            "<script>" + lib + "</script>", 1)
    return html


def open_3d_view(target, ip, results, specs=None, scan_meta=None):
    """Write the visualization (plus a copy of three.min.js) to a temp
    directory and open it in the default browser. Returns the html path."""
    if not results:
        raise ValueError("No scan results to visualize yet — run a scan first.")

    out_dir = os.path.join(tempfile.gettempdir(), "portscanner_3d")
    os.makedirs(out_dir, exist_ok=True)

    local_three = os.path.join(out_dir, "three.min.js")
    if os.path.isfile(VENDOR_THREE):
        if not os.path.isfile(local_three) or \
                os.path.getsize(local_three) != os.path.getsize(VENDOR_THREE):
            shutil.copyfile(VENDOR_THREE, local_three)

    path = os.path.join(out_dir, "scan_3d_view.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_html(target, ip, results, specs, scan_meta))

    webbrowser.open(f"file:///{path.replace(os.sep, '/')}")
    return path


def export_portable(target, ip, results, specs=None, scan_meta=None, path=None):
    """Write a single self-contained .html (Three.js embedded) that renders
    anywhere, with no sibling files and no internet. Returns the path."""
    if not results:
        raise ValueError("No scan results to export yet — run a scan first.")
    if path is None:
        path = os.path.join(tempfile.gettempdir(), "portscanner_3d", "scan_3d_portable.html")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_html(target, ip, results, specs, scan_meta, inline_three=True))
    return path
