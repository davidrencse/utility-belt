# Overlay HUD

A Cluely / Interview-Coder-style **overlay** for Windows 11: a borderless,
translucent, always-on-top window that is **excluded from screen capture** —
it does not appear in Zoom / Teams / Meet / Discord screen-share or OBS
Display/Window Capture, while staying fully visible to you on the physical
screen.

It carries four top-level tabs:

- **SYSTEM** — live CPU / RAM / DISK gauges, plus rolling sparklines for CPU
  load, ping latency, and network up/down throughput, and system uptime.
  (Telemetry pauses automatically while the HUD is hidden, to save CPU.)
- **TOOLS** — a utility belt with an inner switch:
  - *Port Scan* — a thin UI over the existing **Port Scanner** engine
    (`../Port Scanner/`), reused as-is: target, port spec, TCP/UDP, threads,
    rate limit, **Polite** preset and **Deep** probe. Streams results live.
  - *Steganography* — a thin UI over **StegKit** (`../Steganography-Multi-Tool/`):
    hide an AES-256-GCM-encrypted message inside a PNG/BMP's pixels or in
    zero-width Unicode text, and extract it back.
  - *OSINT Geo* — embeds the user's **Image Geolocator** Next.js app
    (`../osint/`); the panel starts its local dev server and loads it in the
    browser view. Needs Node.js (a one-time `npm install`) and, for the AI
    visual estimate, a `VISION_API_KEY` in `osint/.env.local`.
- **CHAT** — an embedded Chromium view (QtWebEngine) at `chatgpt.com` with a
  **persistent profile**: sign in once and it sticks, no API key. A **"Use my
  browser login"** button reuses the ChatGPT session already in your Chrome/
  Edge/Firefox (read locally, on your click) so you don't have to type
  anything. Because it lives inside the capture-excluded window, it's hidden
  from screen-share too.
- **SETTINGS** — transparency slider, show/hide each graph, filled-vs-line
  graphs, capture-exclusion / click-through / always-on-top toggles, telemetry
  sample rate, and ping target. Persists to `_settings.json`.

The header **⋯** button is a **quick launch** menu — pin folders, files, or
links (e.g. a resume folder) and open them instantly; links open as a tab in
the embedded browser, folders/files open in Explorer / their default app.

## Run

```bash
pip install -r requirements.txt
python main.py
```

Or double-click **`Run Overlay.bat`** (launches with no console window). The
overlay starts top-right and lives in the system tray; closing the window
hides it, quit from the tray menu.

Requires **Windows 10 build 19041 (2004) or newer** for the
`WDA_EXCLUDEFROMCAPTURE` capture-exclusion flag, and Python 3.9+.

## Global hotkeys (work even when unfocused)

| Hotkey | Action |
|---|---|
| `Ctrl+Alt+\` | show / hide the HUD |
| `Ctrl+Alt+H` | **panic**: hide instantly and drop the capture flag |
| `Ctrl+Alt+C` | toggle click-through (mouse passes through the overlay) |
| `Ctrl+Alt+X` | toggle capture-exclusion on/off (A/B test it in a share) |
| `Ctrl+Alt+←↑↓→` | nudge the window 20 px |

Drag the header to move it; drag the bottom-right grip to resize. The header
badge reads **HIDDEN** (excluded) or **VISIBLE** (excluded off).

## How "undetectable" actually works — and its limits

The mechanism is one Win32 call in `win_stealth.py`:
`SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)`. This is the same
technique Interview Coder / Cluely use. The desktop compositor then leaves
the window out of every standard capture path — BitBlt, DXGI Desktop
Duplication, and the Windows Graphics Capture API — which is what Zoom,
Teams, Meet, Discord, and OBS all use. To them the window simply isn't there.

**It is not true invisibility. Be honest with yourself about this:**

- A **phone or camera pointed at your monitor** still sees it — it's only the
  digital capture path that's blocked.
- **Kernel-level anti-cheat and dedicated proctoring software** (lockdown
  exam browsers, some enterprise monitors) can detect the *process or the
  window*, and can even query this affinity flag directly. This tool does
  nothing to hide the process, and does not attempt to evade such software.
- It is a **per-window compositor flag**, not OS-wide stealth.

So this is *hidden from screen-share*, not *undetectable by all means*. Use it
where that distinction is legal and appropriate.

## Files

| File | Purpose |
|---|---|
| `main.py` | App bootstrap, tray icon, wires hotkeys to the window |
| `overlay_window.py` | Frameless translucent HUD, tabs, drag/resize, stealth |
| `win_stealth.py` | ctypes: `SetWindowDisplayAffinity`, click-through, tool-window |
| `hotkeys.py` | Global `RegisterHotKey` via a Qt native event filter |
| `netstat.py` | Dependency-free network byte counters (iphlpapi `GetIfTable`) |
| `theme.py` | Design system — the monochrome palette, fonts, and Qt style helpers every panel reads from |
| `widgets.py` | QPainter `Sparkline` and `Gauge` (no pyqtgraph/numpy) |
| `settings.py` | Reactive settings store (JSON-persisted) driving the Settings tab |
| `engine_bridge.py` | Puts `../Port Scanner` and `../Steganography-Multi-Tool` on `sys.path`, re-exports both |
| `panels/metrics_panel.py` | Telemetry sampler + gauges/sparklines (pauses when hidden) |
| `panels/tools_panel.py` | TOOLS container with the Port Scan / Stego / OSINT sub-switch |
| `panels/portscan_panel.py` | UI over the reused `port_scanner` primitives |
| `panels/stego_panel.py` | UI over the reused StegKit image/text stego |
| `panels/osint_panel.py` | Runs the `../osint` Next.js dev server and embeds it |
| `panels/chatgpt_panel.py` | Embedded ChatGPT browser (persistent profile + browser-session import) |
| `panels/settings_panel.py` | The Settings tab controls |
| `_webprofile/` | Auto-created; stores the ChatGPT login session (git-ignore it) |
| `_settings.json` | Auto-created; your saved settings and quick-launch shortcuts |

## Reuse note

The scanning/telemetry logic is **not** duplicated here — `engine_bridge.py`
imports `system_info`, `port_scanner`, and `net_recon` straight from
`../Port Scanner/`. Improvements to that engine flow into this overlay
automatically.
