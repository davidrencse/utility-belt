# Overlay HUD

A borderless, translucent, always-on-top utility overlay. It supports Windows
11 and Arch Linux, including Hyprland.

On Windows 10 2004+ it can ask the compositor to exclude the overlay window
from normal screen capture. On Arch Linux there is no equivalent standard
per-window API exposed to regular apps, so the overlay runs normally but
screen-capture hiding is shown as unsupported.

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
  anything.
- **SETTINGS** — transparency slider, show/hide each graph, filled-vs-line
  graphs, capture hiding status, click-through / always-on-top toggles, telemetry
  sample rate, and ping target. Persists to `_settings.json`.

The header **⋯** button is a **quick launch** menu — pin folders, files, or
links (e.g. a resume folder) and open them instantly; links open as a tab in
the embedded browser, folders/files open in Explorer / their default app.

## Run on Windows

```bash
pip install -r requirements.txt
python main.py
```

Or double-click **`Run Overlay.bat`** (launches with no console window). The
overlay starts top-right and lives in the system tray; closing the window
hides it, quit from the tray menu.

Requires **Windows 10 build 19041 (2004) or newer** for the
`WDA_EXCLUDEFROMCAPTURE` capture-exclusion flag, and Python 3.9+.

## Run on Arch Linux / Hyprland

Install Qt/PySide and the small command-line tools used by the panels:

```bash
sudo pacman -S python python-pyside6 python-pyside6-webengine iputils traceroute net-tools
python -m pip install --user browser_cookie3 colorama
cd Overlay
python main.py
```

If your PySide packages come from `pip` instead of `pacman`, use:

```bash
python -m pip install --user -r requirements.txt
```

Hyprland owns global keybinds, so the app exposes a local command interface
that Hyprland can call. Print bind lines from your current overlay settings:

```bash
cd Overlay
python main.py --print-hyprland-binds
```

Add the printed lines to `~/.config/hypr/hyprland.conf`, then reload:

```bash
hyprctl reload
```

**Required window rule.** Hyprland tiles new windows by default, so without a
rule the HUD opens as just another tile/tab in your workspace instead of
floating on top. Add a float rule matching the window title `sysmon-overlay`.

If you use the classic `~/.config/hypr/hyprland.conf`:

```ini
windowrulev2 = float, title:^(sysmon-overlay)$
windowrulev2 = pin, title:^(sysmon-overlay)$
```

If you use a Lua-based config (`~/.config/hypr/hyprland.lua`, newer Hyprland
builds — `hyprctl keyword` will refuse to work on these with "keyword can't
work with non-legacy parsers", so this rule has to live in the config file,
not be poked in at runtime):

```lua
hl.window_rule({
    name = "sysmon-overlay-float",
    match = { title = "^sysmon-overlay$" },
    float = true,
    pin = true,
})
```

Then reload:

```bash
hyprctl reload
```

## Global hotkeys

| Hotkey | Action |
|---|---|
| `Alt+Y` | show / hide the HUD |
| `Alt+T` | next tab |
| `Ctrl+Alt+H` | **panic**: hide instantly and drop the capture flag |
| `Ctrl+Alt+C` | toggle click-through (mouse passes through the overlay) |
| `Ctrl+Alt+X` | toggle capture-exclusion on/off where supported |
| `Ctrl+Alt+←↑↓→` | nudge the window 20 px |

Drag the header to move it; drag the bottom-right grip to resize. The header
badge reads **HIDDEN** (excluded), **VISIBLE** (excluded off), or
**UNSUPPORTED** on platforms without capture-exclusion support.

## Capture hiding limits

On Windows, the mechanism is one Win32 call:
`SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)`. The desktop
compositor then leaves the window out of standard Windows capture paths.

This is not true invisibility:

- A **phone or camera pointed at your monitor** still sees it — it's only the
  Windows digital capture path that's blocked.
- **Kernel-level anti-cheat and dedicated proctoring software** (lockdown
  exam browsers, some enterprise monitors) can detect the *process or the
  window*, and can even query this affinity flag directly. This tool does
  nothing to hide the process, and does not attempt to evade such software.
- It is a **per-window compositor flag**, not OS-wide stealth.
- Hyprland/Wayland does not provide this Windows compositor flag.

Use it only where it is legal and appropriate.

## Files

| File | Purpose |
|---|---|
| `main.py` | App bootstrap, tray icon, local IPC, native/Hyprland hotkeys |
| `overlay/window.py` | Frameless translucent HUD, tabs, drag/resize, window flags |
| `overlay/core/stealth.py` | Windows capture exclusion; cross-platform click-through helper |
| `overlay/hotkeys.py` | Windows `RegisterHotKey`; no-op elsewhere |
| `overlay/ipc.py` | Local command socket used by Hyprland bind commands |
| `overlay/core/netstat.py` | Dependency-free network byte counters for Windows and Linux |
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
