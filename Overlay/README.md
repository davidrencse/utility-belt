# Overlay HUD

A borderless, translucent, always-on-top **utility-belt overlay** — a wide
landscape HUD that floats over everything. On Windows 10 2004+ it can ask the
compositor to hide its window from normal screen capture (Zoom / Teams / Meet /
OBS / Discord); it also runs on Arch Linux / Hyprland, where per-window capture
hiding is not available and is shown as unsupported.

It reuses several sibling projects as-is (nothing reimplemented): the
`Port Scanner` engine, the `Steganography-Multi-Tool` (StegKit) library, the
`Asphalt` packet capture/analysis engine, and the `osint` Image-Geolocator web
app.

## Tabs

- **SYSTEM** — two sub-views:
  - *Live* — CPU / RAM / DISK gauges and rolling CPU, ping and network graphs.
    Sampling pauses automatically whenever SYSTEM isn't the visible tab (or the
    HUD is hidden), to save CPU.
  - *Specs* — a Task-Manager-style read-out: PC name, model, motherboard, OS +
    build, CPU + cores, GPU, RAM, disk, network adapters (IPv4/gateway/MAC/DNS),
    and Wi-Fi — with a **Reveal saved Wi-Fi passwords** button (reads this PC's
    own `netsh` profiles, on your click).
- **NETWORK** — the wire: what's on it and how fast it is:
  - *Speed Test* — keyless Cloudflare download/upload/latency test.
  - *Port Scan* — thin UI over the reused `Port Scanner` engine (TCP/UDP,
    threads, rate limit, Polite preset, Deep probe); results stream live.
  - *Sniffer* — packet sniffer/analyzer over the reused `Asphalt` engine.
    Pick an interface, optionally narrow with a **BPF capture filter** (`tcp
    port 443`) and an Asphalt **display filter** (`l4=tcp and not
    dst_port=443`, table only — the analyzers still see everything). **LIVE**
    streams decoded packets newest-first with a packets/sec graph; **SIGNALS**
    reads Asphalt's analyzers live and calls out port scans, ARP conflicts,
    NXDOMAIN spikes, high-entropy DNS names, RST storms and half-open
    handshakes, next to protocol mix and top talkers. Needs `scapy` (plus
    Npcap on Windows) and an elevated session.
- **INTEL** — analysis of files, media and images:
  - *VirusTotal* — the VirusTotal website embedded like the CHAT tab (no API
    key): upload files, search hashes/URLs, read reports. Sign-ins persist.
  - *Steganography* — StegKit image (PNG/BMP pixels) and zero-width text
    stego, AES-256-GCM encrypted, encode + decode.
  - *OSINT Geo* — starts the local `osint` Next.js dev server and embeds it
    (needs Node.js + a one-time `npm install`; the AI estimate needs a
    `VISION_API_KEY` in `osint/.env.local`).
- **HISTORY** — *Clipboard* (text you've copied this session, in memory only)
  and *Screenshots*: press **Alt+S** (rebindable) or *Take screenshot* to save
  the screen without the overlay in it; Capture → ChatGPT shots land here too.
  Thumbnail grid with Copy, Send to ChatGPT, Open, Delete. Saved as PNGs in
  `overlay/_screenshots/` (git-ignored), newest 200 kept.
- **WEATHER** — current conditions for your location, no API key (ip-api for
  location, Open-Meteo for forecast + air quality): a drawn condition icon, big
  temperature, feels-like, an hourly temperature curve, a wind compass, and
  tiles for humidity, wind, UV index, pressure, visibility, air quality (US
  AQI), sunrise and sunset.
- **CHAT** — an embedded Chromium view (QtWebEngine) at `chatgpt.com` with a
  **persistent profile** (sign in once, no API key; OAuth popups open in a real
  window so Google/etc. sign-in completes and sticks). **Use my browser login**
  imports an existing Chrome/Edge/Firefox session. **Capture ▾** (or `Alt+A`)
  screenshots the screen, pastes it here, and drops in a ready prompt (Deep
  study notes / Summarize / Cold Absolute mode) — review and press Enter.
- **SETTINGS** — *Display* (transparency, motion, graphs) · *Behavior*
  (stealth, startup, telemetry) · *Keybinds*.

The banner groups chips as `SYSTEM NETWORK INTEL WEATHER | CHAT SETTINGS` —
things you look at, then the assistant and app configuration.

The header **⋯** button is a **quick launch** menu — pin folders, files or
links and open them instantly (links open as a tab in the embedded browser).

## Window & interaction

- **Move** — drag anywhere on the card (controls keep working).
- **Resize** — drag any edge or corner, or the bottom-right grip.
- **Zoom** — `Ctrl` `+` / `Ctrl` `-` / `Ctrl` `0`, or `Ctrl`+scroll. Over a
  browser tab it zooms the page; elsewhere it scales the whole HUD (gauge and
  graph text is size-relative, so the HUD genuinely zooms).
- **Tear-off tabs** — drag a tab down/out of the tab bar to pop it into its own
  standalone window (Chrome-style). Drag that window back over the tab bar (it
  highlights as a drop target) and release to dock it again; closing it also
  docks it back. Detached tabs are marked with **⧉**.
- **Transparency** — a slider in Settings; the desktop shows through the card.
- **Tray** — closing the window hides it; quit from the tray icon.

## Global hotkeys (customizable in Settings › Keybinds)

| Default | Action |
|---|---|
| `Alt+Y` | show / hide the HUD |
| `Alt+A` | capture screen → ChatGPT with a ready prompt |
| `Alt+T` | next tab |
| `Ctrl+Alt+X` | toggle capture hiding |
| `Ctrl+Alt+C` | toggle click-through |
| `Ctrl+Alt+H` | panic hide |
| `Ctrl+Alt+←↑↓→` | nudge the window |

Type any combo (e.g. `alt+y`, `ctrl+alt+left`, `f8`; blank = off).

## Run on Windows

```bash
pip install -r requirements.txt
python main.py
```

Or double-click **`Run Overlay.bat`** (no console window). Needs Windows 10
build 19041 (2004)+ for capture hiding, and Python 3.10+.

## Run on Arch Linux / Hyprland

```bash
sudo pacman -S python python-pyside6 python-pyside6-webengine iputils traceroute net-tools
python -m pip install --user browser_cookie3 colorama
cd Overlay && python main.py
```

Hyprland owns global keybinds, so the app exposes a local command socket it can
call. Print bind lines from your current settings and add them to
`~/.config/hypr/hyprland.conf`, then `hyprctl reload`:

```bash
python main.py --print-hyprland-binds
```

Float the window with a rule matching the title `sysmon-overlay`:

```ini
windowrulev2 = float, title:^(sysmon-overlay)$
windowrulev2 = pin,   title:^(sysmon-overlay)$
```

## Capture-hiding limits (be honest)

On Windows the mechanism is one call —
`SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)`. It hides the window
from standard Windows capture paths, **not**:

- a phone/camera pointed at the screen;
- kernel-level anti-cheat or proctoring that inspects the process/window (this
  tool does not hide the process or evade such software);
- Wayland/Hyprland, which exposes no equivalent flag.

Use it only where it is legal and appropriate.

## Architecture

```
Overlay/
  main.py                     thin launcher (sets sys.path, Qt flags)
  overlay/
    app.py                    QApplication bootstrap, tray, hotkeys, IPC
    window.py                 frameless HUD: tabs, move/resize, zoom, tear-off
    theme.py                  monochrome design tokens + Qt style helpers
    settings.py               reactive JSON-persisted settings store
    subtabs.py                shared SubTabHost (inner sub-tab switch)
    widgets.py                QPainter Sparkline + Gauge (size-relative fonts)
    hotkeys.py                Windows RegisterHotKey; customizable bindings
    ipc.py                    local command socket (Hyprland binds)
    platform_utils.py         OS detection + open-path/runtime helpers
    core/
      bridge.py               imports the sibling engines; PROJECT_ROOT
                              (Asphalt is loaded lazily - scapy is slow)
      stealth.py              capture exclusion; click-through; tool-window
      netstat.py              dependency-free net byte counters (Win + Linux)
    panels/
      system_panel.py         SYSTEM container (Live + Specs)
      metrics_panel.py        live telemetry (Sampler QThread -> Sample dataclass)
      specs_panel.py          machine info + Wi-Fi
      network_panel.py        NETWORK container (Speed Test, Port Scan, Sniffer)
      intel_panel.py          INTEL container (VirusTotal, Stego, OSINT Geo)
      net_panel.py  portscan_panel.py  stego_panel.py  osint_panel.py  virustotal_panel.py
      sniffer_panel.py        live capture + decode + analysis (Asphalt)
      weather_panel.py        weather (Open-Meteo + ip-api), drawn icons/graph
      chatgpt_panel.py        embedded ChatGPT + capture-to-prompt
      settings_panel.py       all settings controls
```

Runtime state (`overlay/_webprofile/` login session, `overlay/_settings.json`)
is created on first run and git-ignored.

## Reuse note

The scanning, stego, packet-capture and telemetry logic is **not** duplicated
here. `overlay/core/bridge.py` puts the sibling repos on `sys.path` and
re-exports them, so improvements to those projects flow into the overlay
automatically. The Sniffer panel is the clearest case: it drives Asphalt's own
`ScapyBackend`, `PacketDecoder` and `AnalysisEngine`, and adds only batching
(one signal per ~200 ms instead of one per packet, so the HUD survives a busy
link) and the read-out that turns analyzer output into signal lines.
