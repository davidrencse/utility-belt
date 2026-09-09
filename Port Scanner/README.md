# Port Scanner

A concurrent TCP/UDP port scanner and host-recon toolkit written in Python,
with both a CLI and a desktop GUI dashboard. It identifies open ports on a
target host, grabs service banners and versions, probes TLS certs and HTTP
headers, and layers on host-level recon (ping, MAC/vendor guess, DNS,
traceroute).

## Quick start (GUI)

Double-click **`Run Port Scanner.bat`**. It launches the dashboard
(`gui.py`) with no console window. Requires Python 3.8+ on `PATH`.

## ⚠️ Legal & Ethical Notice

**Only scan systems and networks you own, or for which you have explicit,
written permission to test.** Port scanning a host you don't control can
violate:

- Computer misuse laws (e.g. the U.S. Computer Fraud and Abuse Act)
- Your ISP's or cloud provider's acceptable use policy
- The target network's terms of service

Unauthorized scanning — even just to "see what's open" — can be treated as
an attack and may carry criminal or civil liability. When in doubt, don't.
Good places to practice legally:

- `127.0.0.1` / `localhost` (your own machine)
- A VM or container you control on an isolated network
- Deliberately vulnerable/legal practice targets (e.g. your own lab, or
  `scanme.nmap.org`, which Nmap's maintainers explicitly permit light
  scanning of)

This tool will prompt for confirmation before scanning any target that
isn't localhost, unless you pass `-y/--yes`.

## Files

| File | Purpose |
|---|---|
| `Run Port Scanner.bat` | Double-click launcher for the GUI (no console window) |
| `gui.py` | Tkinter dashboard — Port Scan / Host Recon / Local Network tabs |
| `port_scanner.py` | CLI + all port-scanning logic (also imported by the GUI) |
| `net_recon.py` | Host-level recon: ping, MAC/vendor, DNS, local interfaces, traceroute |
| `system_info.py` | This machine's specs: CPU/GPU/RAM/disk/OS/uptime/load |
| `geoip.py` | Approximate IP geolocation (ip-api.com), cached; private IPs never leave the box |
| `viz3d.py` | Generates the Three.js 3D system + port visualization (browser) |
| `viz3d_tk.py` | Software 3D renderer for the in-app "3D View" tab (no dependencies) |
| `viz_geo.py` | Three.js geo/infra scene: geopinned globe → stylized street/building → laptop/server/datacenter models |
| `vendor/three.min.js` | Vendored Three.js r128 (MIT) so the 3D views work offline |

## Features

**Port scanning**
- Concurrent TCP connect scanning via a thread pool (`concurrent.futures`),
  plus best-effort UDP scanning (`--udp` / "UDP" protocol in the GUI)
- Configurable timeout, thread count, and port range/list
- Banner grabbing, with protocol-specific nudges for HTTP, Redis, and
  MySQL's binary handshake
- Service/version extraction from banners (e.g. `OpenSSH_9.8`, `nginx/1.24.0`)
- **Deep probe** mode: for open web/TLS ports, fetches HTTP status line,
  `Server` header, and page `<title>`; for implicit-TLS ports (443, 8443,
  993, 995, 465, 636), grabs the negotiated TLS version/cipher and the
  certificate's subject, issuer, and validity dates
- Per-port response time in milliseconds
- **Rate limiting & scan hygiene** — a shared token-bucket caps new
  connections/sec across all threads (GUI "Rate /s" box, CLI `--rate`), and
  an optional randomized scan order (`--random-order`) makes traffic look
  less like a sequential sweep. A "Polite" preset (`--polite`, or the GUI
  checkbox) applies both. This keeps the source under IDS/firewall
  thresholds so the **target doesn't rate-limit or block your machine**
  mid-scan — the failure mode that otherwise turns a scan into all-filtered
  garbage.
- Built-in port → service name lookup table (~100 common services,
  including the RDP/SMB/SSH/FTP/HTTP/HTTPS/MySQL/PostgreSQL/VNC set); other
  ports resolve against the OS services database, which is **parsed once at
  startup** into a dict rather than looked up per-port (~0.7 ms/port saved)
- Colorized, tabular CLI output; sortable table + live activity log in the GUI
- Live GUI visualizations: a port-map heatmap (one dot per port/bucket,
  lights up as results stream in), a scan-progress ring, and a
  response-time sparkline

**Geo / Map** (GUI "Geo / Map" tab, CLI `--geo`)
- Approximate IP geolocation — city, region, country, lat/lon, org/ISP,
  ASN, timezone — via ip-api.com (one cached outbound lookup; private/LAN
  targets are answered locally without any network call).
- **3D map** (`viz_geo.py`, opens in the browser) with three switchable views:
  - **Globe** — a wireframe/dotted Earth with the target geopinned by
    lat/lon (glowing pin, pulsing rings, beam, label), plus a great-circle
    arc from your own location when available.
  - **Street** — a stylized city block centred on those coordinates with
    the target building highlighted.
  - **Infra** — procedural 3D models: your laptop (from real specs), the
    target as a server rack with blinking LEDs, and a data-center row.
- **Honest limitation:** IP geolocation resolves the *ISP/network's
  registered city*, not a street address or a specific building, and is
  often tens–hundreds of km off. The street/building view is a
  representative visualization of the coordinates, **not** a surveyed
  location — it is labelled as such in the UI.
- **3D View tab (in-app)** — the same scene rendered inside the dashboard
  window by a small software renderer written on a Tk Canvas (perspective
  projection, backface culling, painter's-algorithm depth sorting, flat
  shading). Drag to orbit, scroll to zoom, auto-rotates when idle. Tkinter
  has no WebGL surface, so this trades transparency and glow for zero
  dependencies — the side panel is simply left open to show the components.
- **3D View (Three.js/WebGL)** — for the richer version, click "⛶ 3D VIEW"
  (or "OPEN WEBGL VERSION" in the 3D tab) to open a
  real-time 3D scene in your browser: a rendered PC tower (case panels,
  tempered-glass side, motherboard, GPU, RAM, CPU cooler, spinning case
  fans, power LED) standing in a field of port pins arranged in a
  phyllotaxis spiral. Open ports rise as glowing orange beams with labelled
  orbs, filtered ports as shorter amber beams, closed ports as a dim dot
  field. Drag to orbit, scroll to zoom, hover a beam for port detail. The
  HUD shows this machine's real specs alongside the scan summary.
- **Portable export** — "⤓ EXPORT" saves a single self-contained `.html`
  with Three.js embedded, so the scan report opens anywhere, offline, with
  no sibling files.

**System tab** — this machine's specs (model, CPU + core count, GPU, RAM,
disk, OS, mainboard, uptime, architecture) with live dotted gauges for CPU
load, memory used, and disk used. Read via `winreg`/`ctypes`/`shutil` plus
one PowerShell CIM call; no third-party packages.

**Host recon** (`--recon` in the CLI, "Host Recon" tab in the GUI)
- Ping-based host status (online/offline/unreachable), latency, and TTL
- Rough OS-family guess from TTL (heuristic, not fingerprinting)
- MAC address lookup via the OS ARP cache — **local subnet only**
- Vendor guess from the MAC's OUI prefix, using a small built-in table
  (~100 entries — not the full IEEE registry, so "Unknown vendor" is
  expected for lots of hardware)
- Reverse DNS (PTR) and forward DNS (A/AAAA) lookups
- Traceroute (`--traceroute` / "Traceroute" button) via the OS's own
  `tracert`/`traceroute` utility

**Local network tab** — this machine's own hostname, primary IP, and (on
Windows) a parsed `ipconfig /all`: adapter names, IPv4, subnet mask,
gateway, MAC, DNS servers.

**Scan metadata** — start/end time, duration, ports scanned, hosts scanned,
all shown in both the CLI summary and the GUI stat cards.

## Requirements

- Python 3.8+ (Windows: uses `ping`/`arp`/`ipconfig`/`tracert`; other OSes
  fall back to their equivalents)
- `colorama` (optional, for colored CLI output on Windows)
- `tkinter` for the GUI — ships with the standard python.org Windows
  installer; on Linux install your distro's `python3-tk` package if it's
  missing
- The 3D view needs a WebGL-capable browser. Three.js r128 (MIT) is
  vendored in `vendor/` and copied next to the generated page, so no
  internet is required; if that file is ever missing the page falls back
  to loading Three.js from cdnjs.

```bash
pip install -r requirements.txt
```

The CLI runs fine without `colorama` installed — it just falls back to
plain, uncolored text.

## Usage

### GUI

Double-click `Run Port Scanner.bat`, or run `python gui.py` directly. Enter
a target, pick a port range/protocol, and click **Scan**. The Host Recon
and Local Network tabs share the same target field and work independently
of the port scan.

### CLI

```bash
python port_scanner.py -t <target> [options]
```

| Flag | Description | Default |
|---|---|---|
| `-t`, `--target` | Target IP address or hostname (required) | — |
| `-p`, `--ports` | Port(s): single (`80`), range (`1-1024`), or list (`22,80,443,8000-8100`) | `1-1024` |
| `--timeout` | Per-connection timeout in seconds | `2.0` |
| `--threads` | Max concurrent connections | `100` |
| `--rate` | Cap new connections/sec across all threads (0 = unlimited). Stays under IDS/firewall thresholds so the target doesn't rate-limit or block your IP | `0` |
| `--random-order` | Scan ports in randomized order (less like a sequential sweep) | off |
| `--polite` | Shorthand for a low-profile scan: `--rate 50 --random-order` | off |
| `--geo` | Print approximate IP geolocation (city/region/country/org/ASN) via ip-api.com | off |
| `--udp` | Scan UDP instead of TCP (best-effort) | off |
| `--recon` | Run host recon (ping/TTL/OS guess/MAC/vendor/DNS) before scanning | off |
| `--deep` | Deep-probe open web/TLS ports for HTTP + certificate info | off |
| `--traceroute` | Run a traceroute after scanning | off |
| `--no-banner` | Skip banner grabbing for faster scans | off |
| `-v`, `--verbose` | Show closed/filtered ports too, not just open ones | off |
| `-y`, `--yes` | Skip the authorization confirmation prompt | off |
| `--no-progress` | Suppress the live progress indicator | off |

### Examples

Scan the well-known ports on your own machine:

```bash
python port_scanner.py -t 127.0.0.1
```

Full recon + deep-probed scan with a traceroute at the end:

```bash
python port_scanner.py -t 127.0.0.1 -p 1-1024 --recon --deep --traceroute
```

Full 1–65535 port sweep with more threads:

```bash
python port_scanner.py -t 127.0.0.1 -p 1-65535 --threads 200
```

Scan specific ports and show every result, not just open ones:

```bash
python port_scanner.py -t 127.0.0.1 -p 22,80,443,3306,8080-8090 -v
```

Best-effort UDP scan of common UDP services:

```bash
python port_scanner.py -t 127.0.0.1 -p 53,67,123,161 --udp -v
```

## How it works

1. **Argument parsing** validates the target and port spec, and resolves
   hostnames to an IP via `socket.gethostbyname`.
2. **Authorization check** — for any target other than localhost, the
   tool asks for explicit confirmation before proceeding (bypass with
   `-y` on the CLI; the GUI shows the same prompt as a dialog).
3. **Host recon** (optional) — `net_recon.py` shells out to the OS's own
   `ping`, `arp`, and `tracert`/`traceroute` utilities and parses their
   output; no raw sockets or elevated privileges required.
4. **Concurrent scanning** — a `ThreadPoolExecutor` fans out one
   `socket.connect_ex()` (TCP) or `sendto()`/`recvfrom()` (UDP) attempt per
   port, capped at `--threads` concurrent connections.
5. **Banner grabbing & version extraction** — on a successful TCP connect,
   the code reads (or, for silent services, nudges then reads) a banner and
   runs it through a small set of regexes to pull out a version string.
6. **Deep probe** (optional) — open web ports get a real `GET /` request
   parsed for status/headers/title; open TLS ports get a certificate
   fetched via `ssl` with verification disabled (informational only, never
   validated against a CA).
7. **Service lookup** — each port is cross-referenced against a built-in
   dictionary of ~100 common services, falling back to
   `socket.getservbyport`.
8. **Output** — CLI prints a colorized table; the GUI updates stat cards,
   a sortable table, and a live log in real time as results stream in from
   the worker threads via a queue.

## Limitations

- **TCP connect scan, not a SYN scan.** Full handshake (`connect()`), not
  a stealthier half-open scan — it's easily logged and isn't meant to
  evade detection.
- **UDP scanning is inherently ambiguous.** No response can mean open,
  filtered, or just a service that ignores unsolicited probes — reported
  as `open|filtered`, the standard convention (matches nmap's behavior).
- **MAC/vendor lookup only works on your local subnet**, and only after
  the OS has an ARP cache entry for the target (the GUI/CLI ping the host
  first to populate it). Off-subnet targets always show "N/A".
- **OS and vendor guesses are heuristics.** TTL-based OS guessing is
  easily wrong (intermediate hops decrement TTL, and many stacks let you
  configure it). The vendor table is a hand-picked ~100 entries, not the
  full IEEE OUI registry, so "Unknown vendor" is common and expected.
- **TLS/cert info is unauthenticated.** Certificates are fetched with
  verification disabled (`CERT_NONE`) purely to read their fields — this
  tool never validates a chain of trust, so don't use it to decide whether
  a cert is legitimate.
- **No SMB/database protocol enumeration.** SMB and most databases beyond
  MySQL's banner and Redis's `PING` are identified by port/service name
  only — deeper enumeration needs dedicated tooling (e.g. `smbclient`).
- **Not a substitute for a real scanner.** For production security work,
  use established, actively maintained tools (Nmap, Masscan, etc.)
  alongside this one — this project is primarily an educational
  implementation of the underlying techniques.

## Testing

Test against `localhost` first. Two easy ways to get open ports to scan:

```bash
# Start a throwaway HTTP server on port 8000
python -m http.server 8000

# In another terminal, scan for it
python port_scanner.py -t 127.0.0.1 -p 1-9000
```

You should see port `8000` reported as `open` with service `Dev-HTTP` and
an HTTP banner from the `HEAD` probe.
"# port-scanner" 
