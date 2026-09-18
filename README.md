# Utility Belt

A monorepo of security/recon tools. Each project keeps its own README, dependencies, and license; this file is the map.

```
apps/        runnable apps that compose the packages
  overlay/     Overlay HUD
  osint/       Image Geolocator (web)
packages/    standalone engines, each usable on its own
  asphalt/     packet capture + analysis
  port-scanner/
  stegkit/
scripts/     check.py: one command runs every project's checks
benchmarks/  compare.py: working tree vs a git ref, speed + identical output
```

## Apps

### [Overlay HUD](apps/overlay/)
A borderless, always-on-top utility overlay for Windows and Arch Linux, including Hyprland. Windows supports compositor-level capture exclusion; on Arch Linux the overlay runs normally and uses compositor keybinds via the app's local command socket. Its tool panels reuse the Port Scanner, StegKit and Asphalt engines from `packages/`, and it embeds the osint app.

### [Image Geolocator](apps/osint/) (osint)
Web app that estimates where a photo was taken by fusing EXIF GPS, IPTC/XMP place tags, and an AI visual estimate, then plots ranked candidates on a map (Next.js/TypeScript).

## Packages

### [Asphalt](packages/asphalt/)
Packet capture, decode, and analysis toolkit (Python, CLI + PySide6 desktop UI). Live-captures traffic via Scapy or ingests PCAP/PCAPNG files, decodes L2–L4 fields, and runs a pluggable analyzer suite (flow analytics, TCP handshakes/reliability, DNS anomalies, ARP/LAN signals, scan-signal detection) into JSON reports or live dashboards. Its capture + analysis engine also drives the Overlay HUD's Sniffer panel.

### [Port Scanner](packages/port-scanner/)
Concurrent TCP/UDP port scanner and host-recon toolkit (Python, CLI + desktop GUI). Banner/version grabbing, TLS cert and HTTP header probing, ping/MAC-vendor/DNS/traceroute recon, and a 3D visualization dashboard.

### [StegKit](packages/stegkit/)
Educational multi-format steganography CLI. Hides one authenticated payload in PNG/BMP pixels, WAV/FLAC samples, QR module damage, zero-width Unicode, PDF structures, or Git history.

## Development

```bash
pip install -r requirements-dev.txt        # Python deps (inside a venv)
(cd apps/osint && npm ci)                  # web app deps
python scripts/check.py                    # tests, smoke checks, lint for every project
python benchmarks/compare.py               # is it faster than HEAD, with identical output?
```

CI (`.github/workflows/ci.yml`) runs the same `scripts/check.py` on Linux and Windows, and benchmarks each pull request against its base. Agent and contributor conventions are in [AGENTS.md](AGENTS.md).

## Legal & Ethical Notice

These tools are for authorized security testing, research, and educational use only — on systems, files, and accounts you own or have explicit permission to test. Do not use them against targets you don't control or haven't been authorized to assess.

## Upstream repositories

Each project was originally its own git repository and is tracked here as plain files (not a git submodule). Directory names were normalized for the monorepo; each project's independent history lives on GitHub:

- `packages/port-scanner` ← https://github.com/davidrencse/port-scanner
- `packages/stegkit` ← https://github.com/davidrencse/Steganography-Multi-Tool
- `packages/asphalt` ← https://github.com/davidrencse/Asphalt
- `apps/osint` ← https://github.com/davidrencse/osint
