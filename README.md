# Undetectable

A collection of standalone security/recon tools. Each subfolder is its own project with its own README, dependencies, and license — this file is just the map.

## Projects

### [Port Scanner](Port%20Scanner/)
Concurrent TCP/UDP port scanner and host-recon toolkit (Python, CLI + desktop GUI). Banner/version grabbing, TLS cert and HTTP header probing, ping/MAC-vendor/DNS/traceroute recon, and a 3D visualization dashboard.

### [Steganography-Multi-Tool](Steganography-Multi-Tool/) (StegKit)
Educational multi-format steganography CLI. Hides one authenticated payload in PNG/BMP pixels, WAV/FLAC samples, QR module damage, zero-width Unicode, PDF structures, or Git history.

### [osint](osint/) (Image Geolocator)
Web app that estimates where a photo was taken by fusing EXIF GPS, IPTC/XMP place tags, and an AI visual estimate, then plots ranked candidates on a map (Next.js/TypeScript).

### [Overlay](Overlay/) (Overlay HUD)
A borderless, always-on-top utility overlay for Windows and Arch Linux, including Hyprland. Windows supports compositor-level capture exclusion; on Arch Linux the overlay runs normally and uses compositor keybinds via the app's local command socket. Reuses the Port Scanner engine for one of its panels.

## Legal & Ethical Notice

These tools are for authorized security testing, research, and educational use only — on systems, files, and accounts you own or have explicit permission to test. Do not use them against targets you don't control or haven't been authorized to assess.

## Layout note

Each project directory was originally its own git repository and is tracked here as plain files (not a git submodule) for simplicity. See each project's own remote on GitHub for its independent commit history:

- https://github.com/davidrencse/port-scanner
- https://github.com/davidrencse/Steganography-Multi-Tool
- https://github.com/davidrencse/osint
