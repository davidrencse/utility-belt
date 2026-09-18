#!/usr/bin/env python3
"""
Host-level network reconnaissance helpers: ping/latency/TTL, OS guessing,
local-network MAC + vendor lookup, DNS, local interface info, and
traceroute. These wrap the OS's own `ping`/`arp`/`tracert` utilities via
subprocess rather than crafting raw ICMP packets, so no admin/root
privileges or extra dependencies are required.

Everything here is best-effort. MAC lookups only work for hosts on the
same local subnet (and only after the ARP cache has an entry, which
ping_host() takes care of). OS/vendor guesses are heuristics, not
fingerprinting — treat them as hints, not facts.
"""

import functools
import platform
import re
import socket
import subprocess

IS_WINDOWS = platform.system().lower().startswith("win")

# A small, best-effort table of well-known OUI (MAC prefix) -> vendor.
# This is NOT the full IEEE registry (~40k entries) — just the vendors
# most likely to show up on a home/office LAN. Unmatched prefixes report
# "Unknown vendor".
OUI_VENDORS = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:1C:14": "VMware", "00:05:69": "VMware",
    "08:00:27": "Oracle VirtualBox", "0A:00:27": "Oracle VirtualBox",
    "00:15:5D": "Microsoft Hyper-V",
    "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading", "28:CD:C1": "Raspberry Pi Trading",
    "00:1B:63": "Apple", "3C:07:54": "Apple", "A4:5E:60": "Apple", "F0:18:98": "Apple",
    "AC:DE:48": "Apple", "DC:A9:04": "Apple", "00:17:F2": "Apple", "28:CF:E9": "Apple",
    "04:0C:CE": "Apple", "8C:85:90": "Apple", "D0:E1:40": "Apple", "F4:5C:89": "Apple",
    "88:66:A5": "Apple", "BC:52:B7": "Apple", "E0:B9:BA": "Apple", "F0:99:BF": "Apple",
    "3C:5A:B4": "Google", "F4:F5:D8": "Google", "00:1A:11": "Google", "94:EB:2C": "Google",
    "A4:77:33": "Google", "54:60:09": "Amazon", "68:37:E9": "Amazon", "74:C2:46": "Amazon",
    "FC:65:DE": "Amazon", "00:1A:A1": "Cisco", "00:1B:54": "Cisco", "00:0C:85": "Cisco",
    "00:1D:70": "Cisco", "58:97:1E": "Cisco", "00:1F:9E": "TP-Link", "50:C7:BF": "TP-Link",
    "AC:84:C6": "TP-Link", "F4:F2:6D": "TP-Link", "14:CC:20": "TP-Link", "00:14:6C": "Netgear",
    "20:E5:2A": "Netgear", "A0:40:A0": "Netgear", "2C:30:33": "Netgear", "84:1B:5E": "Netgear",
    "00:1E:58": "D-Link", "1C:7E:E5": "D-Link", "00:1B:11": "D-Link", "B0:C5:54": "D-Link",
    "24:A4:3C": "Ubiquiti Networks", "44:D9:E7": "Ubiquiti Networks", "78:8A:20": "Ubiquiti Networks",
    "FC:EC:DA": "Ubiquiti Networks", "00:15:6D": "Ubiquiti Networks",
    "00:11:32": "Synology", "00:0C:F1": "Intel", "00:1B:21": "Intel", "3C:97:0E": "Intel",
    "A0:36:9F": "Intel", "F8:16:54": "Intel", "00:16:6F": "Dell", "18:03:73": "Dell",
    "B8:CA:3A": "Dell", "D4:BE:D9": "Dell", "F8:B1:56": "Dell", "3C:D9:2B": "Hewlett Packard",
    "94:57:A5": "Hewlett Packard", "9C:8E:99": "Hewlett Packard", "00:1F:29": "Hewlett Packard",
    "00:26:B9": "Dell", "E4:B9:7A": "ASUSTek", "1C:87:2C": "ASUSTek", "2C:56:DC": "ASUSTek",
    "AC:9E:17": "ASUSTek", "48:5B:39": "Samsung", "5C:0A:5B": "Samsung", "8C:71:F8": "Samsung",
    "E8:50:8B": "Samsung", "68:9C:E2": "Samsung", "34:BB:1F": "Samsung",
    "00:17:88": "Philips Hue / Signify", "EC:B5:FA": "Philips Hue / Signify",
    "44:65:0D": "Amazon (Echo/Alexa)", "18:74:2E": "Amazon", "B4:7C:9C": "Amazon",
    "38:F7:3D": "Sonos", "94:9F:3E": "Sonos", "5C:AA:FD": "Sonos", "48:A6:B8": "Sonos",
    "B8:69:F4": "Nest / Google", "18:B4:30": "Nest Labs", "64:16:66": "Nest Labs",
    "EC:1A:59": "Belkin", "94:10:3E": "Belkin", "AC:22:0B": "Belkin",
    "00:E0:4C": "Realtek", "52:54:00": "QEMU/KVM (virtual)", "00:16:3E": "Xen (virtual)",
    "00:03:FF": "Microsoft", "7C:1E:52": "Microsoft (Surface)", "60:45:BD": "Microsoft",
    "44:1C:A8": "TP-Link", "70:4F:57": "Apple", "9C:35:EB": "Apple",
}


def _mac_to_oui(mac):
    parts = re.split(r"[:\-]", mac.strip())
    if len(parts) < 3:
        return None
    return ":".join(p.upper().zfill(2) for p in parts[:3])


@functools.lru_cache(maxsize=256)
def guess_vendor(mac):
    """Best-effort vendor guess from a MAC address's OUI prefix (cached)."""
    if not mac:
        return "Unknown"
    oui = _mac_to_oui(mac)
    if not oui:
        return "Unknown"
    return OUI_VENDORS.get(oui, "Unknown vendor")


def ping_host(target, timeout=2.0):
    """Ping a host once via the OS ping utility.

    Returns dict: status ('online'/'offline'/'unreachable'/'error'),
    latency_ms (float or None), ttl (int or None).
    """
    timeout_ms = max(1, int(timeout * 1000))
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), target]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), target]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        output = proc.stdout + proc.stderr
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "error", "latency_ms": None, "ttl": None, "raw": str(exc)}

    lower = output.lower()
    latency_match = re.search(r"time[=<]\s*([\d.]+)\s*ms", output, re.I)
    ttl_match = re.search(r"ttl[=:]\s*(\d+)", output, re.I)
    latency = float(latency_match.group(1)) if latency_match else None
    ttl = int(ttl_match.group(1)) if ttl_match else None

    if latency_match:
        status = "online"
    elif "unreachable" in lower:
        status = "unreachable"
    elif "timed out" in lower or "100% loss" in lower or "100% packet loss" in lower:
        status = "offline"
    else:
        status = "offline"

    return {"status": status, "latency_ms": latency, "ttl": ttl, "raw": output.strip()}


def guess_os_from_ttl(ttl):
    """Very rough OS family guess from the observed TTL (heuristic only —
    intermediate hops decrement TTL, so this is never conclusive)."""
    if ttl is None:
        return "Unknown"
    if ttl > 128:
        return "Cisco/Solaris/Network device (TTL~255)"
    if ttl > 64:
        return "Windows (TTL~128)"
    return "Linux/Unix/macOS (TTL~64)"


def get_mac_address(ip):
    """Look up the MAC address for a LOCAL SUBNET host via the OS ARP
    cache. Returns the MAC string or None if not found (host is off-subnet,
    or hasn't been contacted yet — call ping_host() first)."""
    try:
        if IS_WINDOWS:
            proc = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=5)
            for line in proc.stdout.splitlines():
                m = re.search(r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", line)
                if m:
                    return m.group(1).replace("-", ":").upper()
        else:
            proc = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=5)
            m = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", proc.stdout)
            if m:
                return m.group(1).upper()
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def reverse_dns(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def forward_dns(target):
    """All addresses a hostname resolves to (empty list on failure)."""
    try:
        infos = socket.getaddrinfo(target, None)
        addrs = sorted({info[4][0] for info in infos})
        return addrs
    except socket.gaierror:
        return []


def get_local_network_info():
    """Local machine's hostname, primary IP, and (on Windows) a parsed
    summary of ipconfig /all — adapter names, IPv4 addrs, subnet masks,
    default gateways, DNS servers, and MAC addresses."""
    info = {"hostname": socket.gethostname(), "primary_ip": None, "adapters": []}
    try:
        info["primary_ip"] = socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        pass

    if not IS_WINDOWS:
        return info

    try:
        proc = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=8)
        output = proc.stdout
    except (subprocess.TimeoutExpired, OSError):
        return info

    blocks = re.split(r"\r?\n\r?\n(?=\S)", output)
    for block in blocks:
        header_match = re.match(r"([^\r\n:]+):", block)
        if not header_match or "adapter" not in header_match.group(1).lower():
            continue
        name = header_match.group(1).replace("Ethernet adapter", "").replace(
            "Wireless LAN adapter", "").strip(" :")
        ipv4 = re.search(r"IPv4 Address[.\s]*:\s*([\d.]+)", block)
        mask = re.search(r"Subnet Mask[.\s]*:\s*([\d.]+)", block)
        gateway = re.search(r"Default Gateway[.\s]*:\s*([\d.]+)", block)
        mac = re.search(r"Physical Address[.\s]*:\s*([0-9A-Fa-f-]{17})", block)
        dns = re.findall(r"DNS Servers[.\s]*:\s*([\d.]+)", block)
        if not ipv4:
            continue
        info["adapters"].append({
            "name": name,
            "ipv4": ipv4.group(1) if ipv4 else None,
            "subnet_mask": mask.group(1) if mask else None,
            "gateway": gateway.group(1) if gateway else None,
            "mac": mac.group(1).replace("-", ":").upper() if mac else None,
            "dns_servers": dns,
        })
    return info


def traceroute(target, max_hops=20, timeout=2.0):
    """Run the OS traceroute utility and parse hop IPs + latency.
    Can take several seconds to tens of seconds — call from a worker
    thread, never the UI thread."""
    if IS_WINDOWS:
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), target]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(int(timeout)), target]

    hops = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max_hops * timeout + 10)
        output = proc.stdout
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"hops": [], "error": str(exc)}

    for line in output.splitlines():
        m = re.match(r"\s*(\d+)\s+(.*)", line)
        if not m:
            continue
        hop_num = int(m.group(1))
        rest = m.group(2)
        if "*" in rest and not re.search(r"\d+\.\d+\.\d+\.\d+", rest):
            hops.append({"hop": hop_num, "ip": None, "latency_ms": None, "timeout": True})
            continue
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
        latencies = [float(x) for x in re.findall(r"([\d.]+)\s*ms", rest)]
        if ip_match:
            hops.append({
                "hop": hop_num,
                "ip": ip_match.group(1),
                "latency_ms": sum(latencies) / len(latencies) if latencies else None,
                "timeout": False,
            })
    return {"hops": hops, "error": None}
