"""Offline OUI vendor lookup for MAC addresses."""
from __future__ import annotations

from typing import Dict, Optional

# Minimal offline OUI mapping (uppercase hex without separators).
# Extend as needed without requiring network access.
OUI_VENDOR_MAP: Dict[str, str] = {
    "001A2B": "Cisco Systems",
    "001B63": "Apple",
    "00259C": "Apple",
    "3C5A37": "Google",
    "F4F5D8": "Microsoft",
    "F0F1A1": "Intel",
    "B827EB": "Raspberry Pi",
    "000C29": "VMware",
    "000D93": "Dell",
    "0016EA": "Hewlett Packard",
    "5C514F": "Samsung",
}


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    cleaned = mac.replace(":", "").replace("-", "").replace(".", "").upper()
    if len(cleaned) < 12:
        return None
    return cleaned


def lookup_vendor(mac: Optional[str]) -> str:
    normalized = normalize_mac(mac)
    if not normalized:
        return "Unknown"
    oui = normalized[:6]
    return OUI_VENDOR_MAP.get(oui, "Unknown")
