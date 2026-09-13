"""OSI tagging helpers (view/query layer only)."""
from __future__ import annotations

from typing import Iterable, List


def _add(tags: List[str], value: str) -> None:
    if value not in tags:
        tags.append(value)


def derive_osi_tags_from_decoded(record) -> List[str]:
    """Derive OSI tags from a decoded packet dict or DecodedPacket-like object."""
    if record is None:
        return []
    if isinstance(record, dict):
        is_arp = bool(record.get("is_arp"))
        ip_version = record.get("ip_version")
        l4 = record.get("l4_protocol")
        dns_qname = record.get("dns_qname")
    else:
        is_arp = bool(getattr(record, "is_arp", False))
        ip_version = getattr(record, "ip_version", None)
        l4 = getattr(record, "l4_protocol", None)
        dns_qname = getattr(record, "dns_qname", None)

    tags: List[str] = []
    # L2
    if is_arp:
        _add(tags, "l2:arp")
    else:
        _add(tags, "l2:ethernet")
    # L3
    if ip_version == 4:
        _add(tags, "l3:ipv4")
    elif ip_version == 6:
        _add(tags, "l3:ipv6")
    # L4
    if l4:
        l4_val = str(l4).lower()
        if l4_val in ("tcp", "udp"):
            _add(tags, f"l4:{l4_val}")
    # APP
    if dns_qname:
        _add(tags, "app:dns")
    return tags


def derive_osi_tags_from_analysis_packet(packet) -> List[str]:
    return derive_osi_tags_from_decoded(packet)


def derive_osi_tags_from_flow(flow) -> List[str]:
    tags: List[str] = []
    if flow is None:
        return tags
    if isinstance(flow, dict):
        ip_versions = flow.get("ip_versions", {}) or {}
        proto = flow.get("ip_protocol")
        dns_seen = flow.get("dns_seen", False)
    else:
        ip_versions = getattr(flow, "ip_versions", {}) or {}
        proto = getattr(flow, "ip_protocol", None)
        dns_seen = getattr(flow, "dns_seen", False)
    if "4" in ip_versions or 4 in ip_versions:
        _add(tags, "l3:ipv4")
    if "6" in ip_versions or 6 in ip_versions:
        _add(tags, "l3:ipv6")
    if proto == 6:
        _add(tags, "l4:tcp")
    elif proto == 17:
        _add(tags, "l4:udp")
    if dns_seen:
        _add(tags, "app:dns")
    return tags


def count_tags(tag_lists: Iterable[Iterable[str]]) -> dict:
    summary = {
        "l2": {"ethernet": 0, "arp": 0},
        "l3": {"ipv4": 0, "ipv6": 0},
        "l4": {"tcp": 0, "udp": 0},
        "app": {"dns": 0},
    }
    for tags in tag_lists:
        for tag in tags:
            if not isinstance(tag, str) or ":" not in tag:
                continue
            layer, value = tag.split(":", 1)
            if layer in summary and value in summary[layer]:
                summary[layer][value] += 1
    return summary
