"""Top entities analyzer: IP talkers, MAC talkers, and ports/services."""
from __future__ import annotations

from collections import defaultdict
from ipaddress import ip_address
from typing import Dict, Optional, Tuple, List

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer
from utils.oui_lookup import lookup_vendor


_SERVICE_MAP = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    993: "IMAPS",
    995: "POP3S",
    5353: "mDNS",
}


def _is_internal_ip(ip: str) -> bool:
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return True
    return False


def _sort_top(entries: Dict[str, Dict[str, int]], top_n: int) -> List[Tuple[str, Dict[str, int]]]:
    items = list(entries.items())
    items.sort(key=lambda item: (-item[1]["bytes"], -item[1]["packets"], item[0]))
    return items[:top_n]


@register_analyzer
class TopEntitiesAnalyzer(Analyzer):
    name = "top_entities"
    version = "1.0"

    def __init__(self, top_n: int = 5):
        self.top_n = max(1, top_n)
        self.src_ip: Dict[str, Dict[str, int]] = defaultdict(lambda: {"bytes": 0, "packets": 0})
        self.dst_ip: Dict[str, Dict[str, int]] = defaultdict(lambda: {"bytes": 0, "packets": 0})
        self.src_mac: Dict[str, Dict[str, int]] = defaultdict(lambda: {"bytes": 0, "packets": 0})
        self.dst_mac: Dict[str, Dict[str, int]] = defaultdict(lambda: {"bytes": 0, "packets": 0})
        self.tcp_ports: Dict[int, int] = defaultdict(int)
        self.udp_ports: Dict[int, int] = defaultdict(int)
        self.tcp_total = 0
        self.udp_total = 0
        self.total_bytes = 0
        self.total_packets = 0
        self.internal_bytes = 0
        self.internal_packets = 0

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        size = int(packet.captured_length or 0)
        self.total_bytes += size
        self.total_packets += 1

        if packet.src_ip:
            entry = self.src_ip[packet.src_ip]
            entry["bytes"] += size
            entry["packets"] += 1
            if _is_internal_ip(packet.src_ip):
                self.internal_bytes += size
                self.internal_packets += 1

        if packet.dst_ip:
            entry = self.dst_ip[packet.dst_ip]
            entry["bytes"] += size
            entry["packets"] += 1

        if packet.src_mac:
            entry = self.src_mac[packet.src_mac]
            entry["bytes"] += size
            entry["packets"] += 1

        if packet.dst_mac:
            entry = self.dst_mac[packet.dst_mac]
            entry["bytes"] += size
            entry["packets"] += 1

        if packet.l4_protocol == "TCP" or packet.ip_protocol == 6:
            if packet.dst_port is not None:
                self.tcp_ports[int(packet.dst_port)] += 1
            self.tcp_total += 1
        elif packet.l4_protocol == "UDP" or packet.ip_protocol == 17:
            if packet.dst_port is not None:
                self.udp_ports[int(packet.dst_port)] += 1
            self.udp_total += 1

    def _ip_entries(self, entries: Dict[str, Dict[str, int]]) -> List[Dict[str, object]]:
        total_bytes = self.total_bytes
        total_packets = self.total_packets
        results = []
        for ip, stats in _sort_top(entries, self.top_n):
            bytes_pct = round((stats["bytes"] / total_bytes) * 100.0, 2) if total_bytes else 0.0
            packets_pct = round((stats["packets"] / total_packets) * 100.0, 2) if total_packets else 0.0
            results.append({
                "ip": ip,
                "bytes": stats["bytes"],
                "packets": stats["packets"],
                "bytes_pct": bytes_pct,
                "packets_pct": packets_pct,
                "is_internal": _is_internal_ip(ip),
            })
        return results

    def _mac_entries(self, entries: Dict[str, Dict[str, int]]) -> List[Dict[str, object]]:
        total_bytes = self.total_bytes
        total_packets = self.total_packets
        results = []
        for mac, stats in _sort_top(entries, self.top_n):
            bytes_pct = round((stats["bytes"] / total_bytes) * 100.0, 2) if total_bytes else 0.0
            packets_pct = round((stats["packets"] / total_packets) * 100.0, 2) if total_packets else 0.0
            results.append({
                "mac": mac,
                "vendor": lookup_vendor(mac),
                "bytes": stats["bytes"],
                "packets": stats["packets"],
                "bytes_pct": bytes_pct,
                "packets_pct": packets_pct,
            })
        return results

    def _vendor_distribution(self) -> List[Dict[str, object]]:
        totals: Dict[str, Dict[str, int]] = defaultdict(lambda: {"bytes": 0, "packets": 0})
        for mac, stats in self.src_mac.items():
            vendor = lookup_vendor(mac)
            totals[vendor]["bytes"] += stats["bytes"]
            totals[vendor]["packets"] += stats["packets"]
        for mac, stats in self.dst_mac.items():
            vendor = lookup_vendor(mac)
            totals[vendor]["bytes"] += stats["bytes"]
            totals[vendor]["packets"] += stats["packets"]

        total_bytes = self.total_bytes
        items = list(totals.items())
        items.sort(key=lambda item: (-item[1]["bytes"], -item[1]["packets"], item[0]))
        results = []
        for vendor, stats in items[:self.top_n]:
            bytes_pct = round((stats["bytes"] / total_bytes) * 100.0, 2) if total_bytes else 0.0
            results.append({
                "vendor": vendor,
                "bytes": stats["bytes"],
                "packets": stats["packets"],
                "bytes_pct": bytes_pct,
            })
        return results

    def _port_entries(self, counts: Dict[int, int], total: int) -> List[Dict[str, object]]:
        items = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        results = []
        for port, count in items[:self.top_n]:
            pct = round((count / total) * 100.0, 2) if total else 0.0
            results.append({
                "port": port,
                "service": _SERVICE_MAP.get(port, "unknown"),
                "packets": count,
                "packets_pct": pct,
            })
        return results

    def on_end(self, context) -> AnalyzerResult:
        external_bytes = self.total_bytes - self.internal_bytes
        external_packets = self.total_packets - self.internal_packets

        internal_bytes_pct = round((self.internal_bytes / self.total_bytes) * 100.0, 2) if self.total_bytes else 0.0
        external_bytes_pct = round((external_bytes / self.total_bytes) * 100.0, 2) if self.total_bytes else 0.0
        internal_packets_pct = round((self.internal_packets / self.total_packets) * 100.0, 2) if self.total_packets else 0.0
        external_packets_pct = round((external_packets / self.total_packets) * 100.0, 2) if self.total_packets else 0.0

        return AnalyzerResult(
            analyzer=self.name,
            global_results={
                "ip_talkers": {
                    "top_src": self._ip_entries(self.src_ip),
                    "top_dst": self._ip_entries(self.dst_ip),
                    "totals": {"bytes": self.total_bytes, "packets": self.total_packets},
                    "internal_external": {
                        "basis": "src_ip",
                        "internal_bytes_pct": internal_bytes_pct,
                        "external_bytes_pct": external_bytes_pct,
                        "internal_packets_pct": internal_packets_pct,
                        "external_packets_pct": external_packets_pct,
                    },
                },
                "mac_talkers": {
                    "top_src": self._mac_entries(self.src_mac),
                    "top_dst": self._mac_entries(self.dst_mac),
                    "vendor_distribution": self._vendor_distribution(),
                    "totals": {"bytes": self.total_bytes, "packets": self.total_packets},
                },
                "ports": {
                    "percentage_basis": "protocol_packets",
                    "tcp": {
                        "total_packets": self.tcp_total,
                        "top_dst_ports": self._port_entries(self.tcp_ports, self.tcp_total),
                    },
                    "udp": {
                        "total_packets": self.udp_total,
                        "top_dst_ports": self._port_entries(self.udp_ports, self.udp_total),
                    },
                },
            },
        )
