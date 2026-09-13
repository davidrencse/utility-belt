"""ARP/LAN attack signals."""
from __future__ import annotations

from typing import Dict, List, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@register_analyzer
class ArpLanSignalsAnalyzer(Analyzer):
    name = "arp_lan_signals"
    version = "1.0"

    def __init__(self, change_threshold: int = 1, max_examples: int = 5):
        self.change_threshold = max(1, change_threshold)
        self.max_examples = max(1, max_examples)
        self.current_mac: Dict[str, str] = {}
        self.macs_seen: Dict[str, set] = {}
        self.change_counts: Dict[str, int] = {}

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        if not packet.is_arp:
            return
        ip = packet.arp_sender_ip
        mac = packet.arp_sender_mac
        if not ip or not mac:
            return
        seen = self.macs_seen.setdefault(ip, set())
        seen.add(mac)
        current = self.current_mac.get(ip)
        if current is None:
            self.current_mac[ip] = mac
            self.change_counts.setdefault(ip, 0)
            return
        if current != mac:
            self.current_mac[ip] = mac
            self.change_counts[ip] = self.change_counts.get(ip, 0) + 1

    def on_end(self, context) -> AnalyzerResult:
        multiple = []
        for ip, macs in self.macs_seen.items():
            if len(macs) > 1:
                multiple.append({"ip": ip, "macs": sorted(macs)})
        multiple.sort(key=lambda item: (len(item["macs"]) * -1, item["ip"]))

        changes = []
        for ip, count in self.change_counts.items():
            if count > self.change_threshold:
                changes.append({"ip": ip, "changes": count})
        changes.sort(key=lambda item: (-item["changes"], item["ip"]))

        return AnalyzerResult(
            analyzer=self.name,
            global_results={
                "multiple_macs": {
                    "count": sum(1 for ip, macs in self.macs_seen.items() if len(macs) > 1),
                    "examples": multiple[:self.max_examples],
                },
                "arp_changes": {
                    "count": len(changes),
                    "threshold": self.change_threshold,
                    "top_changes": changes[:self.max_examples],
                },
            },
        )
