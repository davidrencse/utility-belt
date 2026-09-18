"""Protocol mix analyzer."""
from __future__ import annotations

from typing import Dict, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@register_analyzer
class ProtocolMixAnalyzer(Analyzer):
    name = "protocol_mix"
    version = "1.0"

    def __init__(self):
        self.counts: Dict[str, int] = {}
        self.total = 0

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        label = _classify_l4(packet)
        self.counts[label] = self.counts.get(label, 0) + 1
        self.total += 1

    def on_end(self, context) -> AnalyzerResult:
        percentages = {}
        if self.total:
            for key, count in self.counts.items():
                percentages[key] = round((count / self.total) * 100.0, 2)
        return AnalyzerResult(
            analyzer=self.name,
            global_results={
                "total_packets": self.total,
                "protocol_counts": self.counts,
                "protocol_percentages": percentages,
            },
        )


def _classify_l4(packet: AnalysisPacket) -> str:
    if packet.l4_protocol:
        return packet.l4_protocol.upper()
    if packet.ip_protocol == 1:
        return "ICMP"
    if packet.ip_protocol == 6:
        return "TCP"
    if packet.ip_protocol == 17:
        return "UDP"
    if packet.ip_protocol == 58:
        return "ICMP6"
    if packet.ip_protocol == 0:
        return "UNKNOWN"
    return "OTHER"
