"""Global packet statistics analyzer."""
from __future__ import annotations

from typing import Dict, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer

@register_analyzer
class GlobalStatsAnalyzer(Analyzer):
    name = "global_stats"
    version = "1.0"

    def __init__(self):
        self.ip_versions: Dict[str, int] = {}
        self.l4_protocols: Dict[str, int] = {}
        self.quality_flags: Dict[str, int] = {}
        self.tcp_flags: Dict[str, int] = {}

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        if packet.ip_version:
            key = str(packet.ip_version)
            self.ip_versions[key] = self.ip_versions.get(key, 0) + 1
        if packet.l4_protocol:
            self.l4_protocols[packet.l4_protocol] = self.l4_protocols.get(packet.l4_protocol, 0) + 1
        if packet.quality_flags != 0:
            key = str(packet.quality_flags)
            self.quality_flags[key] = self.quality_flags.get(key, 0) + 1
        if packet.tcp_flags is not None:
            for name in _tcp_flag_names(packet.tcp_flags):
                self.tcp_flags[name] = self.tcp_flags.get(name, 0) + 1

    def on_end(self, context) -> AnalyzerResult:
        duration_us = context.stats.get("duration_us", 0)
        return AnalyzerResult(
            analyzer=self.name,
            global_results={
                "packets_total": context.stats.get("packets_total", 0),
                "bytes_captured_total": context.stats.get("bytes_captured_total", 0),
                "bytes_original_total": context.stats.get("bytes_original_total", 0),
                "duration_us": duration_us,
                "ip_versions": self.ip_versions,
                "l4_protocols": self.l4_protocols,
                "quality_flags": self.quality_flags,
                "tcp_flags": self.tcp_flags,
            },
        )

def _tcp_flag_names(flags: int):
    names = []
    flag_map = [
        (0x80, "CWR"),
        (0x40, "ECE"),
        (0x20, "URG"),
        (0x10, "ACK"),
        (0x08, "PSH"),
        (0x04, "RST"),
        (0x02, "SYN"),
        (0x01, "FIN"),
    ]
    for mask, name in flag_map:
        if flags & mask:
            names.append(name)
    return tuple(names)
