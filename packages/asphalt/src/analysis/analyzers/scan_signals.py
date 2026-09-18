"""Scan-like behavior signals."""
from __future__ import annotations

from typing import Dict, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@register_analyzer
class ScanSignalsAnalyzer(Analyzer):
    name = "scan_signals"
    version = "1.0"

    def __init__(self, max_set_size: int = 1024):
        self.max_set_size = max(1, max_set_size)
        self.dst_ports: Dict[str, set] = {}
        self.dst_ips: Dict[str, set] = {}
        self.syn_count = 0
        self.synack_count = 0

    def _add_to_set(self, table: Dict[str, set], src_ip: str, value) -> None:
        entry = table.get(src_ip)
        if entry is None:
            entry = set()
            table[src_ip] = entry
        if len(entry) < self.max_set_size:
            entry.add(value)

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        if packet.src_ip and packet.dst_ip:
            self._add_to_set(self.dst_ips, packet.src_ip, packet.dst_ip)
        if packet.src_ip and packet.dst_port is not None:
            self._add_to_set(self.dst_ports, packet.src_ip, int(packet.dst_port))

        if packet.ip_protocol == 6 or packet.l4_protocol == "TCP":
            flags = packet.tcp_flags or 0
            is_syn = bool(flags & 0x02)
            is_ack = bool(flags & 0x10)
            if is_syn and not is_ack:
                self.syn_count += 1
            if is_syn and is_ack:
                self.synack_count += 1

    def _max_set(self, table: Dict[str, set]):
        max_count = 0
        max_src = None
        for src, values in table.items():
            count = len(values)
            if count > max_count or (count == max_count and max_src and src < max_src):
                max_count = count
                max_src = src
        return max_count, max_src

    def on_end(self, context) -> AnalyzerResult:
        ports_max, ports_src = self._max_set(self.dst_ports)
        ips_max, ips_src = self._max_set(self.dst_ips)
        ratio = None
        ratio_note = None
        if self.synack_count > 0:
            ratio = round(self.syn_count / self.synack_count, 3)
        elif self.syn_count > 0:
            ratio_note = "synack_zero"
        else:
            ratio = 0.0

        return AnalyzerResult(
            analyzer=self.name,
            global_results={
                "distinct_ports": {
                    "max_count": ports_max,
                    "src_ip": ports_src,
                },
                "distinct_ips": {
                    "max_count": ips_max,
                    "src_ip": ips_src,
                },
                "tcp_syn_ratio": {
                    "syn_count": self.syn_count,
                    "synack_count": self.synack_count,
                    "ratio": ratio,
                    "ratio_note": ratio_note,
                },
            },
        )
