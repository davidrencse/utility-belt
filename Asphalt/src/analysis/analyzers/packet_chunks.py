"""Packet chunk analyzer (count-based)."""
from __future__ import annotations

from typing import Dict, Optional, Set

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@register_analyzer
class PacketChunksAnalyzer(Analyzer):
    name = "packet_chunks"
    version = "1.0"

    def __init__(self, chunk_size: int = 200):
        self.chunk_size = max(1, chunk_size)
        self.current = None
        self.chunks = []

    def _start_chunk(self, packet: AnalysisPacket) -> None:
        self.current = {
            "start_us": packet.timestamp_us,
            "end_us": packet.timestamp_us,
            "packets": 0,
            "bytes_captured": 0,
            "bytes_original": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "malformed_packets": 0,
            "flows": set(),
        }

    def _finalize_chunk(self) -> None:
        if not self.current:
            return
        payload = dict(self.current)
        payload["flows"] = len(payload["flows"])
        self.chunks.append(payload)
        self.current = None

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        if self.current is None:
            self._start_chunk(packet)

        self.current["end_us"] = packet.timestamp_us
        self.current["packets"] += 1
        self.current["bytes_captured"] += packet.captured_length
        self.current["bytes_original"] += packet.original_length

        if packet.l4_protocol == "TCP" or packet.ip_protocol == 6:
            self.current["tcp_packets"] += 1
        if packet.l4_protocol == "UDP" or packet.ip_protocol == 17:
            self.current["udp_packets"] += 1
        if packet.quality_flags:
            self.current["malformed_packets"] += 1

        if flow_state is not None:
            self.current["flows"].add(flow_state.flow_id)

        if self.current["packets"] >= self.chunk_size:
            self._finalize_chunk()

    def on_end(self, context) -> AnalyzerResult:
        self._finalize_chunk()
        return AnalyzerResult(
            analyzer=self.name,
            time_series={
                "chunk_size": self.chunk_size,
                "chunks": self.chunks,
            },
        )
