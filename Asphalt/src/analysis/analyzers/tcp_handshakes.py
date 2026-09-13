"""TCP handshake grouping analyzer."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@dataclass
class _Handshake:
    flow_id: str
    initiator: Optional[str] = None
    responder: Optional[str] = None
    syn_ts: Optional[int] = None
    synack_ts: Optional[int] = None
    ack_ts: Optional[int] = None
    syn_src: Optional[str] = None
    syn_dst: Optional[str] = None
    syn_port: Optional[int] = None
    syn_dst_port: Optional[int] = None


@register_analyzer
class TcpHandshakeAnalyzer(Analyzer):
    name = "tcp_handshakes"
    version = "1.0"

    def __init__(self):
        self.handshakes: Dict[str, _Handshake] = {}

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        if packet.ip_protocol != 6 and packet.l4_protocol != "TCP":
            return
        if flow_state is None:
            return

        flags = packet.tcp_flags or 0
        is_syn = bool(flags & 0x02)
        is_ack = bool(flags & 0x10)

        handshake = self.handshakes.get(flow_state.flow_id)
        if handshake is None:
            handshake = _Handshake(flow_id=flow_state.flow_id)
            self.handshakes[flow_state.flow_id] = handshake

        if is_syn and not is_ack and handshake.syn_ts is None:
            handshake.syn_ts = packet.timestamp_us
            handshake.syn_src = packet.src_ip
            handshake.syn_dst = packet.dst_ip
            handshake.syn_port = packet.src_port
            handshake.syn_dst_port = packet.dst_port
            handshake.initiator = f"{packet.src_ip}:{packet.src_port}"
            handshake.responder = f"{packet.dst_ip}:{packet.dst_port}"
            return

        if is_syn and is_ack and handshake.synack_ts is None:
            handshake.synack_ts = packet.timestamp_us
            return

        if is_ack and not is_syn and handshake.ack_ts is None:
            handshake.ack_ts = packet.timestamp_us

    def on_end(self, context) -> AnalyzerResult:
        results = []
        complete = 0
        incomplete = 0
        rtt_samples = []

        for handshake in self.handshakes.values():
            status = "incomplete"
            if handshake.syn_ts and handshake.synack_ts and handshake.ack_ts:
                status = "complete"
                complete += 1
            else:
                incomplete += 1

            rtt_synack = None
            rtt_ack = None
            if handshake.syn_ts and handshake.synack_ts:
                rtt_synack = handshake.synack_ts - handshake.syn_ts
                rtt_samples.append(rtt_synack)
            if handshake.syn_ts and handshake.ack_ts:
                rtt_ack = handshake.ack_ts - handshake.syn_ts

            results.append({
                "flow_id": handshake.flow_id,
                "initiator": handshake.initiator,
                "responder": handshake.responder,
                "syn_ts": handshake.syn_ts,
                "synack_ts": handshake.synack_ts,
                "ack_ts": handshake.ack_ts,
                "rtt_synack_us": rtt_synack,
                "rtt_ack_us": rtt_ack,
                "status": status,
            })

        total = len(self.handshakes)
        completion_rate = round(complete / total, 4) if total else 0.0
        rtt_median_ms = _percentile(rtt_samples, 50.0)
        rtt_p95_ms = _percentile(rtt_samples, 95.0)
        if rtt_median_ms is not None:
            rtt_median_ms = round(rtt_median_ms / 1000.0, 3)
        if rtt_p95_ms is not None:
            rtt_p95_ms = round(rtt_p95_ms / 1000.0, 3)

        return AnalyzerResult(
            analyzer=self.name,
            global_results={
                "handshakes_total": len(self.handshakes),
                "handshakes_complete": complete,
                "handshakes_incomplete": incomplete,
                "completion_rate": completion_rate,
                "rtt_median_ms": rtt_median_ms,
                "rtt_p95_ms": rtt_p95_ms,
            },
            flow_results={
                "handshakes": results,
            },
        )


def _percentile(values, percent: float):
    if not values:
        return None
    if len(values) == 1:
        return float(values[0])
    sorted_vals = sorted(values)
    position = (percent / 100.0) * (len(sorted_vals) - 1)
    lower = int(position)
    upper = min(lower + 1, len(sorted_vals) - 1)
    if lower == upper:
        return float(sorted_vals[lower])
    weight = position - lower
    return sorted_vals[lower] + (sorted_vals[upper] - sorted_vals[lower]) * weight
