"""TCP reliability analyzer (retransmissions, out-of-order, dup ACKs, RST rate)."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Dict, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@dataclass
class _FlowReliabilityState:
    last_seen_us: int
    last_seq: Dict[str, int]
    recent_seqs: Dict[str, deque]
    last_ack: Dict[str, Optional[int]]
    last_ack_repeats: Dict[str, int]
    tcp_packets: int = 0
    retransmissions: int = 0
    out_of_order: int = 0
    dup_acks: int = 0
    rst_packets: int = 0


@register_analyzer
class TcpReliabilityAnalyzer(Analyzer):
    name = "tcp_reliability"
    version = "1.0"

    def __init__(self, max_flows: int = 10000, idle_timeout_us: int = 60_000_000, seq_window: int = 20):
        self.max_flows = max(1, max_flows)
        self.idle_timeout_us = max(0, idle_timeout_us)
        self.seq_window = max(1, seq_window)
        self.flows: Dict[str, _FlowReliabilityState] = {}
        self.total_tcp_packets = 0
        self.total_retransmissions = 0
        self.total_out_of_order = 0
        self.total_dup_acks = 0
        self.total_rst = 0

    def _purge(self, now_us: int) -> None:
        if self.idle_timeout_us and self.flows:
            stale = [fid for fid, state in self.flows.items()
                     if now_us - state.last_seen_us > self.idle_timeout_us]
            for fid in stale:
                del self.flows[fid]
        if len(self.flows) <= self.max_flows:
            return
        items = sorted(self.flows.items(), key=lambda kv: (kv[1].last_seen_us, kv[0]))
        for fid, _ in items[:len(self.flows) - self.max_flows]:
            del self.flows[fid]

    def _flow_state(self, flow_id: str, ts_us: int) -> _FlowReliabilityState:
        state = self.flows.get(flow_id)
        if state is None:
            state = _FlowReliabilityState(
                last_seen_us=ts_us,
                last_seq={"fwd": 0, "rev": 0},
                recent_seqs={"fwd": deque(maxlen=self.seq_window), "rev": deque(maxlen=self.seq_window)},
                last_ack={"fwd": None, "rev": None},
                last_ack_repeats={"fwd": 0, "rev": 0},
            )
            self.flows[flow_id] = state
        return state

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        if packet.ip_protocol != 6 and packet.l4_protocol != "TCP":
            return
        if flow_key is None or packet.tcp_seq is None:
            return

        ts_us = packet.timestamp_us or 0
        self._purge(ts_us)
        state = self._flow_state(flow_state.flow_id if flow_state else flow_key.to_dict().__str__(), ts_us)
        direction = flow_key.direction.value if flow_key else "fwd"

        state.last_seen_us = ts_us
        state.tcp_packets += 1
        self.total_tcp_packets += 1

        flags = packet.tcp_flags or 0
        is_syn = bool(flags & 0x02)
        is_fin = bool(flags & 0x01)
        is_rst = bool(flags & 0x04)
        is_ack = bool(flags & 0x10)
        if is_rst:
            state.rst_packets += 1
            self.total_rst += 1

        seq = packet.tcp_seq
        if seq in state.recent_seqs[direction]:
            state.retransmissions += 1
            self.total_retransmissions += 1
        else:
            state.recent_seqs[direction].append(seq)

        last_seq = state.last_seq[direction]
        if last_seq and seq < last_seq and not is_syn and not is_fin:
            state.out_of_order += 1
            self.total_out_of_order += 1
        if seq > last_seq:
            state.last_seq[direction] = seq

        ack = packet.tcp_ack if is_ack else None
        if ack is not None:
            if state.last_ack[direction] == ack:
                state.last_ack_repeats[direction] += 1
                state.dup_acks += 1
                self.total_dup_acks += 1
            else:
                state.last_ack[direction] = ack
                state.last_ack_repeats[direction] = 0

    def on_end(self, context) -> AnalyzerResult:
        total = self.total_tcp_packets
        rst_rate = round(self.total_rst / total, 4) if total else 0.0
        retrans_rate = round(self.total_retransmissions / total, 4) if total else 0.0
        out_of_order_rate = round(self.total_out_of_order / total, 4) if total else 0.0
        dup_ack_rate = round(self.total_dup_acks / total, 4) if total else 0.0
        return AnalyzerResult(
            analyzer=self.name,
            global_results={
                "tcp_packets": total,
                "retransmissions": self.total_retransmissions,
                "retransmission_rate": retrans_rate,
                "out_of_order": self.total_out_of_order,
                "out_of_order_rate": out_of_order_rate,
                "dup_acks": self.total_dup_acks,
                "dup_ack_rate": dup_ack_rate,
                "rst_packets": self.total_rst,
                "rst_rate": rst_rate,
            },
        )
