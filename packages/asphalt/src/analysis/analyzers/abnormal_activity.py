"""Abnormal activity heuristics."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Set

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@dataclass
class _HandshakeState:
    syn_seen: bool = False
    synack_seen: bool = False
    ack_seen: bool = False


@register_analyzer
class AbnormalActivityAnalyzer(Analyzer):
    name = "abnormal_activity"
    version = "1.0"

    def __init__(self, scan_port_threshold: int = 20, rst_ratio_threshold: float = 0.2):
        self.scan_port_threshold = scan_port_threshold
        self.rst_ratio_threshold = rst_ratio_threshold
        self.malformed_packets = 0
        self.truncated_packets = 0
        self.tcp_packets = 0
        self.tcp_rst_packets = 0
        self.tcp_syn_packets = 0
        self.tcp_synack_packets = 0
        self.tcp_ack_packets = 0
        self.per_src_ports: Dict[str, Set[int]] = {}
        self.flow_handshakes: Dict[str, _HandshakeState] = {}

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        if packet.quality_flags:
            self.malformed_packets += 1
            if packet.quality_flags & (1 << 0):
                self.truncated_packets += 1

        if packet.src_ip and packet.dst_port is not None:
            ports = self.per_src_ports.setdefault(packet.src_ip, set())
            ports.add(int(packet.dst_port))

        if packet.l4_protocol == "TCP" or packet.ip_protocol == 6:
            self.tcp_packets += 1
            flags = packet.tcp_flags or 0
            is_syn = bool(flags & 0x02)
            is_ack = bool(flags & 0x10)
            is_rst = bool(flags & 0x04)

            if is_syn and is_ack:
                self.tcp_synack_packets += 1
            elif is_syn:
                self.tcp_syn_packets += 1
            if is_ack and not is_syn:
                self.tcp_ack_packets += 1
            if is_rst:
                self.tcp_rst_packets += 1

            if flow_state is not None:
                state = self.flow_handshakes.setdefault(flow_state.flow_id, _HandshakeState())
                if is_syn and not is_ack:
                    state.syn_seen = True
                elif is_syn and is_ack:
                    state.synack_seen = True
                elif is_ack and not is_syn:
                    state.ack_seen = True

    def on_end(self, context) -> AnalyzerResult:
        findings = []

        if self.malformed_packets:
            findings.append({
                "type": "malformed_packets",
                "severity": "medium",
                "count": self.malformed_packets,
            })

        if self.tcp_packets:
            rst_ratio = self.tcp_rst_packets / self.tcp_packets
            if rst_ratio >= self.rst_ratio_threshold:
                findings.append({
                    "type": "high_tcp_rst_ratio",
                    "severity": "medium",
                    "ratio": round(rst_ratio, 3),
                    "count": self.tcp_rst_packets,
                })

        scan_sources = []
        for src_ip, ports in self.per_src_ports.items():
            if len(ports) >= self.scan_port_threshold:
                scan_sources.append({"src_ip": src_ip, "unique_dst_ports": len(ports)})
        if scan_sources:
            findings.append({
                "type": "possible_port_scan",
                "severity": "high",
                "sources": scan_sources,
            })

        syn_only = 0
        synack_no_ack = 0
        for state in self.flow_handshakes.values():
            if state.syn_seen and not state.synack_seen and not state.ack_seen:
                syn_only += 1
            elif state.syn_seen and state.synack_seen and not state.ack_seen:
                synack_no_ack += 1

        if syn_only:
            findings.append({
                "type": "syn_without_reply",
                "severity": "medium",
                "flows": syn_only,
            })
        if synack_no_ack:
            findings.append({
                "type": "synack_without_ack",
                "severity": "low",
                "flows": synack_no_ack,
            })

        return AnalyzerResult(
            analyzer=self.name,
            global_results={
                "malformed_packets": self.malformed_packets,
                "truncated_packets": self.truncated_packets,
                "tcp_packets": self.tcp_packets,
                "tcp_rst_packets": self.tcp_rst_packets,
                "tcp_syn_packets": self.tcp_syn_packets,
                "tcp_synack_packets": self.tcp_synack_packets,
                "tcp_ack_packets": self.tcp_ack_packets,
                "scan_port_threshold": self.scan_port_threshold,
                "findings": findings,
            },
        )
