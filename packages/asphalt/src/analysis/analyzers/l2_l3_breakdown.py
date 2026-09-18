"""L2/L3 breakdown analyzer."""
from __future__ import annotations

from typing import Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@register_analyzer
class L2L3BreakdownAnalyzer(Analyzer):
    name = "l2_l3_breakdown"
    version = "1.0"

    def __init__(self):
        self.ethernet_frames = 0
        self.vlan_frames = 0
        self.arp_packets = 0
        self.icmp_packets = 0
        self.icmpv6_packets = 0
        self.multicast_packets = 0
        self.broadcast_packets = 0

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        if packet.link_type == 1:  # DLT_EN10MB
            self.ethernet_frames += 1

        if packet.is_vlan:
            self.vlan_frames += 1
        if packet.is_arp:
            self.arp_packets += 1
        if packet.ip_protocol == 1:
            self.icmp_packets += 1
        if packet.ip_protocol == 58:
            self.icmpv6_packets += 1

        if packet.is_multicast:
            self.multicast_packets += 1
        if packet.is_broadcast:
            self.broadcast_packets += 1

    def on_end(self, context) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer=self.name,
            global_results={
                "ethernet_frames": self.ethernet_frames,
                "vlan_frames": self.vlan_frames,
                "arp_packets": self.arp_packets,
                "icmp_packets": self.icmp_packets,
                "icmpv6_packets": self.icmpv6_packets,
                "multicast_packets": self.multicast_packets,
                "broadcast_packets": self.broadcast_packets,
            },
        )
