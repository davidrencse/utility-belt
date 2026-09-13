"""Analysis data models."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import json

try:
    from models.packet import DecodedPacket
except ImportError:
    from ..models.packet import DecodedPacket

class Direction(str, Enum):
    FWD = "fwd"
    REV = "rev"
    UNKNOWN = "unknown"

@dataclass(frozen=True)
class AnalysisPacket:
    """Normalized decoded packet for analysis."""
    packet_id: int
    timestamp_us: int
    captured_length: int
    original_length: int
    link_type: int
    eth_type: Optional[int]
    src_mac: Optional[str]
    dst_mac: Optional[str]
    ip_version: int
    src_ip: Optional[str]
    dst_ip: Optional[str]
    ip_protocol: int
    l4_protocol: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    tcp_flags: Optional[int]
    tcp_seq: Optional[int]
    tcp_ack: Optional[int]
    tcp_window: Optional[int]
    tcp_mss: Optional[int]
    arp_sender_ip: Optional[str]
    arp_sender_mac: Optional[str]
    dns_qname: Optional[str]
    dns_is_query: Optional[bool]
    dns_is_response: Optional[bool]
    dns_rcode: Optional[int]
    ttl: Optional[int]
    quality_flags: int
    is_vlan: bool = False
    is_arp: bool = False
    is_multicast: bool = False
    is_broadcast: bool = False
    is_ipv4_fragment: bool = False
    is_ipv6_fragment: bool = False
    protocol_stack: Tuple[str, ...] = field(default_factory=tuple)
    payload_bytes: Optional[bytes] = None

    @classmethod
    def from_decoded(cls, decoded: DecodedPacket) -> "AnalysisPacket":
        raw = decoded.raw_packet
        return cls(
            packet_id=raw.packet_id,
            timestamp_us=raw.timestamp_us,
            captured_length=raw.captured_length,
            original_length=raw.original_length,
            link_type=raw.link_type,
            eth_type=getattr(decoded, "eth_type", None),
            src_mac=getattr(decoded, "src_mac", None),
            dst_mac=getattr(decoded, "dst_mac", None),
            ip_version=decoded.ip_version,
            src_ip=decoded.src_ip,
            dst_ip=decoded.dst_ip,
            ip_protocol=decoded.ip_protocol,
            l4_protocol=decoded.l4_protocol,
            src_port=decoded.src_port,
            dst_port=decoded.dst_port,
            tcp_flags=decoded.tcp_flags,
            tcp_seq=getattr(decoded, "tcp_seq", None),
            tcp_ack=getattr(decoded, "tcp_ack", None),
            tcp_window=getattr(decoded, "tcp_window", None),
            tcp_mss=getattr(decoded, "tcp_mss", None),
            arp_sender_ip=getattr(decoded, "arp_sender_ip", None),
            arp_sender_mac=getattr(decoded, "arp_sender_mac", None),
            dns_qname=getattr(decoded, "dns_qname", None),
            dns_is_query=getattr(decoded, "dns_is_query", None),
            dns_is_response=getattr(decoded, "dns_is_response", None),
            dns_rcode=getattr(decoded, "dns_rcode", None),
            ttl=decoded.ttl,
            quality_flags=decoded.quality_flags,
            is_vlan=getattr(decoded, "is_vlan", False),
            is_arp=getattr(decoded, "is_arp", False),
            is_multicast=getattr(decoded, "is_multicast", False),
            is_broadcast=getattr(decoded, "is_broadcast", False),
            is_ipv4_fragment=getattr(decoded, "is_ipv4_fragment", False),
            is_ipv6_fragment=getattr(decoded, "is_ipv6_fragment", False),
            protocol_stack=decoded.protocol_stack,
            payload_bytes=raw.data,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packet_id": self.packet_id,
            "timestamp_us": self.timestamp_us,
            "captured_length": self.captured_length,
            "original_length": self.original_length,
            "link_type": self.link_type,
            "eth_type": self.eth_type,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "ip_version": self.ip_version,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ip_protocol": self.ip_protocol,
            "l4_protocol": self.l4_protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": self.tcp_flags,
            "tcp_seq": self.tcp_seq,
            "tcp_ack": self.tcp_ack,
            "tcp_window": self.tcp_window,
            "tcp_mss": self.tcp_mss,
            "arp_sender_ip": self.arp_sender_ip,
            "arp_sender_mac": self.arp_sender_mac,
            "dns_qname": self.dns_qname,
            "dns_is_query": self.dns_is_query,
            "dns_is_response": self.dns_is_response,
            "dns_rcode": self.dns_rcode,
            "ttl": self.ttl,
            "quality_flags": self.quality_flags,
            "is_vlan": self.is_vlan,
            "is_arp": self.is_arp,
            "is_multicast": self.is_multicast,
            "is_broadcast": self.is_broadcast,
            "is_ipv4_fragment": self.is_ipv4_fragment,
            "is_ipv6_fragment": self.is_ipv6_fragment,
            "protocol_stack": list(self.protocol_stack),
        }

@dataclass(frozen=True)
class FlowKey:
    """Five tuple plus protocol and direction for a packet."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ip_protocol: int
    direction: Direction

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "ip_protocol": self.ip_protocol,
            "direction": self.direction.value,
        }

@dataclass
class FlowState:
    """Aggregate state for a flow."""
    flow_id: str
    a_ip: str
    a_port: int
    b_ip: str
    b_port: int
    ip_protocol: int
    first_ts_us: int
    last_ts_us: int
    packets_total: int = 0
    packets_fwd: int = 0
    packets_rev: int = 0
    bytes_captured_total: int = 0
    bytes_captured_fwd: int = 0
    bytes_captured_rev: int = 0
    bytes_original_total: int = 0
    bytes_original_fwd: int = 0
    bytes_original_rev: int = 0
    ip_versions: Dict[str, int] = field(default_factory=dict)
    l4_protocols: Dict[str, int] = field(default_factory=dict)
    tcp_flags: Dict[str, int] = field(default_factory=dict)
    quality_flags: Dict[str, int] = field(default_factory=dict)
    has_fwd: bool = False
    has_rev: bool = False
    tcp_syn_seen: bool = False
    tcp_synack_seen: bool = False
    tcp_ack_seen: bool = False
    tcp_rst_seen: bool = False
    tcp_seen: bool = False
    udp_seen: bool = False
    dns_seen: bool = False

    def update_from_packet(self, packet: AnalysisPacket, direction: Direction) -> None:
        self.last_ts_us = max(self.last_ts_us, packet.timestamp_us)
        self.packets_total += 1
        self.bytes_captured_total += packet.captured_length
        self.bytes_original_total += packet.original_length

        if direction == Direction.FWD:
            self.packets_fwd += 1
            self.bytes_captured_fwd += packet.captured_length
            self.bytes_original_fwd += packet.original_length
            self.has_fwd = True
        elif direction == Direction.REV:
            self.packets_rev += 1
            self.bytes_captured_rev += packet.captured_length
            self.bytes_original_rev += packet.original_length
            self.has_rev = True

        if packet.ip_version:
            key = str(packet.ip_version)
            self.ip_versions[key] = self.ip_versions.get(key, 0) + 1
        if packet.l4_protocol:
            self.l4_protocols[packet.l4_protocol] = self.l4_protocols.get(packet.l4_protocol, 0) + 1

        if packet.tcp_flags is not None:
            for name in _tcp_flag_names(packet.tcp_flags):
                self.tcp_flags[name] = self.tcp_flags.get(name, 0) + 1
            self.tcp_seen = True
            flags = packet.tcp_flags
            is_syn = bool(flags & 0x02)
            is_ack = bool(flags & 0x10)
            is_rst = bool(flags & 0x04)
            if is_syn and not is_ack:
                self.tcp_syn_seen = True
            if is_syn and is_ack:
                self.tcp_synack_seen = True
            if is_ack and not is_syn:
                self.tcp_ack_seen = True
            if is_rst:
                self.tcp_rst_seen = True

        if packet.quality_flags != 0:
            self.quality_flags[str(packet.quality_flags)] = self.quality_flags.get(str(packet.quality_flags), 0) + 1

        if packet.l4_protocol == "UDP" or packet.ip_protocol == 17:
            self.udp_seen = True
        if packet.dns_qname:
            self.dns_seen = True

    def duration_us(self) -> int:
        if self.packets_total == 0:
            return 0
        return max(0, self.last_ts_us - self.first_ts_us)

    def to_dict(self) -> Dict[str, Any]:
        from .osi import derive_osi_tags_from_flow
        duration = self.duration_us()
        return {
            "flow_id": self.flow_id,
            "a_ip": self.a_ip,
            "a_port": self.a_port,
            "b_ip": self.b_ip,
            "b_port": self.b_port,
            "ip_protocol": self.ip_protocol,
            "first_ts_us": self.first_ts_us,
            "last_ts_us": self.last_ts_us,
            "duration_us": duration,
            "packets_total": self.packets_total,
            "packets_fwd": self.packets_fwd,
            "packets_rev": self.packets_rev,
            "bytes_captured_total": self.bytes_captured_total,
            "bytes_captured_fwd": self.bytes_captured_fwd,
            "bytes_captured_rev": self.bytes_captured_rev,
            "bytes_original_total": self.bytes_original_total,
            "bytes_original_fwd": self.bytes_original_fwd,
            "bytes_original_rev": self.bytes_original_rev,
            "ip_versions": self.ip_versions,
            "l4_protocols": self.l4_protocols,
            "tcp_flags": self.tcp_flags,
            "quality_flags": self.quality_flags,
            "dns_seen": self.dns_seen,
            "osi_tags": derive_osi_tags_from_flow(self),
        }

@dataclass(frozen=True)
class TimeSeriesPoint:
    start_us: int
    end_us: int
    packets: int
    bytes_captured: int
    bytes_original: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_us": self.start_us,
            "end_us": self.end_us,
            "packets": self.packets,
            "bytes_captured": self.bytes_captured,
            "bytes_original": self.bytes_original,
        }

@dataclass(frozen=True)
class AnalyzerResult:
    analyzer: str
    global_results: Dict[str, Any] = field(default_factory=dict)
    flow_results: Dict[str, Any] = field(default_factory=dict)
    time_series: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analyzer": self.analyzer,
            "global_results": self.global_results,
            "flow_results": self.flow_results,
            "time_series": self.time_series,
        }

@dataclass
class AnalysisReport:
    capture_path: Optional[str]
    created_at: str
    stats: Dict[str, Any]
    global_results: Dict[str, Any] = field(default_factory=dict)
    flow_results: Dict[str, Any] = field(default_factory=dict)
    time_series: Dict[str, Any] = field(default_factory=dict)
    osi_summary: Dict[str, Any] = field(default_factory=dict)
    analyzers: List[Dict[str, str]] = field(default_factory=list)

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capture_path": self.capture_path,
            "created_at": self.created_at,
            "stats": self.stats,
            "global_results": self.global_results,
            "flow_results": self.flow_results,
            "time_series": self.time_series,
            "osi_summary": self.osi_summary,
            "analyzers": self.analyzers,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=True)

def _tcp_flag_names(flags: int) -> Tuple[str, ...]:
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
