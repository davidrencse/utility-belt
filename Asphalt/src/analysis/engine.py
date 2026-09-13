"""Analysis engine for decoded packets."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from .flow import make_flow_key, make_flow_key_from_fields
from .osi import count_tags, derive_osi_tags_from_analysis_packet, derive_osi_tags_from_decoded
from .models import AnalysisPacket, AnalysisReport, AnalyzerResult, FlowState
from .analyzers.base import Analyzer

@dataclass
class AnalysisContext:
    capture_path: Optional[str]
    stats: Dict[str, int]
    flow_table: Dict[str, FlowState]
    capture_info: Dict[str, object]
    osi_tags: List[List[str]]

class AnalysisEngine:
    def __init__(self,
                 analyzers: List[Analyzer],
                 capture_path: Optional[str] = None,
                 capture_info: Optional[Dict[str, object]] = None):
        self.analyzers = analyzers
        self.context = AnalysisContext(
            capture_path=capture_path,
            stats={
                "packets_total": 0,
                "bytes_captured_total": 0,
                "bytes_original_total": 0,
                "first_ts_us": 0,
                "last_ts_us": 0,
                "duration_us": 0,
            },
            flow_table={},
            capture_info=capture_info or {},
            osi_tags=[],
        )
        for analyzer in self.analyzers:
            analyzer.on_start(self.context)

    def process_packet(self, decoded) -> None:
        packet = AnalysisPacket.from_decoded(decoded)
        stats = self.context.stats
        stats["packets_total"] += 1
        stats["bytes_captured_total"] += packet.captured_length
        stats["bytes_original_total"] += packet.original_length
        if stats["first_ts_us"] == 0 or packet.timestamp_us < stats["first_ts_us"]:
            stats["first_ts_us"] = packet.timestamp_us
        if packet.timestamp_us > stats["last_ts_us"]:
            stats["last_ts_us"] = packet.timestamp_us
        if stats["first_ts_us"] and stats["last_ts_us"]:
            stats["duration_us"] = max(0, stats["last_ts_us"] - stats["first_ts_us"])

        self.context.osi_tags.append(derive_osi_tags_from_decoded(decoded))

        flow_key_data = make_flow_key(decoded)
        flow_key = None
        flow_state = None
        if flow_key_data:
            flow_id, flow_key, endpoints = flow_key_data
            flow_state = self.context.flow_table.get(flow_id)
            if flow_state is None:
                a_ip, a_port, b_ip, b_port = endpoints
                flow_state = FlowState(
                    flow_id=flow_id,
                    a_ip=a_ip,
                    a_port=a_port,
                    b_ip=b_ip,
                    b_port=b_port,
                    ip_protocol=int(decoded.ip_protocol),
                    first_ts_us=packet.timestamp_us,
                    last_ts_us=packet.timestamp_us,
                )
                self.context.flow_table[flow_id] = flow_state
            flow_state.update_from_packet(packet, flow_key.direction)

        for analyzer in self.analyzers:
            analyzer.on_packet(packet, flow_key, flow_state, self.context)

    def process_packet_dict(self, payload: Dict) -> None:
        packet = AnalysisPacket(
            packet_id=int(payload.get("packet_id", 0)),
            timestamp_us=int(payload.get("timestamp_us", 0)),
            captured_length=int(payload.get("captured_length", 0)),
            original_length=int(payload.get("original_length", 0)),
            link_type=int(payload.get("link_type", 0)),
            eth_type=payload.get("eth_type"),
            src_mac=payload.get("src_mac"),
            dst_mac=payload.get("dst_mac"),
            ip_version=int(payload.get("ip_version", 0) or 0),
            src_ip=payload.get("src_ip"),
            dst_ip=payload.get("dst_ip"),
            ip_protocol=int(payload.get("ip_protocol", 0) or 0),
            l4_protocol=payload.get("l4_protocol"),
            src_port=payload.get("src_port"),
            dst_port=payload.get("dst_port"),
            tcp_flags=payload.get("tcp_flags"),
            tcp_seq=payload.get("tcp_seq"),
            tcp_ack=payload.get("tcp_ack"),
            tcp_window=payload.get("tcp_window"),
            tcp_mss=payload.get("tcp_mss"),
            arp_sender_ip=payload.get("arp_sender_ip"),
            arp_sender_mac=payload.get("arp_sender_mac"),
            dns_qname=payload.get("dns_qname"),
            dns_is_query=payload.get("dns_is_query"),
            dns_is_response=payload.get("dns_is_response"),
            dns_rcode=payload.get("dns_rcode"),
            ttl=payload.get("ttl"),
            quality_flags=int(payload.get("quality_flags", 0) or 0),
            is_vlan=bool(payload.get("is_vlan", False)),
            is_arp=bool(payload.get("is_arp", False)),
            is_multicast=bool(payload.get("is_multicast", False)),
            is_broadcast=bool(payload.get("is_broadcast", False)),
            is_ipv4_fragment=bool(payload.get("is_ipv4_fragment", False)),
            is_ipv6_fragment=bool(payload.get("is_ipv6_fragment", False)),
            protocol_stack=tuple((payload.get("stack_summary") or "").split("/")) if payload.get("stack_summary") else tuple(),
            payload_bytes=None,
        )
        stats = self.context.stats
        stats["packets_total"] += 1
        stats["bytes_captured_total"] += packet.captured_length
        stats["bytes_original_total"] += packet.original_length
        if stats["first_ts_us"] == 0 or packet.timestamp_us < stats["first_ts_us"]:
            stats["first_ts_us"] = packet.timestamp_us
        if packet.timestamp_us > stats["last_ts_us"]:
            stats["last_ts_us"] = packet.timestamp_us
        if stats["first_ts_us"] and stats["last_ts_us"]:
            stats["duration_us"] = max(0, stats["last_ts_us"] - stats["first_ts_us"])

        self.context.osi_tags.append(derive_osi_tags_from_analysis_packet(packet))

        flow_key_data = make_flow_key_from_fields(
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.ip_protocol,
        )
        flow_key = None
        flow_state = None
        if flow_key_data:
            flow_id, flow_key, endpoints = flow_key_data
            flow_state = self.context.flow_table.get(flow_id)
            if flow_state is None:
                a_ip, a_port, b_ip, b_port = endpoints
                flow_state = FlowState(
                    flow_id=flow_id,
                    a_ip=a_ip,
                    a_port=a_port,
                    b_ip=b_ip,
                    b_port=b_port,
                    ip_protocol=int(packet.ip_protocol),
                    first_ts_us=packet.timestamp_us,
                    last_ts_us=packet.timestamp_us,
                )
                self.context.flow_table[flow_id] = flow_state
            flow_state.update_from_packet(packet, flow_key.direction)

        for analyzer in self.analyzers:
            analyzer.on_packet(packet, flow_key, flow_state, self.context)

    def analyze_stream(self, packets: Iterable, limit: int = 0) -> AnalysisReport:
        count = 0
        for decoded in packets:
            self.process_packet(decoded)
            count += 1
            if limit > 0 and count >= limit:
                break
        return self.finalize()

    def finalize(self) -> AnalysisReport:
        global_results: Dict[str, Dict] = {}
        flow_results: Dict[str, Dict] = {}
        time_series: Dict[str, Dict] = {}
        analyzer_meta: List[Dict[str, str]] = []

        for analyzer in self.analyzers:
            analyzer_meta.append({"name": analyzer.name, "version": analyzer.version})
            result: AnalyzerResult = analyzer.on_end(self.context)
            if result.global_results:
                global_results[result.analyzer] = result.global_results
            if result.flow_results:
                flow_results[result.analyzer] = result.flow_results
            if result.time_series:
                time_series[result.analyzer] = result.time_series

        report = AnalysisReport(
            capture_path=self.context.capture_path,
            created_at=AnalysisReport.now_iso(),
            stats=self.context.stats,
            global_results=global_results,
            flow_results=flow_results,
            time_series=time_series,
            analyzers=analyzer_meta,
            osi_summary=count_tags(self.context.osi_tags),
        )
        return report
