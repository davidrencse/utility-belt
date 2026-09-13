"""
Decoder integration layer.

This module connects raw capture packets to decoded models and
provides helpers to enrich index records without UI coupling.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Iterable, Iterator, Optional

try:
    from ..models.packet import RawPacket, DecodedPacket
    from ..models.index_record import PacketIndexRecord
    from ..pcap_loader.packet_index import PacketIndexBuilder
    from .packet_decoder import decode_packet
except ImportError:
    from models.packet import RawPacket, DecodedPacket
    from models.index_record import PacketIndexRecord
    from pcap_loader.packet_index import PacketIndexBuilder
    from capture.packet_decoder import decode_packet

class PacketDecoder:
    """Thin wrapper for decoding packets."""

    def decode(self, packet: RawPacket) -> DecodedPacket:
        return decode_packet(packet)

    def decode_stream(self, packets: Iterable[RawPacket]) -> Iterator[DecodedPacket]:
        for packet in packets:
            yield decode_packet(packet)


def enrich_index_record(record: PacketIndexRecord,
                        decoded: Optional[DecodedPacket]) -> PacketIndexRecord:
    """Return a new PacketIndexRecord enriched with decoded fields."""
    if decoded is None:
        return record

    src_ip = decoded.src_ip if decoded.src_ip else record.src_ip
    dst_ip = decoded.dst_ip if decoded.dst_ip else record.dst_ip
    src_port = decoded.src_port if decoded.src_port is not None else record.src_port
    dst_port = decoded.dst_port if decoded.dst_port is not None else record.dst_port
    protocol = decoded.ip_protocol if decoded.ip_protocol else record.protocol
    stack_summary = decoded.stack_summary if decoded.protocol_stack else record.stack_summary
    flags = decoded.tcp_flags if decoded.tcp_flags is not None else record.flags
    ttl = decoded.ttl if decoded.ttl is not None else record.ttl

    return replace(
        record,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        stack_summary=stack_summary,
        flags=flags,
        ttl=ttl,
    )


def build_index_record(builder: PacketIndexBuilder,
                       packet: RawPacket,
                       decoded: Optional[DecodedPacket] = None) -> PacketIndexRecord:
    """Create a PacketIndexRecord with optional decoded enrichment."""
    record = builder.create_index_record(packet, decoded=decoded)
    if decoded is None:
        return record
    return enrich_index_record(record, decoded)
