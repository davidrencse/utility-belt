"""Flow key helpers."""
from __future__ import annotations

from ipaddress import ip_address
from typing import Optional, Tuple

try:
    from models.packet import DecodedPacket
except ImportError:
    from ..models.packet import DecodedPacket

from .models import Direction, FlowKey


def _endpoint_key(ip: str, port: int):
    try:
        return (ip_address(ip), port)
    except ValueError:
        return (ip, port)


def make_flow_key(decoded: DecodedPacket) -> Optional[Tuple[str, FlowKey, Tuple[str, int, str, int]]]:
    if not decoded.src_ip or not decoded.dst_ip:
        return None
    if decoded.src_port is None or decoded.dst_port is None:
        return None
    if not decoded.ip_protocol:
        return None

    src_ip = decoded.src_ip
    dst_ip = decoded.dst_ip
    src_port = int(decoded.src_port)
    dst_port = int(decoded.dst_port)

    src_key = _endpoint_key(src_ip, src_port)
    dst_key = _endpoint_key(dst_ip, dst_port)

    if src_key <= dst_key:
        direction = Direction.FWD
        a_ip, a_port, b_ip, b_port = src_ip, src_port, dst_ip, dst_port
    else:
        direction = Direction.REV
        a_ip, a_port, b_ip, b_port = dst_ip, dst_port, src_ip, src_port

    flow_id = f"{a_ip}:{a_port}-{b_ip}:{b_port}-{decoded.ip_protocol}"
    flow_key = FlowKey(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        ip_protocol=int(decoded.ip_protocol),
        direction=direction,
    )
    return flow_id, flow_key, (a_ip, a_port, b_ip, b_port)


def make_flow_key_from_fields(src_ip: Optional[str],
                              dst_ip: Optional[str],
                              src_port: Optional[int],
                              dst_port: Optional[int],
                              ip_protocol: Optional[int]) -> Optional[Tuple[str, FlowKey, Tuple[str, int, str, int]]]:
    if not src_ip or not dst_ip:
        return None
    if src_port is None or dst_port is None:
        return None
    if not ip_protocol:
        return None

    src_ip = str(src_ip)
    dst_ip = str(dst_ip)
    src_port = int(src_port)
    dst_port = int(dst_port)
    ip_protocol = int(ip_protocol)

    src_key = _endpoint_key(src_ip, src_port)
    dst_key = _endpoint_key(dst_ip, dst_port)

    if src_key <= dst_key:
        direction = Direction.FWD
        a_ip, a_port, b_ip, b_port = src_ip, src_port, dst_ip, dst_port
    else:
        direction = Direction.REV
        a_ip, a_port, b_ip, b_port = dst_ip, dst_port, src_ip, src_port

    flow_id = f"{a_ip}:{a_port}-{b_ip}:{b_port}-{ip_protocol}"
    flow_key = FlowKey(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        ip_protocol=ip_protocol,
        direction=direction,
    )
    return flow_id, flow_key, (a_ip, a_port, b_ip, b_port)
