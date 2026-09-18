"""Filtering helpers for decoded packets and flows."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List

from analysis.osi import derive_osi_tags_from_decoded, derive_osi_tags_from_flow
from .filter_expr import build_predicate


_DNS_RCODE_MAP = {
    "nxdomain": 3,
}


def _normalize_tag(tag: str) -> str:
    return tag.lower()


def _with_osi_fields(record: Dict[str, Any]) -> Dict[str, Any]:
    tags = record.get("osi_tags")
    if not tags:
        tags = derive_osi_tags_from_decoded(record)
    tags = [_normalize_tag(t) for t in tags]
    enriched = dict(record)
    enriched["osi_tags"] = tags
    # OSI lenses
    enriched["l2"] = [t.split(":", 1)[1] for t in tags if t.startswith("l2:")]
    enriched["l3"] = [t.split(":", 1)[1] for t in tags if t.startswith("l3:")]
    enriched["l4"] = [t.split(":", 1)[1] for t in tags if t.startswith("l4:")]
    enriched["app"] = [t.split(":", 1)[1] for t in tags if t.startswith("app:")]
    # Aliases
    enriched["tcp_flag"] = [f.lower() for f in (record.get("tcp_flags_names") or [])]
    if record.get("dns_rcode") is not None:
        enriched["dns_rcode"] = record.get("dns_rcode")
    return enriched


def _normalize_dns_rcode(value: Any) -> Any:
    if isinstance(value, str):
        return _DNS_RCODE_MAP.get(value.lower(), value)
    return value


def compile_packet_filter(expr: str):
    predicate = build_predicate(expr, value_normalizers={"dns_rcode": _normalize_dns_rcode})

    def _match(packet_dict: Dict[str, Any]) -> bool:
        enriched = _with_osi_fields(packet_dict)
        enriched["dns_rcode"] = _normalize_dns_rcode(enriched.get("dns_rcode"))
        return predicate(enriched)

    return _match


def compile_flow_filter(expr: str):
    predicate = build_predicate(expr)

    def _match(flow_dict: Dict[str, Any]) -> bool:
        tags = flow_dict.get("osi_tags")
        if not tags:
            tags = derive_osi_tags_from_flow(flow_dict)
        tags = [_normalize_tag(t) for t in tags]
        enriched = dict(flow_dict)
        enriched["osi_tags"] = tags
        enriched["l2"] = []
        enriched["l3"] = [t.split(":", 1)[1] for t in tags if t.startswith("l3:")]
        enriched["l4"] = [t.split(":", 1)[1] for t in tags if t.startswith("l4:")]
        enriched["app"] = [t.split(":", 1)[1] for t in tags if t.startswith("app:")]
        return predicate(enriched)

    return _match


def filter_packets(packets: Iterable[Dict[str, Any]], expr: str) -> List[Dict[str, Any]]:
    if not expr:
        return list(packets)
    pred = compile_packet_filter(expr)
    return [p for p in packets if pred(p)]
