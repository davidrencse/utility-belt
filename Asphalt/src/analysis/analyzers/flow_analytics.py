"""Flow analytics summary, heavy hitters, and flow state classification."""
from __future__ import annotations

from typing import Dict, List, Optional

from .base import Analyzer
from ..models import AnalyzerResult
from ..registry import register_analyzer


def _percentile(values: List[int], percent: float) -> Optional[float]:
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


def _flow_label(flow) -> str:
    return f"{flow.a_ip}:{flow.a_port} -> {flow.b_ip}:{flow.b_port}"


@register_analyzer
class FlowAnalyticsAnalyzer(Analyzer):
    name = "flow_analytics"
    version = "1.0"

    def __init__(self, top_n: int = 5):
        self.top_n = max(1, top_n)

    def on_packet(self, packet, flow_key, flow_state, context) -> None:
        return None

    def _heavy_hitters(self, flows, key: str) -> List[Dict[str, object]]:
        sorted_flows = sorted(
            flows,
            key=lambda f: (-getattr(f, key), -f.packets_total, f.flow_id)
        )
        hitters = []
        for flow in sorted_flows[:self.top_n]:
            hitters.append({
                "flow_id": flow.flow_id,
                "label": _flow_label(flow),
                "protocol": flow.ip_protocol,
                "bytes": flow.bytes_captured_total,
                "packets": flow.packets_total,
                "duration_us": flow.duration_us(),
            })
        return hitters

    def _flow_states(self, flows) -> Dict[str, int]:
        states = {
            "tcp_established": 0,
            "tcp_half_open": 0,
            "tcp_reset_failed": 0,
            "udp_paired": 0,
            "udp_unpaired": 0,
        }
        for flow in flows:
            if flow.ip_protocol == 6 or flow.tcp_seen:
                if flow.tcp_rst_seen:
                    states["tcp_reset_failed"] += 1
                elif flow.tcp_syn_seen and flow.tcp_synack_seen and flow.tcp_ack_seen:
                    states["tcp_established"] += 1
                elif flow.tcp_syn_seen:
                    states["tcp_half_open"] += 1
            elif flow.ip_protocol == 17 or flow.udp_seen:
                if flow.has_fwd and flow.has_rev:
                    states["udp_paired"] += 1
                else:
                    states["udp_unpaired"] += 1
        return states

    def on_end(self, context) -> AnalyzerResult:
        flows = list(context.flow_table.values())
        durations = [flow.duration_us() for flow in flows if flow.packets_total > 0]
        bytes_per_flow = [flow.bytes_captured_total for flow in flows]

        duration_us = context.stats.get("duration_us", 0) or 0
        duration_sec = duration_us / 1_000_000.0 if duration_us > 0 else 0.0
        flow_rate = (len(flows) / duration_sec) if duration_sec > 0 else 0.0

        bytes_avg = (sum(bytes_per_flow) / len(bytes_per_flow)) if bytes_per_flow else 0.0
        bytes_p95 = _percentile(bytes_per_flow, 95.0)

        summary = {
            "total_flows": len(flows),
            "new_flows_per_sec": round(flow_rate, 4),
            "duration_us_median": _percentile(durations, 50.0),
            "duration_us_p95": _percentile(durations, 95.0),
            "bytes_per_flow_avg": round(bytes_avg, 2) if bytes_per_flow else 0.0,
            "bytes_per_flow_p95": bytes_p95,
        }

        heavy_hitters = {
            "top_by_bytes": self._heavy_hitters(flows, "bytes_captured_total"),
            "top_by_packets": self._heavy_hitters(flows, "packets_total"),
        }

        return AnalyzerResult(
            analyzer=self.name,
            global_results={
                "summary": summary,
                "heavy_hitters": heavy_hitters,
                "states": self._flow_states(flows),
            },
        )
