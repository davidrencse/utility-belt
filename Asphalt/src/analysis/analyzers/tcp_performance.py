"""TCP performance analyzer (window, zero-window, MSS distribution)."""
from __future__ import annotations

from collections import defaultdict
from typing import List, Optional, Dict

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
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


@register_analyzer
class TcpPerformanceAnalyzer(Analyzer):
    name = "tcp_performance"
    version = "1.0"

    def __init__(self, top_n: int = 3):
        self.top_n = max(1, top_n)
        self.windows: List[int] = []
        self.zero_window = 0
        self.mss_counts: Dict[int, int] = defaultdict(int)
        self.mss_total = 0

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        if packet.ip_protocol != 6 and packet.l4_protocol != "TCP":
            return
        flags = packet.tcp_flags or 0
        is_ack = bool(flags & 0x10)

        if packet.tcp_window is not None:
            self.windows.append(int(packet.tcp_window))
            if packet.tcp_window == 0 and is_ack:
                self.zero_window += 1

        if packet.tcp_mss is not None:
            self.mss_counts[int(packet.tcp_mss)] += 1
            self.mss_total += 1

    def _top_mss(self) -> List[dict]:
        items = sorted(self.mss_counts.items(), key=lambda kv: (-kv[1], kv[0]))
        results = []
        for value, count in items[:self.top_n]:
            pct = round((count / self.mss_total) * 100.0, 2) if self.mss_total else 0.0
            results.append({"mss": value, "count": count, "pct": pct})
        return results

    def on_end(self, context) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer=self.name,
            global_results={
                "window_median": _percentile(self.windows, 50.0),
                "window_p95": _percentile(self.windows, 95.0),
                "zero_window": self.zero_window,
                "mss_top_value": (max(self.mss_counts, key=lambda k: self.mss_counts[k]) if self.mss_counts else None),
                "mss_top_pct": round((max(self.mss_counts.values()) / self.mss_total) * 100.0, 2) if self.mss_total else 0.0,
                "mss_top_k": self._top_mss(),
            },
        )
