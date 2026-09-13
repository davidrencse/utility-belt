"""Packet size statistics analyzer.

Uses exact storage for small inputs and P² streaming estimates for large inputs
to avoid unbounded memory while keeping median/p95 reasonably accurate.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

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


class _P2Quantile:
    """P² streaming quantile estimator (approximate)."""
    def __init__(self, quantile: float):
        self.quantile = quantile
        self.count = 0
        self.initial: List[float] = []
        self.n: List[int] = []
        self.np: List[float] = []
        self.dn: List[float] = []
        self.q: List[float] = []

    def add(self, value: float) -> None:
        self.count += 1
        if len(self.initial) < 5:
            self.initial.append(value)
            if len(self.initial) == 5:
                self.initial.sort()
                self.q = list(self.initial)
                self.n = [1, 2, 3, 4, 5]
                q = self.quantile
                self.np = [1, 1 + 2 * q, 1 + 4 * q, 3 + 2 * q, 5]
                self.dn = [0, q / 2, q, (1 + q) / 2, 1]
            return

        k = 0
        if value < self.q[0]:
            self.q[0] = value
            k = 0
        elif value < self.q[1]:
            k = 0
        elif value < self.q[2]:
            k = 1
        elif value < self.q[3]:
            k = 2
        elif value < self.q[4]:
            k = 3
        else:
            self.q[4] = value
            k = 3

        for i in range(k + 1, 5):
            self.n[i] += 1
        for i in range(5):
            self.np[i] += self.dn[i]

        for i in range(1, 4):
            d = self.np[i] - self.n[i]
            if (d >= 1 and self.n[i + 1] - self.n[i] > 1) or (d <= -1 and self.n[i - 1] - self.n[i] < -1):
                d = 1 if d >= 1 else -1
                n_i = self.n[i]
                n_im1 = self.n[i - 1]
                n_ip1 = self.n[i + 1]
                q_i = self.q[i]
                q_im1 = self.q[i - 1]
                q_ip1 = self.q[i + 1]
                numerator = (n_i - n_im1 + d) * (q_ip1 - q_i) / (n_ip1 - n_i)
                numerator += (n_ip1 - n_i - d) * (q_i - q_im1) / (n_i - n_im1)
                q_new = q_i + d * (numerator / (n_ip1 - n_im1))
                if q_im1 < q_new < q_ip1:
                    self.q[i] = q_new
                else:
                    self.q[i] = q_i + d * (self.q[i + d] - q_i) / (self.n[i + d] - n_i)
                self.n[i] += d

    def value(self) -> Optional[float]:
        if len(self.initial) < 5:
            return None
        return float(self.q[2])


class _QuantileTracker:
    """Track quantiles exactly for small inputs; switch to P² when large."""
    def __init__(self, max_store: int = 200000):
        self.max_store = max_store
        self.values: Optional[List[int]] = []
        self.min_value: Optional[int] = None
        self.max_value: Optional[int] = None
        self.p2_median = _P2Quantile(0.5)
        self.p2_p95 = _P2Quantile(0.95)

    def _promote_to_streaming(self) -> None:
        if self.values is None:
            return
        for value in self.values:
            self.p2_median.add(float(value))
            self.p2_p95.add(float(value))
        self.values = None

    def add(self, value: Optional[int]) -> None:
        if value is None:
            return
        value = int(value)
        if self.min_value is None or value < self.min_value:
            self.min_value = value
        if self.max_value is None or value > self.max_value:
            self.max_value = value

        if self.values is not None:
            self.values.append(value)
            if len(self.values) > self.max_store:
                self._promote_to_streaming()
        else:
            self.p2_median.add(float(value))
            self.p2_p95.add(float(value))

    def stats(self) -> dict:
        if self.min_value is None:
            return {
                "min": None,
                "median": None,
                "p95": None,
                "max": None,
            }
        if self.values is not None:
            return {
                "min": self.min_value,
                "median": _percentile(self.values, 50.0),
                "p95": _percentile(self.values, 95.0),
                "max": self.max_value,
            }
        return {
            "min": self.min_value,
            "median": self.p2_median.value(),
            "p95": self.p2_p95.value(),
            "max": self.max_value,
        }


@register_analyzer
class PacketSizeStatsAnalyzer(Analyzer):
    name = "packet_size_stats"
    version = "1.0"

    def __init__(self):
        self.captured = _QuantileTracker()
        self.original = _QuantileTracker()
        self.hist = {
            "0-63": 0,
            "64-127": 0,
            "128-511": 0,
            "512-1023": 0,
            "1024-1514": 0,
            "jumbo": 0,
        }
        self.ipv4_fragments = 0
        self.ipv6_fragments = 0

    def _hist_bucket(self, size: int) -> str:
        if size <= 63:
            return "0-63"
        if size <= 127:
            return "64-127"
        if size <= 511:
            return "128-511"
        if size <= 1023:
            return "512-1023"
        if size <= 1514:
            return "1024-1514"
        return "jumbo"

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        cap_len = int(packet.captured_length or 0)
        self.captured.add(cap_len)
        self.hist[self._hist_bucket(cap_len)] += 1

        original_len = int(packet.original_length or 0)
        if original_len > 0:
            self.original.add(original_len)

        if packet.is_ipv4_fragment:
            self.ipv4_fragments += 1
        if packet.is_ipv6_fragment:
            self.ipv6_fragments += 1

    def on_end(self, context) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer=self.name,
            global_results={
                "captured_length": self.captured.stats(),
                "original_length": self.original.stats(),
                "histogram": dict(self.hist),
                "fragments": {
                    "ipv4_fragments": self.ipv4_fragments,
                    "ipv6_fragments": self.ipv6_fragments,
                },
            },
        )
