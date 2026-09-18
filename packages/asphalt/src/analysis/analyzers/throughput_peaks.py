"""Throughput and peaks analyzer derived from time buckets."""
from __future__ import annotations

from typing import Dict, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


@register_analyzer
class ThroughputPeaksAnalyzer(Analyzer):
    name = "throughput_peaks"
    version = "1.0"

    def __init__(self, bucket_ms: int = 1000):
        self.bucket_us = max(1, bucket_ms) * 1000
        self.buckets: Dict[int, Dict[str, int]] = {}

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        ts = packet.timestamp_us
        if ts <= 0:
            return
        start = ts - (ts % self.bucket_us)
        bucket = self.buckets.setdefault(start, {"packets": 0, "bytes_captured": 0})
        bucket["packets"] += 1
        bucket["bytes_captured"] += packet.captured_length

    def on_end(self, context) -> AnalyzerResult:
        if not self.buckets:
            return AnalyzerResult(
                analyzer=self.name,
                global_results={
                    "bucket_ms": self.bucket_us // 1000,
                    "bps_now": 0.0,
                    "bps_avg": 0.0,
                    "pps_now": 0.0,
                    "pps_avg": 0.0,
                    "peak_bps": 0.0,
                    "peak_pps": 0.0,
                    "peak_bps_timestamp": None,
                    "peak_pps_timestamp": None,
                    "peak_timestamp": None,
                },
            )

        bucket_duration_sec = self.bucket_us / 1_000_000.0
        starts = sorted(self.buckets.keys())
        first_start = starts[0]
        last_start = starts[-1]

        total_packets = 0
        total_bytes = 0
        peak_bps = 0.0
        peak_pps = 0.0
        peak_bps_ts = None
        peak_pps_ts = None

        for start in starts:
            data = self.buckets[start]
            total_packets += data["packets"]
            total_bytes += data["bytes_captured"]

            bps = (data["bytes_captured"] * 8) / bucket_duration_sec
            pps = data["packets"] / bucket_duration_sec
            if bps > peak_bps:
                peak_bps = bps
                peak_bps_ts = start
            if pps > peak_pps:
                peak_pps = pps
                peak_pps_ts = start

        duration_us = (last_start + self.bucket_us) - first_start
        duration_sec = duration_us / 1_000_000.0 if duration_us > 0 else bucket_duration_sec

        now_bucket = self.buckets[last_start]
        bps_now = (now_bucket["bytes_captured"] * 8) / bucket_duration_sec
        pps_now = now_bucket["packets"] / bucket_duration_sec

        bps_avg = (total_bytes * 8) / duration_sec if duration_sec > 0 else 0.0
        pps_avg = total_packets / duration_sec if duration_sec > 0 else 0.0

        peak_timestamp = peak_bps_ts if peak_bps_ts == peak_pps_ts else None

        return AnalyzerResult(
            analyzer=self.name,
            global_results={
                "bucket_ms": self.bucket_us // 1000,
                "bps_now": round(bps_now, 3),
                "bps_avg": round(bps_avg, 3),
                "pps_now": round(pps_now, 3),
                "pps_avg": round(pps_avg, 3),
                "peak_bps": round(peak_bps, 3),
                "peak_pps": round(peak_pps, 3),
                "peak_bps_timestamp": peak_bps_ts,
                "peak_pps_timestamp": peak_pps_ts,
                "peak_timestamp": peak_timestamp,
            },
        )
