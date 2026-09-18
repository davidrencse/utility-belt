"""DNS anomalies analyzer."""
from __future__ import annotations

from math import log2
from typing import Dict, List, Optional

from .base import Analyzer
from ..models import AnalysisPacket, AnalyzerResult, FlowKey
from ..registry import register_analyzer


def _entropy_score(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * log2(p)
    return entropy


@register_analyzer
class DnsAnomaliesAnalyzer(Analyzer):
    name = "dns_anomalies"
    version = "1.0"

    def __init__(self,
                 entropy_threshold: float = 3.5,
                 label_length_threshold: int = 40,
                 nxdomain_threshold_pct: float = 30.0,
                 min_responses: int = 10,
                 max_samples: int = 5):
        self.entropy_threshold = entropy_threshold
        self.label_length_threshold = label_length_threshold
        self.nxdomain_threshold_pct = nxdomain_threshold_pct
        self.min_responses = min_responses
        self.max_samples = max(1, max_samples)
        self.high_entropy: List[Dict[str, object]] = []
        self.long_labels: List[Dict[str, object]] = []
        self.nxdomain_count = 0
        self.total_responses = 0

    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        if packet.dns_is_response is True:
            self.total_responses += 1
            if packet.dns_rcode == 3:
                self.nxdomain_count += 1

        if not packet.dns_qname:
            return
        qname = packet.dns_qname.strip(".").lower()
        if not qname:
            return
        compact = qname.replace(".", "")
        score = _entropy_score(compact)
        if score >= self.entropy_threshold and len(self.high_entropy) < self.max_samples:
            self.high_entropy.append({"domain": qname, "score": round(score, 3)})

        labels = qname.split(".")
        max_len = max((len(label) for label in labels), default=0)
        if max_len >= self.label_length_threshold and len(self.long_labels) < self.max_samples:
            self.long_labels.append({"domain": qname, "max_label_len": max_len})

    def on_end(self, context) -> AnalyzerResult:
        pct = round((self.nxdomain_count / self.total_responses) * 100.0, 2) if self.total_responses else 0.0
        spike = self.total_responses >= self.min_responses and pct >= self.nxdomain_threshold_pct
        return AnalyzerResult(
            analyzer=self.name,
            global_results={
                "entropy": {
                    "count": len(self.high_entropy),
                    "samples": self.high_entropy,
                    "threshold": self.entropy_threshold,
                },
                "long_labels": {
                    "count": len(self.long_labels),
                    "samples": self.long_labels,
                    "threshold": self.label_length_threshold,
                },
                "nxdomain": {
                    "nxdomain_count": self.nxdomain_count,
                    "total_responses": self.total_responses,
                    "nxdomain_pct": pct,
                    "spike_detected": spike,
                    "threshold_pct": self.nxdomain_threshold_pct,
                    "min_responses": self.min_responses,
                },
            },
        )
