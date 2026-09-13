"""Analyzer base class."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from ..models import AnalysisPacket, AnalyzerResult, FlowKey

class Analyzer(ABC):
    name = "base"
    version = "0.1"

    def on_start(self, context) -> None:
        return None

    @abstractmethod
    def on_packet(self, packet: AnalysisPacket, flow_key: Optional[FlowKey], flow_state, context) -> None:
        raise NotImplementedError

    @abstractmethod
    def on_end(self, context) -> AnalyzerResult:
        raise NotImplementedError
