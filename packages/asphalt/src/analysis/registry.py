"""Analyzer registry."""
from __future__ import annotations

from typing import Dict, List, Type

from .analyzers.base import Analyzer

_REGISTRY: Dict[str, Type[Analyzer]] = {}


def register_analyzer(cls: Type[Analyzer]) -> Type[Analyzer]:
    _REGISTRY[cls.name] = cls
    return cls


def _load_builtin_analyzers() -> None:
    if _REGISTRY:
        return
    from .analyzers import global_stats  # noqa: F401
    from .analyzers import flow_summary  # noqa: F401
    from .analyzers import time_series  # noqa: F401
    from .analyzers import protocol_mix  # noqa: F401
    from .analyzers import abnormal_activity  # noqa: F401
    from .analyzers import packet_chunks  # noqa: F401
    from .analyzers import tcp_handshakes  # noqa: F401
    from .analyzers import capture_health  # noqa: F401
    from .analyzers import throughput_peaks  # noqa: F401
    from .analyzers import packet_size_stats  # noqa: F401
    from .analyzers import l2_l3_breakdown  # noqa: F401
    from .analyzers import top_entities  # noqa: F401
    from .analyzers import flow_analytics  # noqa: F401
    from .analyzers import tcp_reliability  # noqa: F401
    from .analyzers import tcp_performance  # noqa: F401
    from .analyzers import scan_signals  # noqa: F401
    from .analyzers import arp_lan_signals  # noqa: F401
    from .analyzers import dns_anomalies  # noqa: F401


def list_analyzers() -> List[str]:
    _load_builtin_analyzers()
    return sorted(_REGISTRY.keys())


def create_analyzer(name: str, **kwargs) -> Analyzer:
    _load_builtin_analyzers()
    if name not in _REGISTRY:
        raise KeyError(f"Unknown analyzer: {name}")
    return _REGISTRY[name](**kwargs)
