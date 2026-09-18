"""
Live packet capture subsystem.
"""

from .icapture_backend import ICaptureBackend, CaptureConfig


def __getattr__(name):
    # Scapy takes seconds to import on Windows; only load it when live capture is used,
    # not whenever capture.decoder / capture.packet_decoder is imported.
    if name == 'ScapyBackend':
        from .scapy_backend import ScapyBackend
        return ScapyBackend
    if name == 'LiveCaptureSource':
        from .live_source import LiveCaptureSource
        return LiveCaptureSource
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    'ICaptureBackend',
    'CaptureConfig',
    'ScapyBackend',
    'LiveCaptureSource',
]
