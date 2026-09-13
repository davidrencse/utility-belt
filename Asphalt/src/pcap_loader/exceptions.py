# Custom exceptions

"""
Custom exceptions for Asphalt PCAP processing.
"""

class PcapError(Exception):
    """Base exception for all PCAP-related errors."""
    pass

class PcapFormatError(PcapError):
    """Raised when PCAP file format is invalid or corrupt."""
    pass

class PcapEOFError(PcapFormatError):
    """Raised when PCAP file ends unexpectedly (truncated)."""
    pass

class PcapUnsupportedFeatureError(PcapError):
    """Raised when encountering unsupported PCAP features."""
    pass

class PcapngError(PcapError):
    """Base exception for PCAPNG-specific errors."""
    pass

class PcapngFormatError(PcapngError):
    """Raised when PCAPNG file format is invalid."""
    pass