"""
PCAP/PCAPNG file loading and processing.
"""

# Import without relative paths for root-level access
try:
    from .packet_source import IPacketSource
    from .pcap_reader import PcapReader
    from .pcapng_reader import PcapngReader
    from .packet_index import PacketIndexBuilder
    from .session_manifest import SessionManifest
    from .exceptions import (
        PcapError,
        PcapFormatError,
        PcapEOFError,
        PcapngError,
        PcapngFormatError,
    )
except ImportError as e:
    # If relative imports fail, provide helpful error
    print(f"Warning: Failed to import pcap_loader modules: {e}")
    print("You may need to run Python from the project root with -m flag")
    raise

__all__ = [
    'IPacketSource',
    'PcapReader',
    'PcapngReader',
    'PacketIndexBuilder',
    'SessionManifest',
    'PcapError',
    'PcapFormatError', 
    'PcapEOFError',
    'PcapngError',
    'PcapngFormatError',
]