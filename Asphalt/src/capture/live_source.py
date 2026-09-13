"""
LiveCaptureSource using Scapy backend.
Simplified version without circular imports.
"""
import time
from typing import Iterator, Optional

# Don't import IPacketSource - define it locally
class IPacketSource:
    """Minimal interface for compatibility."""
    def open(self): pass
    def __iter__(self): pass  
    def close(self): pass

# Don't import RawPacket - define minimal version
class RawPacket:
    """Minimal packet class."""
    def __init__(self, timestamp=0, data=b"", capture_length=0, wire_length=0, interface=""):
        self.timestamp = timestamp
        self.data = data
        self.capture_length = capture_length
        self.wire_length = wire_length
        self.interface = interface

# Now import from same directory
from .scapy_backend import ScapyBackend, CaptureConfig

class LiveCaptureSource(IPacketSource):
    """Live packet capture source using Scapy."""
    
    def __init__(self, interface: str, filter: Optional[str] = None, 
                 promisc: bool = True, snaplen: int = 65535):
        self.backend = ScapyBackend()
        self.config = CaptureConfig(
            interface=interface,
            filter=filter,
            promisc=promisc,
            snaplen=snaplen
        )
        self.session_id: Optional[str] = None
        self._capturing = False
    
    def open(self):
        """Start capture."""
        self.session_id = self.backend.start(self.config)
        self._capturing = True
    
    def __iter__(self) -> Iterator[RawPacket]:
        """Yield captured packets."""
        if not self.session_id or not self._capturing:
            raise RuntimeError("Capture not started. Call open() first.")
        
        while self._capturing:
            packets = self.backend.get_packets(self.session_id, count=100)
            for pkt in packets:
                yield RawPacket(
                    timestamp=int(pkt['ts'] * 1_000_000),  # Convert to microseconds
                    data=pkt['data'],
                    capture_length=len(pkt['data']),
                    wire_length=pkt['wirelen'],
                    interface=self.config.interface
                )
            
            if not packets:
                time.sleep(0.01)  # Small sleep to prevent busy waiting
    
    def close(self):
        """Stop capture."""
        if self.session_id and self._capturing:
            metadata = self.backend.stop(self.session_id)
            self._capturing = False
            return metadata
        return None
    
    def get_stats(self):
        """Get current capture statistics."""
        if self.session_id:
            return self.backend.get_stats(self.session_id)
        return None