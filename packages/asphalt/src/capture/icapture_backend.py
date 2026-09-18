"""
Capture backend interface definition.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

@dataclass
class CaptureConfig:
    """Capture configuration."""
    interface: str
    snaplen: int = 65535
    promisc: bool = True
    timeout_ms: int = 1000
    buffer_size: int = 10000  # Queue size
    filter: Optional[str] = None
    monitor: bool = False  # Monitor mode for WiFi

class ICaptureBackend(ABC):
    """Capture backend interface."""
    
    @abstractmethod
    def start(self, config: CaptureConfig) -> str:
        """Start capture, return session_id."""
        pass
    
    @abstractmethod
    def stop(self, session_id: str) -> Dict[str, Any]:
        """Stop capture, return session metadata."""
        pass
    
    @abstractmethod
    def get_stats(self, session_id: str) -> Dict[str, Any]:
        """Get current capture statistics."""
        pass
    
    @abstractmethod
    def get_packets(self, session_id: str, count: int = 100) -> List[Dict]:
        """Get captured packets from queue."""
        pass
    
    @abstractmethod
    def list_interfaces(self) -> List[Dict]:
        """List available network interfaces."""
        pass