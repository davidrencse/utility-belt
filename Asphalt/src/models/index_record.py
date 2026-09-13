# index record model
"""
Packet index record model for Asphalt.

These records are written to persistent storage and MUST be:
1. Deterministic - same input always produces same output
2. Backward compatible - schema changes must be handled
3. Queryable - optimized for common lookup patterns
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any
import json

@dataclass
class PacketIndexRecord:
    """
    Index record for fast packet lookup and metadata storage.
    
    This record exists in the analytics database (Tier 3) and enables:
    - Fast timestamp-based lookups
    - Flow reassembly queries
    - Protocol filtering
    - Statistical analysis
    
    SCHEMA VERSIONING: Always include schema_version field.
    When adding fields, ensure they have sensible defaults.
    """
    
    # ========== PRIMARY IDENTIFICATION ==========
    packet_id: int  
    """Monotonic integer, starting at 1 for this session.
    This is the primary key for intra-session lookups."""
    
    session_id: str  
    """Links to SessionManifest. Format: blake2b_hexdigest.
    Used for cross-session queries and data partitioning."""
    
    timestamp_us: int  
    """Microseconds since epoch. MUST match RawPacket.timestamp_us."""
    
    
    # ========== SIZE INFORMATION ==========
    captured_length: int  
    """Bytes captured (for statistics and filtering)"""
    
    original_length: int  
    """Original packet size (for bandwidth calculations)"""
    
    
    # ========== STORAGE REFERENCE ==========
    pcap_ref: str  
    """Format: 'file_id:start_offset:data_offset'
    Used to retrieve raw packet data from PCAP store."""
    
    packet_hash: str  
    """Blake2b-128 hash of (timestamp + data + lengths).
    Used for duplicate detection and data integrity."""
    
    
    # ========== NETWORK ADDRESSING ==========
    # NOTE: These are PLACEHOLDERS in Sprint 0.2
    # Will be populated by decoder in future sprints
    src_ip: str = "0.0.0.0"  
    """Source IP address. Default indicates not yet decoded."""
    
    dst_ip: str = "0.0.0.0"  
    """Destination IP address."""
    
    src_port: int = 0  
    """Source port (0 for non-TCP/UDP)."""
    
    dst_port: int = 0  
    """Destination port."""
    
    protocol: int = 0  
    """IP protocol number (e.g., 6=TCP, 17=UDP)."""
    
    
    # ========== PROTOCOL INFORMATION ==========
    stack_summary: str = "unknown"  
    """Colon-separated protocol stack, e.g., 'eth:ip:tcp'"""
    
    
    # ========== SCHEMA VERSIONING ==========
    schema_version: str = "0.2.0"  
    """Enables schema evolution. Increment on breaking changes."""
    
    
    # ========== OPTIONAL FIELDS ==========
    # These fields are optional and can be added later
    # without breaking existing records
    
    flags: Optional[int] = None  
    """TCP flags or other protocol-specific flags"""
    
    ttl: Optional[int] = None  
    """Time To Live (for IP packets)"""
    
    flow_id: Optional[str] = None  
    """Links to flow tracking (future sprint)"""
    
    analysis_flags: int = 0  
    """Bitmask of analysis results (future sprint)"""
    
    
    # ========== SERIALIZATION METHODS ==========
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for JSON/Protobuf serialization.
        
        IMPORTANT: This method must maintain deterministic ordering
        for consistent hashing and testing.
        """
        # Define explicit field order for determinism
        base_fields = {
            'packet_id': self.packet_id,
            'session_id': self.session_id,
            'timestamp_us': self.timestamp_us,
            'captured_length': self.captured_length,
            'original_length': self.original_length,
            'pcap_ref': self.pcap_ref,
            'packet_hash': self.packet_hash,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'stack_summary': self.stack_summary,
            'schema_version': self.schema_version,
        }
        
        # Add optional fields only if they have values
        optional_fields = {}
        if self.flags is not None:
            optional_fields['flags'] = self.flags
        if self.ttl is not None:
            optional_fields['ttl'] = self.ttl
        if self.flow_id is not None:
            optional_fields['flow_id'] = self.flow_id
        if self.analysis_flags != 0:
            optional_fields['analysis_flags'] = self.analysis_flags
            
        return {**base_fields, **optional_fields}
    
    def to_json(self) -> str:
        """Serialize to JSON string with deterministic ordering."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(',', ':'))
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PacketIndexRecord':
        """
        Deserialize from dictionary.
        
        Handles schema evolution by:
        1. Setting defaults for missing fields
        2. Ignoring unknown fields
        3. Validating required fields
        """
        # Extract known fields, ignore unknown ones
        known_fields = {
            k: v for k, v in data.items() 
            if k in cls.__dataclass_fields__
        }
        return cls(**known_fields)
    
    
    # ========== HELPER METHODS ==========
    
    @property
    def is_decoded(self) -> bool:
        """True if network addressing fields have been populated."""
        return (self.src_ip != "0.0.0.0" or 
                self.dst_ip != "0.0.0.0" or 
                self.protocol != 0)
    
    @property
    def timestamp_seconds(self) -> float:
        """Convert microseconds to seconds with fractional part."""
        return self.timestamp_us / 1_000_000.0
    
    @property
    def is_truncated(self) -> bool:
        """True if packet was truncated during capture."""
        return self.captured_length < self.original_length
    
    def matches_filter(self, 
                      src_ip: Optional[str] = None,
                      dst_ip: Optional[str] = None,
                      protocol: Optional[int] = None) -> bool:
        """
        Simple filter matching for common queries.
        
        Used by index builder for creating filtered views.
        """
        if src_ip and self.src_ip != src_ip:
            return False
        if dst_ip and self.dst_ip != dst_ip:
            return False
        if protocol and self.protocol != protocol:
            return False
        return True