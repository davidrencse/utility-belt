# Sess manifest handling
"""
Session manifest creation and management.

The session manifest is the authoritative metadata source for a capture session.
Think of it as a "receipt" that documents everything about the capture:

1. WHAT was captured (source file, timestamps, packet count)
2. WHERE it's stored (file mappings for multi-file sessions)
3. HOW it was processed (schema versions for compatibility)
4. WHEN it was created (creation timestamp for freshness)

The manifest is:
- Deterministic: Same input → same manifest (critical!)
- Immutable: Once created, shouldn't change
- Portable: Can be moved with the data
- Self-describing: Contains all needed metadata
"""

import json
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from pathlib import Path
import os


@dataclass
class SessionManifest:
    """
    Authoritative metadata for a capture session.
    
    This is a DATA CONTAINER - no business logic here.
    Just stores and validates the metadata.
    
    Fields are designed for:
    1. Deterministic hashing (session_id = hash(source + time + count))
    2. Backward compatibility (default values, schema versions)
    3. Fast lookups (time range, file mappings)
    4. Debugging (original path, capture settings)
    """
    
    # ==================== CORE IDENTIFICATION ====================
    session_id: str
    """
    Deterministic hash of (source_hash + time_range + packet_count).
    
    Format: blake2b_hexdigest(32 bytes = 64 chars)
    Example: "e4d7f1b4c5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"
    
    This is the PRIMARY KEY for the session.
    Same inputs → same session_id → deterministic!
    """
    
    created_at: str
    """
    When this manifest was created (UTC).
    
    Format: ISO 8601 with 'Z' suffix for UTC.
    Example: "2024-01-20T14:30:45.123456Z"
    
    Used for:
    - Knowing when analysis was done
    - Version comparisons
    - Cache invalidation
    """
    
    # ==================== SOURCE INFORMATION ====================
    source_type: str
    """
    How packets were acquired.
    
    Values: "file", "interface", "upload", "stream"
    
    Determines what other fields are relevant:
    - "file": source_hash, original_path, file_mapping
    - "interface": interface_name, capture_filter
    - "upload": source_hash only
    """
    
    source_hash: str
    """
    Cryptographic hash of the original data source.
    
    For files: SHA256 of the file bytes.
    For interfaces: Hash of (interface + start_time + filter).
    For uploads: SHA256 of uploaded data.
    
    Used for:
    - Data integrity verification
    - Duplicate detection
    - Deterministic session_id generation
    """
    
    # ==================== TEMPORAL SCOPE ====================
    time_start_us: int
    """
    Earliest packet timestamp in microseconds since Unix epoch.
    
    Example: 1700000000000000 (2023-11-14T22:13:20Z)
    
    Used for:
    - Time-based queries ("show packets after X")
    - Duration calculations
    - Timeline visualizations
    """
    
    time_end_us: int
    """
    Latest packet timestamp in microseconds.
    
    Must be >= time_start_us.
    
    Together with time_start_us defines the session's time window.
    """
    
    # ==================== PACKET STATISTICS ====================
    total_packets: int
    """
    Total packets in the session.
    
    Must be >= 0.
    Used for:
    - Progress tracking
    - Resource allocation
    - Statistical analysis
    """
    
    total_bytes_captured: int
    """
    Sum of captured_length for all packets.
    
    This is the actual bytes stored on disk.
    May be less than total_bytes_original due to snaplen.
    """
    
    total_bytes_original: int
    """
    Sum of original_length for all packets.
    
    This is the bytes that were on the wire.
    Used for bandwidth calculations.
    """
    
    # ==================== STORAGE MAPPING ====================
    file_mapping: Dict[str, str] = field(default_factory=dict)
    """
    Maps file_id to file path for multi-file sessions.
    
    Format: {"0": "/data/part1.pcap", "1": "/data/part2.pcap"}
    
    file_id is used in pcap_ref: "file_id:offset"
    Allows random access to packets across multiple files.
    """
    
    # ==================== SCHEMA VERSIONING ====================
    index_schema_version: str = "0.2.0"
    """
    Version of PacketIndexRecord schema used.
    
    Format: "MAJOR.MINOR.PATCH"
    
    Enables schema evolution:
    - Different versions can coexist
    - Migration scripts can detect old formats
    - Backward compatibility checks
    """
    
    manifest_schema_version: str = "0.2.0"
    """
    Version of THIS manifest schema.
    
    Allows the manifest format itself to evolve.
    When adding/removing fields, increment this.
    """
    
    # ==================== CAPTURE METADATA ====================
    capture_filter: Optional[str] = None
    """
    BPF filter applied during capture (if any).
    
    Example: "tcp port 80 or port 443"
    
    Important for understanding what might be missing.
    """
    
    interface_name: Optional[str] = None
    """
    Network interface name for live captures.
    
    Example: "eth0", "en0", "Wi-Fi"
    """
    
    link_types: List[int] = field(default_factory=list)
    """
    List of DLT_* link types present in the session.
    
    Example: [1] for Ethernet, [1, 12] for mixed Ethernet/RawIP.
    
    Used for:
    - Protocol decoder selection
    - Format validation
    - Statistics
    """
    
    snaplen: Optional[int] = None
    """
    Maximum captured packet length (if limited).
    
    None means no limit (full packets captured).
    
    Important for understanding truncation:
    - captured_length <= snaplen
    - captured_length <= original_length
    """

    # ==================== OPTIONAL FIELDS ====================
    original_path: Optional[str] = None
    """
    Original file path (optional for privacy/portability).
    
    Example: "/data/captures/network.pcap"
    
    Can be None if:
    - File was moved/deleted
    - Privacy concerns (don't expose paths)
    - Uploaded content (no local path)
    """
    
    # ==================== SERIALIZATION ====================
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary with deterministic field ordering.
        
        Important: Field order must be consistent for deterministic
        JSON serialization and hashing.
        """
        # Define explicit field order for determinism
        base_dict = {
            'session_id': self.session_id,
            'created_at': self.created_at,
            'source_type': self.source_type,
            'source_hash': self.source_hash,
            'time_start_us': self.time_start_us,
            'time_end_us': self.time_end_us,
            'total_packets': self.total_packets,
            'total_bytes_captured': self.total_bytes_captured,
            'total_bytes_original': self.total_bytes_original,
            'file_mapping': self.file_mapping,
            'index_schema_version': self.index_schema_version,
            'manifest_schema_version': self.manifest_schema_version,
        }
        
        # Add optional fields only if they have values
        optional_fields = {}
        if self.original_path is not None:
            optional_fields['original_path'] = self.original_path
        if self.capture_filter is not None:
            optional_fields['capture_filter'] = self.capture_filter
        if self.interface_name is not None:
            optional_fields['interface_name'] = self.interface_name
        if self.link_types:
            optional_fields['link_types'] = self.link_types
        if self.snaplen is not None:
            optional_fields['snaplen'] = self.snaplen
        
        return {**base_dict, **optional_fields}
    
    def to_json(self, indent: int = 2) -> str:
        """
        Serialize to JSON string with deterministic ordering.
        
        Uses sort_keys=True to ensure consistent output regardless
        of Python version or dictionary insertion order.
        """
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)
    
    def save(self, filepath: str):
        """
        Save manifest to file.
        
        Creates parent directories if needed.
        Uses atomic write pattern to prevent corruption.
        """
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write to temp file first, then rename (atomic)
        temp_path = path.with_suffix('.tmp')
        with open(temp_path, 'w') as f:
            f.write(self.to_json())
        
        # Atomic rename (works on Unix, Windows may need special handling)
        temp_path.replace(path)
    
    @classmethod
    def load(cls, filepath: str) -> 'SessionManifest':
        """
        Load manifest from file.
        
        Handles backward compatibility by filling missing fields
        with default values.
        """
        with open(filepath, 'r') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SessionManifest':
        """
        Create manifest from dictionary with backward compatibility.
        
        If fields are missing (older manifest version), uses defaults.
        Extra fields are ignored (forward compatibility).
        """
        # Default values for backward compatibility
        defaults = {
            'original_path': None,
            'capture_filter': None,
            'interface_name': None,
            'link_types': [],
            'snaplen': None,
            'file_mapping': {},
            'index_schema_version': '0.2.0',
            'manifest_schema_version': '0.2.0',
        }
        
        # Merge defaults with provided data
        merged = {**defaults, **data}
        
        # Extract only the fields the dataclass expects
        # (ignores unknown fields for forward compatibility)
        known_fields = {
            k: v for k, v in merged.items()
            if k in cls.__dataclass_fields__
        }
        
        return cls(**known_fields)
    
    # ==================== HELPER PROPERTIES ====================
    
    @property
    def duration_seconds(self) -> float:
        """Session duration in seconds (with fractional part)."""
        if self.time_end_us > self.time_start_us:
            return (self.time_end_us - self.time_start_us) / 1_000_000.0
        return 0.0
    
    @property
    def avg_packet_size(self) -> float:
        """Average captured packet size in bytes."""
        if self.total_packets > 0:
            return self.total_bytes_captured / self.total_packets
        return 0.0
    
    @property
    def avg_bitrate(self) -> float:
        """Average bitrate in bits per second."""
        duration = self.duration_seconds
        if duration > 0:
            return (self.total_bytes_captured * 8) / duration
        return 0.0
    
    @property
    def is_truncated(self) -> bool:
        """True if any packets were truncated (snaplen limited)."""
        return (self.snaplen is not None and 
                self.total_bytes_captured < self.total_bytes_original)
    
    def get_file_path(self, file_id: str) -> Optional[str]:
        """Get file path for given file_id."""
        return self.file_mapping.get(file_id)
    
    def validate(self) -> List[str]:
        """
        Validate manifest consistency.
        
        Returns list of warning/error messages.
        Empty list means everything is valid.
        """
        issues = []
        
        # Basic validation
        if self.total_packets < 0:
            issues.append("total_packets cannot be negative")
        
        if self.time_end_us < self.time_start_us:
            issues.append("time_end_us is before time_start_us")
        
        if not self.session_id:
            issues.append("session_id is empty")
        
        if not self.source_hash:
            issues.append("source_hash is empty")
        
        if self.total_bytes_captured > self.total_bytes_original:
            issues.append("captured bytes cannot exceed original bytes")
        
        # Warn about unusual but not necessarily wrong conditions
        if self.total_packets == 0:
            issues.append("Warning: session has 0 packets")
        
        if self.duration_seconds > 86400:  # 24 hours
            issues.append("Warning: session longer than 24 hours")
        
        return issues
    
    def __str__(self) -> str:
        """Human-readable summary."""
        duration = self.duration_seconds
        return (f"Session {self.session_id[:16]}... "
                f"({self.total_packets} packets, "
                f"{duration:.1f}s, "
                f"{self.total_bytes_captured:,} bytes)")


class SessionManifestBuilder:
    """
    Builds SessionManifest objects from packet sources.
    
    This is where the BUSINESS LOGIC lives:
    - Calculates deterministic hashes
    - Collects statistics from packet iteration
    - Generates session_id from source metadata
    
    Separate from SessionManifest class to maintain:
    - Single Responsibility (manifest = data, builder = logic)
    - Testability (can test builder without manifest serialization)
    - Flexibility (different builders for different sources)
    """
    
    @staticmethod
    def from_packet_source(
        source,  # Any IPacketSource implementation
        filepath: Optional[str] = None,
        capture_filter: Optional[str] = None,
        interface_name: Optional[str] = None
    ) -> SessionManifest:
        """
        Create manifest by analyzing a packet source.
        
        This is the MAIN ENTRY POINT for creating manifests.
        
        Process:
        1. Calculate source hash (file hash or synthetic)
        2. Iterate through packets to collect statistics
        3. Generate deterministic session_id
        4. Create and return SessionManifest
        
        Args:
            source: IPacketSource (PcapReader, PcapngReader, etc.)
            filepath: Original file path (optional)
            capture_filter: BPF filter used (optional)
            interface_name: Interface name for live captures (optional)
        
        Returns:
            Complete SessionManifest ready for saving
        """
        # Step 1: Calculate source hash
        source_hash = ""
        source_type = "unknown"
        
        if filepath and Path(filepath).exists():
            # File source - hash the actual file
            source_hash = SessionManifestBuilder._calculate_file_hash(filepath)
            source_type = "file"
        elif hasattr(source, 'filepath') and Path(source.filepath).exists():
            # Source has its own filepath
            source_hash = SessionManifestBuilder._calculate_file_hash(source.filepath)
            source_type = "file"
            filepath = source.filepath
        else:
            # Non-file source (interface, upload, etc.)
            # Create synthetic hash from available metadata
            source_hash = SessionManifestBuilder._calculate_synthetic_hash(
                source_type="interface" if interface_name else "upload",
                metadata={
                    'interface': interface_name,
                    'filter': capture_filter,
                    'start_time': datetime.utcnow().isoformat()
                }
            )
            source_type = "interface" if interface_name else "upload"
        
        # Step 2: Get session info from source
        # (This may iterate packets, collecting stats)
        session_info = source.get_session_info()
        
        # Step 3: Generate deterministic session_id
        session_id = SessionManifestBuilder._generate_session_id(
            source_hash=source_hash,
            time_range=session_info.get('time_range', (0, 0)),
            packet_count=session_info.get('packet_count', 0),
            source_type=source_type
        )
        
        # Step 4: Create file mapping
        file_mapping = {}
        if filepath:
            # Single file session
            file_mapping = {"0": filepath}
        
        # Step 5: Build and return manifest
        return SessionManifest(
            session_id=session_id,
            created_at=datetime.utcnow().isoformat() + "Z",
            source_type=source_type,
            source_hash=source_hash,
            original_path=filepath,
            time_start_us=session_info.get('time_range', (0, 0))[0],
            time_end_us=session_info.get('time_range', (0, 0))[1],
            total_packets=session_info.get('packet_count', 0),
            total_bytes_captured=session_info.get('file_size', 0),  # Approximation
            total_bytes_original=session_info.get('file_size', 0),  # Same for now
            file_mapping=file_mapping,
            capture_filter=capture_filter,
            interface_name=interface_name,
            link_types=session_info.get('link_types', []),
            snaplen=session_info.get('snaplen', None),
            # Schema versions are set by defaults in SessionManifest
        )
    
    @staticmethod
    def _calculate_file_hash(filepath: str) -> str:
        """
        Calculate SHA256 hash of file for integrity verification.
        
        Uses incremental reading for memory efficiency with large files.
        Deterministic: same file → same hash.
        """
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            # Read in 64KB chunks for efficiency
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    @staticmethod
    def _calculate_synthetic_hash(source_type: str, metadata: Dict[str, Any]) -> str:
        """
        Create hash for non-file sources.
        
        Used for live captures, uploads, etc. where there's no
        physical file to hash.
        
        Makes the hash deterministic from the metadata.
        """
        h = hashlib.blake2b(digest_size=32)
        
        # Include source type
        h.update(source_type.encode('utf-8'))
        
        # Include sorted metadata for determinism
        for key, value in sorted(metadata.items()):
            if value is not None:
                h.update(key.encode('utf-8'))
                h.update(str(value).encode('utf-8'))
        
        return h.hexdigest()
    
    @staticmethod
    def _generate_session_id(
        source_hash: str,
        time_range: Tuple[int, int],
        packet_count: int,
        source_type: str
    ) -> str:
        """
        Generate deterministic session ID.
        
        Inputs are hashed together to create a unique but
        deterministic identifier for the session.
        
        Same inputs → same session_id.
        """
        h = hashlib.blake2b(digest_size=32)
        
        # Include all identifying information
        h.update(source_hash.encode('utf-8'))
        h.update(source_type.encode('utf-8'))
        h.update(str(time_range[0]).encode('utf-8'))
        h.update(str(time_range[1]).encode('utf-8'))
        h.update(str(packet_count).encode('utf-8'))
        
        return h.hexdigest()
    
    @staticmethod
    def create_for_file(
        filepath: str,
        capture_filter: Optional[str] = None
    ) -> SessionManifest:
        """
        Convenience method: create manifest for a file.
        
        Handles opening the appropriate reader based on file extension.
        """
        from .pcap_reader import PcapReader
        from .pcapng_reader import PcapngReader
        
        # Determine reader based on file extension
        if filepath.lower().endswith('.pcapng'):
            reader_class = PcapngReader
        else:
            # Default to PCAP for .pcap or unknown extensions
            reader_class = PcapReader
        
        # Create reader, process, and build manifest
        with reader_class(filepath) as reader:
            return SessionManifestBuilder.from_packet_source(
                source=reader,
                filepath=filepath,
                capture_filter=capture_filter
            )


# Example usage function (not part of the class)
def example_usage():
    """
    Show how to use SessionManifestBuilder.
    
    This would be in a test file or documentation.
    """
    # Method 1: Direct from file
    manifest = SessionManifestBuilder.create_for_file("capture.pcap")
    manifest.save("capture.manifest.json")
    print(f"Created manifest: {manifest}")
    
    # Method 2: Manual with reader
    from .pcap_reader import PcapReader
    with PcapReader("capture.pcap") as reader:
        manifest = SessionManifestBuilder.from_packet_source(
            source=reader,
            filepath="capture.pcap",
            capture_filter="tcp port 80"
        )
    
    # Load it back
    loaded = SessionManifest.load("capture.manifest.json")
    print(f"Loaded: {loaded.session_id}")
    
    # Validate
    issues = loaded.validate()
    if issues:
        print(f"Validation issues: {issues}")
    else:
        print("Manifest is valid!")


if __name__ == "__main__":
    # Quick test if run directly
    print("SessionManifest module loaded successfully")
    print(f"SessionManifest schema version: {SessionManifest().manifest_schema_version}")
