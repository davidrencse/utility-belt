"""
IPacketSource Interface

This is the CONTRACT that all packet sources must follow.
Think of this as a "job description" for PCAP file readers.

All packet source classes (PcapReader, PcapngReader, etc.) must:
1. Implement ALL the methods marked @abstractmethod
2. Follow the rules defined in each method's docstring
3. Handle errors consistently
4. Clean up resources properly
"""

from abc import ABC, abstractmethod
from typing import Iterator, Optional, Dict, Any
try:
    from ..models.packet import RawPacket
    from ..models.index_record import PacketIndexRecord
except ImportError:
    from models.packet import RawPacket
    from models.index_record import PacketIndexRecord

class IPacketSource(ABC):
    """
    Abstract base class for all packet data sources.
    
    This is like a "job description" for file readers.
    Any class that wants to read packets MUST implement these methods.
    
    Example implementations:
    - PcapReader (reads .pcap files)
    - PcapngReader (reads .pcapng files) 
    - LiveCapture (future: reads from network interface)
    
    Rules for implementers:
    1. Deterministic iteration order
    2. Proper resource cleanup (close files!)
    3. Accurate packet metadata
    4. Consistent error handling
    """
    
    # =========================================================================
    # TODO: MUST IMPLEMENT - PACKET ITERATION
    # =========================================================================
    @abstractmethod
    def __iter__(self) -> Iterator[RawPacket]:
        """
        Iterate through packets in capture order.
        
        This is the MAIN JOB of a packet source: read packets one by one.
        
        Yields:
            RawPacket objects with these REQUIRED fields:
            - packet_id: Must start at 1, increment by 1 (1, 2, 3...)
            - timestamp_us: Microseconds since 1970
            - pcap_ref: Format "file_id:start_offset:data_offset"
            - captured_length, original_length, link_type, data
            
        Raises:
            FormatError: If file is corrupt or wrong format
            IOError: If file cannot be read (permissions, missing)
            
        Implementation Rules:
        1. MUST handle EOF gracefully (stop when no more packets)
        2. MUST preserve packet order (first in file = first yielded)
        3. SHOULD use memory mapping for large files (for speed)
        4. MUST set packet_id correctly (starts at 1!)
        """
        pass
    
    # =========================================================================
    # TODO: MUST IMPLEMENT - INDEX RECORD CREATION
    # =========================================================================
    @abstractmethod
    def get_index_record(self, packet: RawPacket, packet_id: int) -> PacketIndexRecord:
        """
        Create index record for a packet.
        
        This creates the "library card" for searching packets later.
        
        Args:
            packet: RawPacket from the iterator
            packet_id: Should match packet.packet_id (for validation)
            
        Returns:
            PacketIndexRecord with all required fields
            
        IMPORTANT: Must be DETERMINISTIC!
        - Same packet → same index record, every time
        - No random values
        - No system-specific values (like current time)
        
        Implementation Rules:
        1. Use PacketIndexBuilder for consistency
        2. Validate packet_id matches packet.packet_id
        3. Fill in placeholder values for fields not yet decoded
        """
        pass
    
    # =========================================================================
    # TODO: MUST IMPLEMENT - SESSION METADATA
    # =========================================================================
    @abstractmethod
    def get_session_info(self) -> Dict[str, Any]:
        """
        Return session metadata.
        
        This info is used to build the SessionManifest.
        
        Returns dictionary with AT LEAST:
        - 'packet_count': Total packets in source
        - 'time_range': Tuple of (start_us, end_us) in microseconds
        - 'link_types': List of DLT_* constants present (e.g., [1, 12])
        - 'file_size': Size in bytes (for file sources)
        
        Optional fields (implementation-specific):
        - 'format_version': PCAP/PCAPNG version
        - 'snaplen': Maximum capture length
        - 'endianness': 'big' or 'little'
        - 'is_nanosecond': True if nanosecond timestamps
        
        Implementation Rules:
        1. Calculate time_range by scanning packets
        2. Count packets during iteration
        3. Track all link types encountered
        """
        pass
    
    # =========================================================================
    # TODO: MUST IMPLEMENT - OPEN SOURCE
    # =========================================================================
    @abstractmethod
    def open(self):
        """
        Open the packet source for reading.
        
        Called before iteration starts.
        
        Should do:
        1. Validate file format (check magic numbers)
        2. Initialize resources (open files, memory maps)
        3. Read initial metadata (global headers)
        4. Prepare for iteration
        
        Raises:
            FileNotFoundError: If file doesn't exist
            FormatError: If file format is invalid
            PermissionError: If cannot read file
            
        Implementation Rules:
        1. MUST validate file is correct format
        2. MUST set up for iteration (reset counters, etc.)
        3. SHOULD use context manager pattern
        """
        pass
    
    # =========================================================================
    # TODO: MUST IMPLEMENT - CLOSE SOURCE
    # =========================================================================
    @abstractmethod
    def close(self):
        """
        Close the packet source and release resources.
        
        Called after iteration completes or on error.
        
        Should do:
        1. Close file handles
        2. Release memory mappings
        3. Clean up temporary resources
        4. Reset state if needed
        
        Implementation Rules:
        1. MUST be safe to call multiple times
        2. MUST release system resources (files, memory)
        3. SHOULD not raise errors on already-closed resources
        """
        pass
    
    # =========================================================================
    # TODO: IMPLEMENT - CONTEXT MANAGER (already done below)
    # =========================================================================
    def __enter__(self):
        """
        Context manager entry: open the source.
        
        Enables 'with' statement:
            with PcapReader("file.pcap") as reader:
                for packet in reader:
                    process(packet)
                    
        Implementation: Already done - calls self.open()
        """
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit: close the source.
        
        Ensures resources are cleaned up even if errors occur.
        
        Implementation: Already done - calls self.close()
        """
        self.close()
    
    def __del__(self):
        """
        Destructor: cleanup during garbage collection.
        
        Safety net in case user forgets to close().
        
        Implementation: Already done - tries to close()
        """
        try:
            self.close()
        except:
            pass  # Ignore errors during garbage collection
