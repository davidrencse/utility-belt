"""
PCAP file format reader (legacy .pcap).

Reference: https://wiki.wireshark.org/Development/LibpcapFileFormat

File structure:
- 24-byte global header
- Repeated packet records:
  - 16-byte packet header
  - Packet data (variable length, padded to 32-bit boundary)
"""

import struct
import mmap
from typing import BinaryIO, Iterator, Tuple, Dict, Any, Optional
import os
from .packet_source import IPacketSource
from .exceptions import PcapFormatError, PcapEOFError
try:
    from ..models.packet import RawPacket
except ImportError:
    from models.packet import RawPacket
from .packet_index import PacketIndexRecord, PacketIndexBuilder

class PcapReader(IPacketSource):
    """
    Reads legacy PCAP format files.
    
    This class MUST implement ALL abstract methods from IPacketSource.
    """
    
    # Magic numbers for format detection
    MAGIC_NUMBER_BIG_ENDIAN = 0xA1B2C3D4        # Standard microsecond
    MAGIC_NUMBER_LITTLE_ENDIAN = 0xD4C3B2A1     # Swapped microsecond
    MAGIC_NUMBER_BIG_ENDIAN_NANO = 0xA1B23C4D   # Nanosecond resolution
    MAGIC_NUMBER_LITTLE_ENDIAN_NANO = 0x4D3CB2A1 # Swapped nanosecond
    
    # Link type constants (from pcap/bpf.h)
    DLT_NULL = 0          # BSD loopback
    DLT_EN10MB = 1        # Ethernet
    DLT_RAW = 12          # Raw IP
    DLT_LINUX_SLL = 113   # Linux cooked socket
    
    def __init__(self, filepath: str):
        """
        Initialize PCAP reader.
        
        Args:
            filepath: Path to .pcap file
        """
        # TODO: Store filepath and initialize instance variables:
        # 1. file_handle: None (will be set in open())
        self.filepath = filepath
        self.file_handle = None
    
        # 2. mmap: None (memory mapping for fast access)
        self.mmap = None

        # 3. byte_order: '>' or '<' (detected in open())
        self.byte_order = '>'

        # 4. is_nanosecond: bool (detected in open())
        self.is_nanosecond = False

        # 5. link_type: int (detected in open())
        self.link_type = self.DLT_EN10MB # Default ethernet

        # 6. _packet_count: 0 (count packets as we read)
        self._packet_count = 0 

        # 7. _time_range: None (track (start_us, end_us))
        self._time_range = None

        # 8. _file_size: 0 (set in open())
        self._file_size = 0

        # 9. _current_offset: 0 (track position in file)
        self._current_offset = 0 
        
    def open(self):
        """
        Open and validate PCAP file.
        
        Implementation of abstract method from IPacketSource.
        """
        # TODO:
        # 1. Check file exists with os.path.exists()
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"PCAP file not found: {self.filepath}")
        
        # 2. Open file: self.file_handle = open(self.filepath, 'rb')
        self.file_handle = open(self.filepath, 'rb')

        # 3. Get file size: self._file_size = os.path.getsize(self.filepath)
        self._file_size = os.path.getsize(self.filepath)

        # 4. Call self._read_global_header() to validate and set format
        self._read_global_header()

        # 5. Create memory map
        try:
            self.mmap = mmap.mmap(
                self.file_handle.fileno(), 
                0,  # Map entire file
                access=mmap.ACCESS_READ
            )
        except Exception as e:
            # Close file if mmap fails
            self.file_handle.close()
            self.file_handle = None
            raise PcapFormatError(f"Failed to memory map file: {e}")

        # 6. Set self._current_offset = 24 (skip global header)
        self._current_offset = 24

    
    def _read_global_header(self):
        
        # Read and validate PCAP global header (24 bytes).
        
        # TODO:
        # 1. Read first 24 bytes from file_handle
        self.file_handle.seek(0)
        header_data = self.file_handle.read(24)
        # 2. Check length >= 24 bytes
        if len(header_data) < 24:
            raise PcapFormatError("File too small for PCAP header")
        
        # 3. Read magic number (first 4 bytes) to determine:
        #    - byte_order ('>' or '<')
        #    - is_nanosecond (True for nanosecond formats)
        magic_number, = struct.unpack('>I', header_data[0:4])

        # 4. Parse rest of header to get link_type
        if magic_number == self.MAGIC_NUMBER_BIG_ENDIAN:
            self.byte_order = '>'
            self.is_nanosecond = False
        elif magic_number == self.MAGIC_NUMBER_LITTLE_ENDIAN:
            self.byte_order = '<'
            self.is_nanosecond = False
        elif magic_number == self.MAGIC_NUMBER_BIG_ENDIAN_NANO:
            self.byte_order = '>'
            self.is_nanosecond = True
        elif magic_number == self.MAGIC_NUMBER_LITTLE_ENDIAN_NANO:
            self.byte_order = '<'
            self.is_nanosecond = True
        else:
            # Try little-endian interpretation for better error message
            magic_le, = struct.unpack('<I', header_data[0:4])
            raise PcapFormatError(
                f"Invalid PCAP magic number: 0x{magic_number:08x} (big) / "
                f"0x{magic_le:08x} (little). Expected one of the valid magic numbers."
            )
        # Step 5: Parse rest of header (bytes 4-24)
        # Format string: 'HHIIII' means:
        # H = unsigned short (2 bytes) - version_major
        # H = unsigned short (2 bytes) - version_minor  
        # I = unsigned int (4 bytes) - timezone offset (ignore)
        # I = unsigned int (4 bytes) - timestamp accuracy (ignore)
        # I = unsigned int (4 bytes) - snaplen (max packet size)
        # I = unsigned int (4 bytes) - link_type
        fmt = self.byte_order + 'HHIIII'
        version_major, version_minor, _, _, snaplen, self.link_type = \
            struct.unpack(fmt, header_data[4:24])
        
    
    def __iter__(self) -> Iterator[RawPacket]:
        """
        Read packets from file and yield them.
        """
        # 1. Check self.mmap exists (raise error if not opened)
        if self.mmap is None:
            raise RuntimeError("PCAP file not opened. Call open() or use 'with' statement.")
        
        # 2. Start at offset = 24 (after global header)
        offset = 24  # Use local variable, not self._current_offset for iteration
        
        # 3. packet_id = 1 (MUST start at 1!)
        packet_id = 1
        
        # 4. While there's enough bytes for a packet header (16 bytes):
        while offset + 16 <= len(self.mmap):
            
            # a. Store packet start for pcap_ref
            packet_start = offset
            
            # b. Read packet header (16 bytes from mmap[offset:offset+16])
            header = self.mmap[offset:offset + 16]
            if len(header) < 16:
                # Truncated header - end of file
                break
            
            # c. Parse header with struct.unpack(self.byte_order + 'IIII')
            # Format: 'IIII' = 4 unsigned integers:
            #   ts_sec: timestamp seconds
            #   ts_frac: timestamp fraction (micro/nanoseconds)
            #   caplen: captured length (bytes actually saved)
            #   wirelen: wire length (original packet size)
            fmt = self.byte_order + 'IIII'
            ts_sec, ts_frac, caplen, wirelen = struct.unpack(fmt, header)
            
            # d. Calculate timestamp_us (convert seconds + microseconds/nanoseconds)
            if self.is_nanosecond:
                # ts_frac is nanoseconds, convert to microseconds
                timestamp_us = ts_sec * 1_000_000 + ts_frac // 1000
            else:
                # ts_frac is already microseconds
                timestamp_us = ts_sec * 1_000_000 + ts_frac
            
            # Move to data start (after 16-byte header)
            offset += 16
            data_start = offset
            
            # e. Validate packet data fits in file
            if offset + caplen > len(self.mmap):
                raise PcapEOFError(
                    f"Packet {packet_id} truncated: "
                    f"expected {caplen} bytes at offset {offset}, "
                    f"but file only has {len(self.mmap)} bytes"
                )
            
            # f. Get packet data slice from mmap
            packet_data = self.mmap[offset:offset + caplen]
            
            # g. Create pcap_ref = f"0:{packet_start}:{data_start}"
            pcap_ref = f"0:{packet_start}:{data_start}"
            
            # h. Create RawPacket with all fields
            packet = RawPacket(
                packet_id=packet_id,
                timestamp_us=timestamp_us,
                captured_length=caplen,
                original_length=wirelen,
                link_type=self.link_type,
                data=bytes(packet_data),  # Convert to bytes for safety
                pcap_ref=pcap_ref
            )
            
            # i. Yield the RawPacket
            yield packet
            
            # j. Update tracking variables
            packet_id += 1
            self._packet_count += 1
            
            # Update time range (track earliest and latest timestamps)
            if self._time_range is None:
                self._time_range = (timestamp_us, timestamp_us)
            else:
                start, end = self._time_range
                if timestamp_us < start:
                    start = timestamp_us
                if timestamp_us > end:
                    end = timestamp_us
                self._time_range = (start, end)
            
            # k. Move offset to next packet (add caplen + padding)
            offset += caplen
            
            # PCAP files pad packet data to 32-bit (4-byte) boundaries
            if caplen % 4 != 0:
                padding = 4 - (caplen % 4)
                offset += padding
            
            # Update current offset (optional, for debugging)
            self._current_offset = offset
        
        # When loop ends, we've read all packets
        
    
    def close(self):
        """
        Close the packet source and release resources.
        Safe to call multiple times.
        """
        # Close memory map
        if self.mmap is not None:
            try:
                self.mmap.close()
            except:
                pass  # Already closed or error
            self.mmap = None
        
        # Close file handle
        if self.file_handle is not None:
            try:
                self.file_handle.close()
            except:
                pass  # Already closed or error
            self.file_handle = None
        
        # Reset state
        self._packet_count = 0
        self._time_range = None
        self._current_offset = 0
    
    def get_index_record(self, packet: RawPacket, packet_id: int) -> PacketIndexRecord:
        """
        Create index record for a packet.
        
        Implementation of abstract method from IPacketSource.
        """
        
        # Create PacketIndexBuilder instance
        # Need a session_id, but don't have it yet (will come from SessionManifest)
        # For now, use a placeholder like "unknown_session"
        builder = PacketIndexBuilder(session_id="unknown_session")
        
        # Call builder.create_index_record(packet)
        index_record = builder.create_index_record(packet)
        
        # Return the result
        return index_record
    
    def get_session_info(self) -> Dict[str, Any]:
        """
        Return session metadata.
        
        Implementation of abstract method from IPacketSource.
        
        TODO:
        Return dictionary with these REQUIRED keys:
        {
            'packet_count': self._packet_count,
            'time_range': self._time_range or (0, 0),
            'link_types': [self.link_type],  # List of link types found
            'file_size': self._file_size,
            'format': 'pcap',
            'byte_order': self.byte_order,
            'is_nanosecond': self.is_nanosecond,
            'link_type': self.link_type,
        }
        """

        return {
            'packet_count': self._packet_count,
            'time_range': self._time_range if self._time_range is not None else (0, 0),
            'link_types': [self.link_type],  # List of link types found
            'file_size': self._file_size,
            'format': 'pcap',
            'byte_order': self.byte_order,
            'is_nanosecond': self.is_nanosecond,
            'link_type': self.link_type,
        }
