"""
PCAPNG file format reader (next generation .pcapng).

Reference: https://github.com/pcapng/pcapng

File structure:
- Block-based format (Type-Length-Value blocks)
- Each block has: Block Type (4B) + Block Length (4B) + Block Body + Block Length (repeat)
- Must be 32-bit aligned

Key blocks:
1. Section Header Block (SHB) - Defines a section (like PCAP header)
2. Interface Description Block (IDB) - Defines network interface
3. Enhanced Packet Block (EPB) - Contains packet data (most common)
4. Simple Packet Block (SPB) - Simplified packet
5. Name Resolution Block (NRB) - DNS-like name resolution
"""

import struct
import mmap
from typing import BinaryIO, Iterator, Dict, Any, Optional, List, Tuple
import os
from .packet_source import IPacketSource
from .exceptions import PcapngFormatError, PcapEOFError
try:
    from ..models.packet import RawPacket
except ImportError:
    from models.packet import RawPacket
from .packet_index import PacketIndexRecord, PacketIndexBuilder

class PcapngReader(IPacketSource):
    """
    Reads PCAPNG format files.
    
    Key differences from PCAP:
    1. Block-based instead of linear packet records
    2. Supports multiple interfaces in one file
    3. Extensible with custom block types
    4. More metadata (interface descriptions, comments, etc.)
    5. 64-bit timestamps (nanosecond resolution)
    """
    
    # Block type constants
    BLOCK_TYPE_SECTION_HEADER = 0x0A0D0D0A
    BLOCK_TYPE_INTERFACE_DESCRIPTION = 0x00000001
    BLOCK_TYPE_ENHANCED_PACKET = 0x00000006
    BLOCK_TYPE_SIMPLE_PACKET = 0x00000003
    BLOCK_TYPE_NAME_RESOLUTION = 0x00000004
    BLOCK_TYPE_INTERFACE_STATS = 0x00000005
    
    def __init__(self, filepath: str):
        """
        Initialize PCAPNG reader.
        
        Args:
            filepath: Path to .pcapng file
        """
        self.filepath = filepath
        
        self.file_handle: Optional[BinaryIO] = None
        self.mmap: Optional[mmap.mmap] = None
        
        # Interface info: {if_id: {'link_type': int, 'snaplen': int, 'name': str or None, 'tsresol': int or None, ...}}
        self.interfaces: Dict[int, Dict[str, Any]] = {}
        
        # Current section metadata (updated on each SHB)
        self.current_section: Dict[str, Any] = {
            'byte_order': 'little',  
            'version_major': 1,
            'version_minor': 0,
            'section_length': -1,       
            'start_offset': 0,
        }
        
        self._packet_count: int = 0
        self._time_range: Optional[Tuple[int, int]] = None 
        self._file_size: int = 0
        self._current_offset: int = 0
        
        # For building index / random access later: packet_id → byte offset of its block
        self.block_offsets: Dict[int, int] = {} 
        
    def open(self):
        """
        Open and validate PCAPNG file.
        
        Implementation of abstract method from IPacketSource.
        """
        # 1. Check file exists
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"PCAPNG file not found: {self.filepath}")
        
        # 2. Open file
        self.file_handle = open(self.filepath, 'rb')
        
        # 3. Get file size
        self._file_size = os.path.getsize(self.filepath)
        
        # 4. Create memory map
        try:
            self.mmap = mmap.mmap(
                self.file_handle.fileno(),
                0,  # Map entire file
                access=mmap.ACCESS_READ
            )
        except Exception as e:
            self.file_handle.close()
            self.file_handle = None
            raise PcapngFormatError(f"Failed to memory map file: {e}")
        
        # 5. Parse initial blocks to find SHB and IDBs
        self._parse_initial_blocks()
        
        # 6. Set starting offset
        self._current_offset = 0
    
    def _read_block_header(self, offset: int) -> Tuple[int, int]:
        """
        Read block type and length at given offset.
        
        PCAPNG block format:
        - Bytes 0-3: Block Type (e.g., 0x0A0D0D0A = Section Header)
        - Bytes 4-7: Block Total Length (includes header and footer)
        
        Args:
            offset: Position in file to read from
            
        Returns:
            Tuple of (block_type, block_total_length)
            
        Raises:
            PcapEOFError: If not enough bytes for header
        """
        # 1. Check we have enough bytes
        if offset + 8 > len(self.mmap):
            raise PcapEOFError(f"Not enough bytes for block header at offset {offset}")
        
        # 2. Read 8 bytes from memory map
        header_bytes = self.mmap[offset:offset + 8]
        
        # 3. Unpack as two 32-bit unsigned integers (little-endian)
        block_type, block_length = struct.unpack('<II', header_bytes)
        
        # 4. Validate block_length makes sense
        if block_length < 12:
            raise PcapngFormatError(
                f"Invalid block length {block_length} at offset {offset} - "
                f"must be at least 12 bytes"
            )
        
        if offset + block_length > len(self.mmap):
            raise PcapEOFError(
                f"Block extends past end of file: "
                f"offset={offset}, length={block_length}, "
                f"file size={len(self.mmap)}"
            )
        
        return block_type, block_length
    
    def _parse_section_header_block(self, offset: int):
        """
        Parse Section Header Block (SHB).
        """
        if self.mmap is None:
            raise PcapngFormatError("File not memory-mapped")
        
        # Read block type and length
        block_type, block_length = struct.unpack_from("<II", self.mmap, offset)
        if block_type != self.BLOCK_TYPE_SECTION_HEADER:
            raise PcapngFormatError(f"Expected SHB at offset {offset}, got type {hex(block_type)}")
        
        # Byte-order magic (4B)
        bom = struct.unpack_from("<I", self.mmap, offset + 8)[0]
        if bom != 0x1A2B3C4D:
            raise PcapngFormatError(f"Invalid byte-order magic: {hex(bom)} (expected 0x1A2B3C4D)")
        
        # Version major/minor (2B each)
        version_major, version_minor = struct.unpack_from("<HH", self.mmap, offset + 12)
        
        # Section length (8B signed int, -1 = unknown)
        section_length = struct.unpack_from("<q", self.mmap, offset + 16)[0]
        
        # Validate trailing block length matches
        trailing_length = struct.unpack_from("<I", self.mmap, offset + block_length - 4)[0]
        if trailing_length != block_length:
            raise PcapngFormatError("Mismatched block lengths in SHB")
        
        # Update current_section
        self.current_section.update({
            'byte_order': 'little',
            'version_major': version_major,
            'version_minor': version_minor,
            'section_length': section_length,
            'start_offset': offset,
        })
    
    def _parse_interface_description_block(self, offset: int):
        """
        Parse Interface Description Block (IDB).
        """
        if self.mmap is None:
            raise PcapngFormatError("File not memory-mapped")
        
        # Read block type and length
        block_type, block_length = struct.unpack_from("<II", self.mmap, offset)
        if block_type != self.BLOCK_TYPE_INTERFACE_DESCRIPTION:
            raise PcapngFormatError(f"Expected IDB at offset {offset}, got type {hex(block_type)}")
        
        # Link type (2B), reserved (2B), snaplen (4B)
        link_type, _, snaplen = struct.unpack_from("<HHI", self.mmap, offset + 8)
        
        # Options start at offset + 16; parse some common ones
        opt_offset = offset + 16
        interface_info = {
            'link_type': link_type,
            'snaplen': snaplen,
            'tsresol': 6,  # Default μs (10**-6)
            'name': None,
        }
        
        while True:
            if opt_offset >= offset + block_length - 4:
                break
            opt_code, opt_len = struct.unpack_from("<HH", self.mmap, opt_offset)
            if opt_code == 0:  # End of options
                break
            opt_data_start = opt_offset + 4
            if opt_code == 2:  # if_name (UTF-8 string)
                interface_info['name'] = self.mmap[opt_data_start:opt_data_start + opt_len].decode('utf-8', errors='ignore').rstrip('\x00')
            elif opt_code == 9:  # if_tsresol (1B: unit+exponent)
                tsresol_byte = self.mmap[opt_data_start]
                if tsresol_byte & 0x80:  # Binary (2**exponent)
                    exponent = -(tsresol_byte & 0x7F)
                else:  # Decimal (10**exponent)
                    exponent = -tsresol_byte
                interface_info['tsresol'] = -exponent  # Store as log10 resolution
            # Pad to 32-bit
            padded_len = ((opt_len + 3) // 4) * 4
            opt_offset += 4 + padded_len
        
        # Validate trailing length
        trailing_length = struct.unpack_from("<I", self.mmap, offset + block_length - 4)[0]
        if trailing_length != block_length:
            raise PcapngFormatError("Mismatched block lengths in IDB")
        
        # Store: interface_id is sequential
        interface_id = len(self.interfaces)
        self.interfaces[interface_id] = interface_info
    
    def _parse_enhanced_packet_block(self, offset: int) -> RawPacket:
        """
        Parse Enhanced Packet Block (EPB) and return RawPacket.
        """
        if self.mmap is None:
            raise PcapngFormatError("File not memory-mapped")
        
        # Read block header (type + length)
        block_type, block_length = struct.unpack_from("<II", self.mmap, offset)
        if block_type != self.BLOCK_TYPE_ENHANCED_PACKET:
            raise PcapngFormatError(f"Expected EPB at offset {offset}, got type {hex(block_type)}")
        
        # Read: interface_id (4B), ts_high (4B), ts_low (4B), caplen (4B), wirelen (4B)
        interface_id, ts_high, ts_low, caplen, wirelen = struct.unpack_from("<IIIII", self.mmap, offset + 8)
        
        # Get interface info
        if_info = self.interfaces.get(interface_id)
        if if_info is None:
            raise PcapngFormatError(f"Unknown interface_id {interface_id}")
        
        # Calculate timestamp in microseconds
        ts_raw = (ts_high << 32) | ts_low
        tsresol = if_info['tsresol']
        if tsresol == 9:  # ns → μs
            timestamp_us = ts_raw // 1000
        elif tsresol == 6:  # μs
            timestamp_us = ts_raw
        else:
            raise NotImplementedError(f"Unsupported tsresol {tsresol}")
        
        # Read packet data
        data_start = offset + 8 + 20  # header + fields
        data = self.mmap[data_start:data_start + caplen]
        
        # Validate trailing length
        trailing_length = struct.unpack_from("<I", self.mmap, offset + block_length - 4)[0]
        if trailing_length != block_length:
            raise PcapngFormatError("Mismatched block lengths in EPB")
        
        # Create pcap_ref
        file_id = "0"  # Use file ID 0 for single-file sessions
        pcap_ref = f"{file_id}:{offset}"
        
        # Create RawPacket
        return RawPacket(
            packet_id=0,  # Will be assigned in __iter__
            timestamp_us=timestamp_us,
            captured_length=caplen,
            original_length=wirelen,
            link_type=if_info['link_type'],
            data=bytes(data),
            pcap_ref=pcap_ref,
            interface_id=interface_id,  # Store interface ID
        )
    
    def _parse_initial_blocks(self):
        """
        Parse initial blocks to find Section Header and Interface Descriptions.
        """
        if self.mmap is None:
            raise RuntimeError("File not opened")
        
        offset = 0
        found_shb = False
        
        while offset < len(self.mmap):
            # Read block header
            if offset + 8 > len(self.mmap):
                break
            
            block_type, block_length = self._read_block_header(offset)
            
            # Handle SHB first
            if block_type == self.BLOCK_TYPE_SECTION_HEADER:
                self._parse_section_header_block(offset)
                found_shb = True
            elif block_type == self.BLOCK_TYPE_INTERFACE_DESCRIPTION:
                self._parse_interface_description_block(offset)
            else:
                # Found a packet or unknown block - stop parsing initial metadata
                break
            
            # Move to next block
            offset += block_length
        
        if not found_shb:
            raise PcapngFormatError("No Section Header Block found")
        
        if not self.interfaces:
            print("Warning: No Interface Description Blocks found")
    
    def __iter__(self) -> Iterator[RawPacket]:
        """
        Read packets from file and yield them.
        
        Implementation of abstract method from IPacketSource.
        """
        if self.mmap is None:
            raise RuntimeError("PCAPNG file not opened. Call open() or use 'with' statement.")
        
        offset = 0
        packet_id = 1
        
        while offset < len(self.mmap):
            if offset + 8 > len(self.mmap):
                break  # Incomplete block
            
            try:
                block_type, block_length = self._read_block_header(offset)
            except PcapEOFError:
                break  # End of file
            
            # Process block based on type
            if block_type == self.BLOCK_TYPE_SECTION_HEADER:
                # We already parsed SHBs in _parse_initial_blocks
                pass
            elif block_type == self.BLOCK_TYPE_INTERFACE_DESCRIPTION:
                # We already parsed IDBs in _parse_initial_blocks
                pass
            elif block_type == self.BLOCK_TYPE_ENHANCED_PACKET:
                try:
                    packet = self._parse_enhanced_packet_block(offset)
                    # Assign packet_id
                    packet = RawPacket(
                        packet_id=packet_id,
                        timestamp_us=packet.timestamp_us,
                        captured_length=packet.captured_length,
                        original_length=packet.original_length,
                        link_type=packet.link_type,
                        data=packet.data,
                        pcap_ref=packet.pcap_ref,
                        interface_id=packet.interface_id,
                    )
                    
                    # Store block offset for indexing
                    self.block_offsets[packet_id] = offset
                    
                    # Update statistics
                    self._packet_count += 1
                    timestamp_us = packet.timestamp_us
                    if self._time_range is None:
                        self._time_range = (timestamp_us, timestamp_us)
                    else:
                        start, end = self._time_range
                        if timestamp_us < start:
                            start = timestamp_us
                        if timestamp_us > end:
                            end = timestamp_us
                        self._time_range = (start, end)
                    
                    yield packet
                    packet_id += 1
                    
                except Exception as e:
                    print(f"Warning: Failed to parse packet at offset {offset}: {e}")
                    # Skip this packet and continue
            elif block_type == self.BLOCK_TYPE_SIMPLE_PACKET:
                # TODO: Implement SPB parsing
                pass
            else:
                # Unknown block type - skip it
                pass
            
            # Move to next block
            offset += block_length
    
    def close(self):
        """
        Close the packet source and release resources.
        
        Implementation of abstract method from IPacketSource.
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
        self.block_offsets.clear()
        # Keep interfaces and current_section for potential reuse
    
    def get_index_record(self, packet: RawPacket, packet_id: int) -> PacketIndexRecord:
        """
        Create index record for a packet.
        
        Implementation of abstract method from IPacketSource.
        """
        # Create builder with placeholder session ID
        builder = PacketIndexBuilder(session_id="pcapng_session_placeholder")
        
        # Create index record
        return builder.create_index_record(packet)
    
    def get_session_info(self) -> Dict[str, Any]:
        """
        Return session metadata.
        
        Implementation of abstract method from IPacketSource.
        """
        link_types = [if_info['link_type'] for if_info in self.interfaces.values()]
        
        return {
            'packet_count': self._packet_count,
            'time_range': self._time_range if self._time_range is not None else (0, 0),
            'link_types': link_types,
            'file_size': self._file_size,
            'format': 'pcapng',
            'interfaces': self.interfaces,
            'sections': [self.current_section],
        }
