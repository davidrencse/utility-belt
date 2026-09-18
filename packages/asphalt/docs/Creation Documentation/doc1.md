# Daily Recap: 2026-01-19

### **PacketIndexBuilder**
**What it does**: Creates searchable index cards for every packet
**Key learning**: 
- **Determinism is critical** - same input must always produce same output
- Uses **Blake2b hashing** for packet fingerprints (fast and cryptographic)
- Creates **pcap_ref** strings that work like "GPS coordinates" for packets: `"file_id:start_offset:data_offset"`
- Packet IDs must start at **1** and be monotonic (1, 2, 3...)


### **Models vs Interfaces**
- **Models** (`RawPacket`, `PacketIndexRecord`, `SessionManifest`) are **data containers**
- **Interfaces** (`IPacketSource`) are **contracts/job descriptions**
- Models **store data**, Interfaces **define what must be done** with data
- This separation prevents spaghetti code and enforces boundaries

- Models = **Pizza boxes** (hold data)
- Interfaces = **Pizza recipes** (define how to make them)
- Implementations = **Pizza chefs** (actually make the pizza)

### **@abstractmethod**
- `@abstractmethod` means "child classes MUST implement this"
- Interface files only contain `pass` for abstract methods
- Concrete implementations go in separate files (`pcap_reader.py`)
- Context manager methods (`__enter__`, `__exit__`, `__del__`) can be implemented in the interface because they're always the same


### **PCAP File Structure **
PCAP files have:
- **24-byte global header** with magic number, version, link type
- **Magic numbers** determine endianness and timestamp resolution
- Each packet has: **16-byte header** (timestamp + lengths) + **packet data**
- **Padding** to 32-bit boundaries (important for file navigation)

### **Testing and Import Patterns**
**Practical Python knowledge**:
- Python's `sys.path` determines where modules are found
- Need to add project root to path when running tests
- `python -m testing.test_packet_index` works better than direct execution
- Test-driven development: write tests that verify contracts

### **Common Python Mistakes Fixed**
1. **`os.path.exists()`** needs an argument: `os.path.exists(path)`
2. **FileNotFoundError vs FileExistsError**: 
   - `FileNotFoundError`: file missing when trying to read
   - `FileExistsError`: file already exists when trying to create
3. **Store function results**: `self.mmap = mmap.mmap(...)` not just `mmap.mmap(...)`
4. **Property recursion**: `return self.current_packet_id` calls itself infinitely; use `return self._packet_counter`


### The Data Flow Pipeline
```
PCAP File (binary)
     ↓
PcapReader (opens file, reads bytes) → Implements IPacketSource interface
     ↓
RawPacket (container: timestamp, data, pcap_ref, etc.)
     ↓
PacketIndexBuilder (creates searchable index)
     ↓  
PacketIndexRecord (library card: hash, location, metadata)
     ↓
SessionManifestBuilder (creates session receipt)
     ↓
SessionManifest (metadata: file hash, time range, packet count)
```

### Key Design Principles

1. **Single Responsibility**: Each class does ONE thing well
2. **Immutability**: Models are frozen (`@dataclass(frozen=True)`) to prevent accidental changes
3. **Determinism**: Same input → same output, critical for testing and reliability
4. **Contract-First**: Define interfaces before implementations
5. **Resource Management**: Always close files/memory maps (context managers help)

### Python Patterns 

1. **Abstract Base Classes**: Define contracts with `@abstractmethod`
2. **Context Managers**: `__enter__`/`__exit__` for safe resource handling
3. **Memory Mapping**: `mmap` for zero-copy file access (critical for large PCAPs)
4. **Type Hints**: `-> Iterator[RawPacket]` helps catch errors early
5. **Property Decorators**: `@property` for computed attributes


# Notes
Packet Header Structure
text

Packet Header (16 bytes):
┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│ ts_sec (4 bytes)│ ts_frac (4 bytes)│ caplen (4 bytes)│ wirelen (4 bytes)│
└─────────────────┴─────────────────┴─────────────────┴─────────────────┘

ts_sec: Seconds since 1970-01-01 (Unix timestamp)
ts_frac: Fraction of second (microseconds OR nanoseconds)
caplen: Bytes actually captured (may be less than wirelen due to snaplen)
wirelen: Original packet size on the wire