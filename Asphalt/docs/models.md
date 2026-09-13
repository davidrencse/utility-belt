# Asphalt Models Explained

## What Are Models?

Models are **data containers** - they define the **shape and rules** for data that flows through Asphalt. Think of them as **custom data types** that everyone agrees to use.

## Simple Analogy: Shipping Boxes

Imagine you run a warehouse:

- **Without models**: Workers throw items randomly into any box. "Is this a large or small item? Fragile or durable?" Nobody knows.
- **With models**: You have labeled boxes:
  - `SmallBox(max_weight=5kg, label="FRAGILE")`
  - `LargeBox(max_weight=20kg, label="DURABLE")`
  - Every worker knows exactly what goes where.

Models are those **labeled boxes**.

## The Three Core Models

### 1. `RawPacket` - The Raw Data Container

**What it does**: Stores exactly what comes out of a PCAP file.

```python
# Think of this as a "PCAP packet box"
@dataclass(frozen=True)  # Frozen = cannot be changed (important!)
class RawPacket:
    # REQUIRED LABELS on the box:
    packet_id: int          # "Box #1, #2, #3..."
    timestamp_us: int       # "Created at: 1,234,567,890 microseconds"
    captured_length: int    # "Actual contents: 64 bytes"
    original_length: int    # "Original size: 64 bytes"  
    link_type: int          # "Contents type: Ethernet"
    data: bytes             # THE ACTUAL DATA inside
    pcap_ref: str           # "Location: file 0, starts at byte 100"
    
    # OPTIONAL labels:
    interface_id: Optional[int] = None  # "From camera #2"
    comment: Optional[str] = None       # "Note: suspicious"
```

**Why frozen?** So nobody can change a packet after it's created. If you need to modify it, you create a NEW packet.

### 2. `PacketIndexRecord` - The Search Index Entry

**What it does**: Creates a "library card" for each packet so we can find it later.

```python
# Think of this as a "library catalog card"
@dataclass
class PacketIndexRecord:
    # BASIC INFO (like book title/author)
    packet_id: int          # "Book #42 in this library"
    session_id: str         # "Library: Downtown Branch"
    timestamp_us: int       # "Published: 1998"
    
    # SIZE INFO
    captured_length: int    # "Pages: 300"
    original_length: int    # "Original manuscript: 350 pages"
    
    # LOCATION INFO
    pcap_ref: str           # "Shelf: A3, Row 4"
    packet_hash: str        # "ISBN: 978-3-16-148410-0"
    
    # CONTENT INFO (PLACEHOLDERS for now)
    src_ip: str = "0.0.0.0"      # "Author: Unknown" 
    dst_ip: str = "0.0.0.0"      # "Publisher: Unknown"
    src_port: int = 0            # "Chapter: 0"
    dst_port: int = 0            # "Section: 0"
    protocol: int = 0            # "Genre: Unknown"
    stack_summary: str = "raw"   # "Tags: Fiction"
    
    # VERSION TRACKING
    schema_version: str = "0.2.0"  # "Catalog system v2.0"
```

**Why placeholders?** We don't know IP addresses yet (that's for next sprint). But we DEFINE the fields now so everything fits together later.

### 3. `SessionManifest` - The Session Receipt

**What it does**: Keeps a receipt for an entire capture session.

```python
# Think of this as a "shopping receipt"
@dataclass
class SessionManifest:
    # RECEIPT HEADER
    session_id: str          # "Transaction #TX-12345"
    created_at: str          # "Date: 2024-01-15 14:30:00"
    
    # WHAT WAS BOUGHT
    source_type: str         # "Store: Online"
    source_hash: str         # "Order hash: abc123..."
    original_path: Optional[str] = None  # "Original URL: ..."
    
    # TIMING
    time_start_us: int       # "Start shopping: 14:30:00"
    time_end_us: int         # "Finish: 14:45:00"
    
    # TOTALS
    total_packets: int       # "Items: 15"
    total_bytes_captured: int  # "Weight: 4.2kg"
    total_bytes_original: int  # "Original weight: 4.5kg"
    
    # WHERE IT'S STORED
    file_mapping: Dict[str, str]  # "Bag #1: Frozen, Bag #2: Produce"
    
    # SYSTEM INFO
    schema_version: str = "0.2.0"  # "Receipt format v2.0"
```

## How Models Work Together

```
PCAP File (raw bytes)
     |
     v
PcapReader (reads bytes, calculates values)
     |
     v
RawPacket (container holding: timestamp, data, etc.)
     |
     v
PacketIndexBuilder (creates index card for packet)
     |
     v
PacketIndexRecord (searchable index card)
     |
     v
SessionManifestBuilder (creates session receipt)
     |
     v
SessionManifest (complete session receipt)
```

## Key Model Features Explained

### 1. `@dataclass` - Automatic Boilerplate
```python
# WITHOUT @dataclass:
class RawPacket:
    def __init__(self, packet_id, timestamp_us, ...):
        self.packet_id = packet_id
        self.timestamp_us = timestamp_us
        # ... 10 more lines
        
    def __eq__(self, other):
        return self.packet_id == other.packet_id
    # ... more boilerplate

# WITH @dataclass: (Auto-generates all that!)
@dataclass
class RawPacket:
    packet_id: int
    timestamp_us: int
    # ... Python handles the rest
```

### 2. `frozen=True` - Immutability
```python
packet = RawPacket(packet_id=1, timestamp_us=1000, ...)

# CANNOT do this (throws error):
packet.packet_id = 2  # ERROR: "can't set attribute"

# MUST do this instead:
new_packet = RawPacket(packet_id=2, timestamp_us=1000, ...)
```

**Why?** So packets can't be accidentally changed after creation. This prevents bugs.

### 3. Type Hints - Documentation + Error Checking
```python
# BAD: What kind of data is this?
def process(data):
    pass  # Is data bytes? str? dict?

# GOOD: Clear what's expected
def process(packet: RawPacket) -> PacketIndexRecord:
    pass  # IDE shows error if wrong type passed
```

### 4. Default Values - Backward Compatibility
```python
@dataclass
class PacketIndexRecord:
    schema_version: str = "0.2.0"  # Default if not specified
    src_ip: str = "0.0.0.0"        # Default placeholder
    
# Works with old code:
old_data = {"packet_id": 1, "timestamp_us": 1000}
record = PacketIndexRecord(**old_data)  # Uses defaults for missing fields
```

## Common Questions

### Q: Do models parse files?
**A: NO!** Models are **containers**, not **parsers**. 
- **Parser** (`pcap_reader.py`): Reads file, calculates values
- **Model** (`RawPacket`): Stores those values

### Q: Why not just use dictionaries?
```python
# BAD: Dictionary (unclear, error-prone)
packet = {
    "id": 1,           # or "packet_id" or "num"?
    "time": 123456789, # seconds? milliseconds?
    "data": b"...",
}

# GOOD: Model (clear, type-safe)
packet = RawPacket(
    packet_id=1,        # Always this name
    timestamp_us=123456789000000,  # Always microseconds
    data=b"...",
)
```

### Q: What's with all the `Optional` and defaults?
**A: Future-proofing.** When we add new fields later, old code won't break.

### Q: Why `timestamp_us` not just `timestamp`?
**A: Precision matters.** `timestamp_us` explicitly says "microseconds". Avoids confusion between seconds/milliseconds/microseconds.

## Practical Example

```python
# 1. Reader PARSES the file
reader = PcapReader("capture.pcap")
reader.open()

# 2. Reader creates RawPacket CONTAINERS
for packet in reader:  # packet is a RawPacket
    # 3. Index builder uses packet to create index record
    index_record = index_builder.create_index_record(packet)
    
    # 4. All components understand the SAME structure
    print(f"Packet {packet.packet_id} at {packet.timestamp_us}μs")
    print(f"Indexed as {index_record.packet_hash}")
    
    # 5. Type safety: IDE helps catch errors
    # print(packet.timestmap)  # IDE shows error: typo!
    print(packet.timestamp_us)  # Correct!
```

## The "Deterministic" Part

Because models define EXACT structures:

```python
# Test: Same input → Same output
packet1 = RawPacket(packet_id=1, timestamp_us=1000, ...)
packet2 = RawPacket(packet_id=1, timestamp_us=1000, ...)  # Same values

index1 = builder.create_index_record(packet1)
index2 = builder.create_index_record(packet2)

# This MUST be true for deterministic pipeline:
assert index1.to_dict() == index2.to_dict()
```

## Summary

Models are:
- **Containers** for data 
- **Agreements** between components
- **Type-safe** with clear field names
- **Immutable** (can't change after creation)
- **Versioned** for future changes
- **Testable** for deterministic behavior

They're the **labeled boxes** that ensure every component in Asphalt understands the data the same way.