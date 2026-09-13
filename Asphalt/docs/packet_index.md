# What Does PacketIndex Do? (Simple Explanation)

## Think: **Book Index vs. Book Content**

- **Book Content** = The actual story (pages 1-300)
- **Book Index** = That section in the back that says:
  - "Elephants, mentioned on pages 45, 89, 156"
  - "Africa, discussed on pages 23-56"
  - "Zebra, page 102"

**PacketIndex is the "back of the book" for your PCAP file.**

## Real Example:

You have a PCAP file with 1,000,000 packets. You want to find:

> "Show me all packets between 2:00 PM and 2:01 PM"

**Without PacketIndex:**
- Read ALL 1,000,000 packets
- Check each timestamp
- Takes forever

**With PacketIndex:**
- Look in the "timestamp index" 
- Jump directly to packets around 2:00 PM
- Read maybe 1,000 packets
- Done in milliseconds

## What's Actually in the PacketIndex?

It's like a **library catalog card** for each packet:

```python
# For packet #42 in the file:
{
    "packet_id": 42,          # "Book #42 on shelf"
    "timestamp_us": 1700000000,  # "Published: 2023"
    "pcap_ref": "0:4200:4216",   # "Location: Shelf A, Row 3"
    "packet_hash": "abc123...",   # "ISBN number"
    "src_ip": "192.168.1.100",    # "Author: John"
    "dst_ip": "8.8.8.8",          # "Publisher: Google"
    "protocol": 6,                # "Genre: TCP"
    # ... other metadata
}
```

## The Key Fields Explained:

### 1. `pcap_ref` - The "GPS Coordinates"
```
"0:4200:4216"
 │   │    └── Data starts at byte 4216
 │   └─────── Packet record starts at byte 4200  
 └─────────── File ID #0 (first file in session)
```
**Why?** So we can JUMP directly to the packet without reading the whole file.

### 2. `packet_hash` - The "Fingerprint"
A unique ID for this exact packet. Like an ISBN for books.
- Same packet data → Same hash
- Different packet data → Different hash
- Used to detect duplicates

### 3. `timestamp_us` - The "When"
Microseconds since 1970. Allows:
- "Show packets from 2:00-2:01 PM"
- "Sort by time"
- "Find the first/last packet"

### 4. `src_ip`, `dst_ip`, `protocol` - The "Who & What"
(Placeholders in Sprint 0.2, will be filled later)
Allows queries like:
- "Show all traffic to 8.8.8.8"
- "Find HTTP packets (port 80)"
- "Show TCP connections"

## What PacketIndexBuilder Actually Does:

```python
# Input: RawPacket (the actual packet data)
packet = RawPacket(
    packet_id=1,
    timestamp_us=1700000000,
    data=b'\x00\x01\x02...',  # Actual packet bytes
    pcap_ref="0:100:116"
)

# Process: Creates "catalog card"
index = PacketIndexBuilder.create_index_record(packet)

# Output: PacketIndexRecord (the catalog card)
print(index.to_dict())
# {
#     "packet_id": 1,
#     "timestamp_us": 1700000000,
#     "pcap_ref": "0:100:116",
#     "packet_hash": "e4d7f1b...",  # ← Calculated from packet data
#     "src_ip": "0.0.0.0",  # ← Placeholder (for now)
#     ...
# }
```

## The "Deterministic" Part:

**CRITICAL REQUIREMENT:** Same PCAP file → Same index → Same results

```python
# Monday, run on Server A:
pcap_file = "capture.pcap"
index1 = PacketIndexBuilder.process_file(pcap_file)

# Tuesday, run on Server B (same file):
index2 = PacketIndexBuilder.process_file(pcap_file)

# MUST BE IDENTICAL:
assert index1 == index2  # True!

# Why? Because:
# 1. packet_id always starts at 1
# 2. packet_hash uses same algorithm
# 3. timestamps calculated same way
# 4. pcap_ref format consistent
```

## How It's Used Later:

### 1. **Fast Search** (Library Lookup)
```python
# "Find packets between 2:00-2:01 PM"
query = {
    "start_time": 1700000000,  # 2:00 PM
    "end_time":   1700000060,  # 2:01 PM
    "src_ip": "192.168.1.100"  # Optional filter
}

# Database query uses PacketIndex:
SELECT * FROM packet_index 
WHERE timestamp_us BETWEEN 1700000000 AND 1700000060
  AND src_ip = '192.168.1.100'
```

### 2. **Random Access** (Jump to Packet)
```python
# "Show me packet #42,567"
pcap_ref = index_db.get_ref(packet_id=42567)  # Returns "0:123456:123472"
# Jump directly to byte 123456 in file and read packet
```

### 3. **Statistics** (Counting)
```python
# "How many TCP packets to port 80?"
count = index_db.count(
    protocol=6,      # TCP
    dst_port=80      # HTTP
)
```

### 4. **Flow Reconstruction** (Future)
```python
# "Reconstruct this TCP conversation"
# Find all packets with same (src_ip, dst_ip, src_port, dst_port)
packets = index_db.get_flow_packets(
    src_ip="192.168.1.100",
    dst_ip="8.8.8.8", 
    src_port=54321,
    dst_port=80
)
```

## For Sprint 0.2:

Your `PacketIndexBuilder` has **TWO MAIN JOBS**:

### Job 1: Create Deterministic Packet IDs
```python
# MUST: Start at 1, increment by 1
packet1 → packet_id=1
packet2 → packet_id=2
packet3 → packet_id=3
# Always same order, always same IDs
```

### Job 2: Calculate Packet Hash
```python
# Like a fingerprint for the packet
hash = hash_function(
    timestamp + 
    packet_data + 
    lengths
)
# Same packet → Same hash
# Different packet → Different hash
```

### Job 3: Store Location (`pcap_ref`)
```python
# Where to find this packet later
pcap_ref = f"{file_id}:{start_offset}:{data_offset}"
# Example: "0:100:116" = file 0, packet starts at byte 100, data at byte 116
```

## What It's NOT:

- ❌ **NOT a parser** (doesn't read PCAP files)
- ❌ **NOT a storage system** (just creates index records)
- ❌ **NOT a search engine** (just creates data for search engine)

## What It IS:

- ✅ **A catalog card creator**
- ✅ **A fingerprint calculator**
- ✅ **A location tracker**
- ✅ **A deterministic ID generator**

## Simple Test to Understand:

```python
# Imagine 3 packets in a file:
packets = [
    # Packet 1: HTTP request
    RawPacket(packet_id=1, timestamp_us=1000, data=b'GET / ...', pcap_ref="0:100:116"),
    # Packet 2: HTTP response  
    RawPacket(packet_id=2, timestamp_us=1010, data=b'HTTP/1.1 ...', pcap_ref="0:200:216"),
    # Packet 3: DNS query
    RawPacket(packet_id=3, timestamp_us=1020, data=b'\x00\x01...', pcap_ref="0:300:316"),
]

# PacketIndexBuilder creates index cards:
index_cards = []
for packet in packets:
    card = PacketIndexBuilder.create_index_record(packet)
    index_cards.append(card)

# Now you have:
# [
#   {"packet_id": 1, "timestamp_us": 1000, "pcap_ref": "0:100:116", "hash": "abc123..."},
#   {"packet_id": 2, "timestamp_us": 1010, "pcap_ref": "0:200:216", "hash": "def456..."},
#   {"packet_id": 3, "timestamp_us": 1020, "pcap_ref": "0:300:316", "hash": "ghi789..."},
# ]

# Later, to find "packets around time 1005":
result = [card for card in index_cards if 995 <= card.timestamp_us <= 1015]
# Returns cards 1 and 2 instantly, without reading the file!
```

## Bottom Line:

**PacketIndex is the "table of contents" for your PCAP file.** It tells you:
- What's in the file
- Where to find it
- When it happened
- How to identify it uniquely

Without it, every search means reading the ENTIRE file. With it, you jump straight to what you need.