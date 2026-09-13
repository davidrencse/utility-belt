# Asphalt System Architecture Contract

## 1.1 Executive Summary
Asphalt is a production-grade network diagnostics platform combining Wireshark-level packet capture capabilities with an opinionated analytics and diagnostics layer. It provides full-fidelity packet capture, real-time protocol decoding, configurable analysis pipelines, and a unified diagnostic UI with interactive visualizations and actionable insights—transforming raw packet data into operational intelligence.

## 1.2 System Context Diagram
```
┌─────────────────────────────────────────────────────────────┐
│                    External Entities                         │
├─────────────┬──────────────┬──────────────┬─────────────────┤
│Network      │PCAP Import   │API Clients   │Administrator    │
│Interfaces   │(Files)       │(REST/WebSocket│(UI/CLI)        │
│             │              │)             │                 │
└──────┬──────┴───────┬──────┴──────┬───────┴─────────────────┘
       │              │             │
       ▼              ▼             ▼
┌─────────────────────────────────────────────────────────────┐
│                    Asphalt System Boundary                   │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────────┐  │
│  │Capture     │  │Analytics   │  │Diagnostics UI        │  │
│  │Engine      │◄─┤Pipeline    │◄─┤& API Gateway         │  │
│  └────────────┘  └────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 1.3 Component Diagram and Responsibilities

| Component | Inputs | Outputs | Responsibilities |
|-----------|--------|---------|------------------|
| **Elevated Capture Service** | Network interface config, BPF filters, rotation policies | Raw packets (PCAPNG), capture metadata, performance metrics | Privileged packet capture, BPF compilation, PCAPNG rotation, drop monitoring, hardware timestamping |
| **Packet Decoder** | Raw packets from queue, protocol definitions | Decoded packet objects, protocol metadata, error events | Protocol decoding (Ethernet→IP→TCP/UDP→application), checksum validation, reassembly, malformed packet handling |
| **Flow Tracker** | Decoded packets, flow timeout config | Flow records, session metadata, RTT calculations | TCP/UDP/ICMP flow identification, session state tracking, connection lifecycle events, flow termination detection |
| **Analysis Task Runner** | Decoded packets, flow records, task configurations | Analysis results, time-series data, diagnostic findings | Executes configured analysis modules (retransmission detection, latency spikes, protocol anomalies), produces normalized outputs |
| **Unified Parser** | Raw analysis outputs, normalization schema | Normalized records (JSON/Protobuf), schema version | Schema enforcement, data normalization, version compatibility, output validation |
| **Index Builder** | Decoded packets, flow records, user queries | Search indices, paging tokens, query results | Creates/searchable indices (timestamp, IP 5-tuple, protocol), supports pagination, index optimization |
| **Storage Manager** | PCAPNG files, indices, analysis results | Storage manifests, retention reports, integrity checks | Tiered storage management, rotation/retention policies, data integrity verification, archive operations |
| **API Gateway** | HTTP/REST requests, WebSocket connections, UI events | JSON/Protobuf responses, real-time events, UI state | Request routing, authentication/authorization, rate limiting, WebSocket management, API versioning |
| **Diagnostics UI** | User interactions, real-time data streams, configuration | Visualizations, alerts, reports, configuration changes | Interactive dashboards, graph rendering, drill-down navigation, explanation generation, configuration interface |
| **Metrics Collector** | Component events, performance data, system metrics | Time-series metrics, health status, alert conditions | Performance monitoring, SLA tracking, anomaly detection, observability data export |

## 1.4 Runtime Flows

### Flow A: Start/Stop Capture Sequence Diagram

```
User → API Gateway → Elevated Capture Service → Storage Manager → Index Builder
      ↓             ↓                           ↓                 ↓
    UI Updates   IPC Auth                    File Rotation     Index Updates
      ↓             ↓                           ↓                 ↓
WebSocket Events ← Metrics Streaming ← Capture Loop → Packet Processing
```

**Steps:**
1. **UI Request**: POST `/api/capture/start` with interface and filter
2. **Privileged Execution**: Capture service starts with elevated privileges
3. **Storage Setup**: Session manifest and PCAPNG file creation
4. **Capture Loop**: 
   - Real-time packet capture with BPF filtering
   - Time/size-based file rotation
   - Concurrent indexing of captured packets
5. **Live Updates**: Metrics streamed via WebSocket to UI
6. **Clean Shutdown**: Final index build and session summary

### Flow B: Load PCAP → Analyze → Render Sequence Diagram

```
UI → API Gateway → Storage Manager → Index Builder → Packet Decoder → Flow Tracker
↓                    ↓                  ↓               ↓                ↓
Render ← Results ← Task Runner ← Unified Parser ← Analysis Modules ← Flow Context
```

**Steps:**
1. **Session Load**: UI requests PCAP analysis with specific profile
2. **Index Check/ Build**: 
   - If index exists: load metadata
   - If missing: decode packets and build search indices
3. **Analysis Pipeline**:
   - Filtered packet retrieval via indices
   - Protocol decoding with flow context
   - Configurable analysis module execution
   - Output normalization via unified parser
4. **Visualization**: 
   - Schema-conformant data retrieval
   - UI rendering of graphs and diagnostics

## 1.5 Storage Model (Three-Tier)

### Tier 1: PCAPNG Store
**Format**: Standard PCAPNG with custom Asphalt blocks
**Rotation**: Time-based (default 5min) or size-based (default 100MB)
**Retention**: Configurable policy (time, space, or count-based)

**Session Manifest Format**:
```json
{
  "session_id": "uuid",
  "start_time": "iso8601",
  "end_time": "iso8601",
  "interface": "eth0",
  "filter": "tcp port 443",
  "files": [
    {"sequence": 1, "path": "/data/...", "time_range": [...], "size": 104857600},
    {"sequence": 2, "path": "/data/...", "time_range": [...], "size": 104857600}
  ],
  "total_packets": 1500000,
  "total_bytes": 1572864000,
  "index_status": "complete"
}
```

### Tier 2: Packet Index
**Primary Key**: `(session_id, file_sequence, packet_offset)`

**Indices**:
- **Timestamp**: `(session_id, timestamp_ns)` → `(file_sequence, offset)`
- **Flow 5-tuple**: `(session_id, src_ip, dst_ip, src_port, dst_port, protocol)` → `[timestamp_ranges]`
- **Protocol**: `(session_id, protocol, port)` → `[timestamp_ranges]`
- **Custom**: Plugin-defined indices via configuration

**Paging**: Opaque tokens containing `(session_id, last_timestamp, last_offset, limit)`
**Storage Format**: Columnar (Parquet) for time-series queries

### Tier 3: Analytics DB
**Tables Structure**:

```sql
-- Flows table
CREATE TABLE flows (
  flow_id UUID PRIMARY KEY,
  session_id UUID REFERENCES sessions,
  start_time TIMESTAMPTZ,
  end_time TIMESTAMPTZ,
  src_ip INET,
  dst_ip INET,
  src_port INTEGER,
  dst_port INTEGER,
  protocol INTEGER,
  packet_count INTEGER,
  byte_count INTEGER,
  flags INTEGER,
  rtt_stats JSONB
);

-- Time-series table
CREATE TABLE timeseries (
  session_id UUID,
  metric_name VARCHAR(50),
  timestamp TIMESTAMPTZ,
  value DOUBLE PRECISION,
  tags JSONB,
  PRIMARY KEY (session_id, metric_name, timestamp)
);

-- Findings table  
CREATE TABLE findings (
  finding_id UUID PRIMARY KEY,
  session_id UUID,
  severity VARCHAR(10),
  category VARCHAR(50),
  title VARCHAR(200),
  description TEXT,
  evidence JSONB,
  packet_references UUID[],
  flow_references UUID[],
  created_at TIMESTAMPTZ
);

-- Task outputs table
CREATE TABLE task_outputs (
  task_id UUID,
  session_id UUID,
  output_type VARCHAR(50),
  output_data JSONB,
  schema_version INTEGER,
  created_at TIMESTAMPTZ,
  PRIMARY KEY (task_id, session_id, output_type)
);
```

## 1.6 Backpressure and Performance Model

### Queue Architecture
```
Network → [Ring Buffer (kernel)] → [Capture Queue (100k pkts)] → Decoder
Decoder → [Flow Queue (50k pkts)] → Flow Tracker
Flow Tracker → [Analysis Queue (25k items)] → Task Runner
```

### Drop Policies (Configurable)
1. **Drop-Oldest**: Default for capture queue (preserve newest traffic)
2. **Drop-Newest**: For analysis queue (preserve temporal sequence)
3. **Sampling**: Configurable rate (1:N) when sustained overload
4. **Intelligent Drop**: Protocol-aware (preserve TCP handshakes, drop duplicates)

### Observable Metrics
**Per-Queue Metrics**:
- `asphalt_queue_depth{component="capture"}`: Current items in queue
- `asphalt_queue_drops_total{component="capture",policy="drop_oldest"}`: Total dropped items
- `asphalt_queue_latency_seconds{quantile="0.95"}`: 95th percentile processing latency

**System Metrics**:
- `asphalt_packets_processed_total`: Total packets processed
- `asphalt_decode_errors_total`: Protocol decoding errors
- `asphalt_storage_write_latency_seconds`: Storage write performance
- `asphalt_memory_usage_bytes`: Component memory consumption

### Budget Targets (Placeholders)
| Resource | Target | Measurement Method |
|----------|--------|-------------------|
| CPU | ≤70% per core under 1Gbps | `cpu_usage_seconds_total` |
| RAM | ≤2GB baseline + 1GB per 10k active flows | `process_resident_memory_bytes` |
| Disk Write | Sustained 200MB/s, burst 500MB/s | `disk_write_bytes_second` |
| Packet Loss | <0.1% at 10Gbps line rate | `packets_dropped_total / packets_received_total` |
| UI Latency | <100ms for indexed queries | API response time histograms |

## 1.7 Privilege Model and Threat Boundaries

### Privilege Separation Architecture
```
┌────────────────────┐    UNIX Domain Socket    ┌────────────────────┐
│  Elevated Capture  │◄────────────────────────►│  Unprivileged Main │
│      Service       │   (authenticated IPC)    │     Process        │
│  (root/cap_net_raw)│                          │   (user context)   │
└────────────────────┘                          └────────────────────┘
         │                                              │
         ▼                                              ▼
   Raw Socket Access                           All other components
   BPF Injection                                (Decoder, Analytics,
   PCAPNG Writing                                 UI, Storage, API)
```

### IPC Mechanism
- **Primary**: gRPC over UNIX domain sockets with mutual TLS authentication
- **Fallback**: Named pipes with kernel-level access control
- **Authentication**: Mutual certificate-based with short-lived tokens
- **Authorization**: Component-level capability model

### Threat Model

| Threat Actor | Capabilities | Mitigations |
|--------------|-------------|-------------|
| **Local Attacker** | Execute code on host, sniff local traffic | IPC authentication, capability limiting, process isolation, no shell access from capture service |
| **Untrusted PCAP Input** | Malformed files, crafted packets, resource exhaustion | Input validation, parser sandboxing, resource quotas, timeouts, isolated processing context |
| **Malformed Packets** | Protocol violations, buffer overflow attempts | Defensive decoding, bounds checking, protocol anomaly detection, fuzz-tested parsers |
| **API Attacker** | Unauthenticated requests, injection attempts | Authentication middleware, input sanitization, rate limiting, SQL injection protection |
| **Privilege Escalation** | Attempt to gain capture service privileges | Minimal capability set, no external network access, seccomp filters, regular privilege drops |

### Security Boundaries
1. **Capture Boundary**: Only the capture service runs elevated; communicates via authenticated IPC
2. **Parser Boundary**: All packet parsing occurs in unprivileged processes with resource limits
3. **Storage Boundary**: Write-only access for capture service; read/write for main process
4. **API Boundary**: All external inputs validated and sanitized before processing

---

## Contract Enforcement & Change Management

### Change Identification Protocol
For any future change, reviewers must identify:

1. **Module Ownership**: Which component(s) in section 1.3 are modified
2. **Schema Impact**: How storage models (1.5) or IPC contracts evolve
3. **UI Integration**: Which API endpoints (1.4 flows) and visualizations are affected
4. **Performance Impact**: Updates to budgets (1.6) or queue sizing
5. **Security Review**: Threat model implications (1.7)

### Acceptance Criteria
- [ ] All components have single responsibility per 1.3 table
- [ ] All data flows match sequence diagrams in 1.4
- [ ] Storage schema supports required queries without monolith coupling
- [ ] Performance targets have measurement hooks defined
- [ ] Privilege separation is enforceable in deployment
- [ ] Every future feature maps to exactly one component's responsibility

### Review Gate Definition
**Sprint Completion**: When a reviewer can point to any proposed change and immediately identify:
- The owning component from 1.3
- Required schema changes from 1.5
- API/UI integration points from 1.4
- Performance budget implications from 1.6
- Security boundary considerations from 1.7

This ensures implementation cannot drift into an untestable monolith, as all component boundaries and contracts are explicitly defined and enforceable.