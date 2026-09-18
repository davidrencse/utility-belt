# Packet Analysis Subsystem

This document describes the offline packet-analysis subsystem that runs on decoded packets and produces JSON reports.

## Architecture

### Pipeline

1. Read packets from PCAP or PCAPNG (offline).
2. Decode packets to structured fields.
3. Analyze decoded packets using a plugin-style analyzer framework.
4. Emit a JSON AnalysisReport with global, per-flow, and optional time-series results.

### Components

- AnalysisEngine: streams decoded packets into analyzers and manages flow state.
- Analyzer plugins: independent modules that compute results (global, per-flow, time-series).
- Registry: maps analyzer names to implementations and enables selection via CLI.
- Models: AnalysisPacket, FlowKey, FlowState, AnalysisReport.

### Analyzer Contract

Each analyzer implements:

- on_start(context)
- on_packet(packet, flow_key, flow_state, context)
- on_end(context) -> AnalyzerResult

The engine merges analyzer results into the final report.

## Data Models

### AnalysisPacket (decoded representation)
Fields (subset):
- packet_id, timestamp_us
- captured_length, original_length
- ip_version, src_ip, dst_ip
- ip_protocol, l4_protocol, src_port, dst_port
- tcp_flags, ttl, quality_flags
- payload_bytes (optional, not serialized by default)

### FlowKey (5-tuple + protocol + direction)
- src_ip, dst_ip, src_port, dst_port, ip_protocol
- direction: fwd or rev (relative to canonical flow order)

### FlowState (aggregates and derived metrics)
- flow_id and canonical endpoints (a_ip:a_port, b_ip:b_port)
- first_ts_us, last_ts_us, duration_us
- packets and bytes (captured and original), total and per-direction
- protocol and quality counters

### AnalysisReport (JSON-serializable output)
- capture_path, created_at
- stats (packets_total, bytes_total, duration_us, etc.)
- global_results (per analyzer)
- flow_results (per analyzer)
- time_series (per analyzer)
- analyzers (name and version)

## Capture Health and Integrity

This analyzer surfaces whether a capture is trustworthy. It reports three sections:

- Capture Quality: drop stats (if available), kernel buffer drops, start/end/duration, link type, snaplen, promiscuous mode.
- Decode Health: decode success rate, malformed and truncated counts, unknown L3/L4, unsupported link types, checksum results (if computed).
- Filtering and Sampling: active filter, filtered-out count, sampling rate (if present).

When metadata is unavailable (e.g., offline files without capture stats), fields are populated as `n/a`.

## CLI Usage

Analyze a capture file offline and emit JSON:

```
python run.py analyze capture.pcapng --output report.json
```

Select analyzers and configure time-series buckets:

```
python run.py analyze capture.pcap --analyzers global_stats,protocol_mix,tcp_handshakes,abnormal_activity,packet_chunks,time_series --bucket-ms 500
```

## Built-in Analyzers

- global_stats: bytes, duration, IP/L4 distribution.
- capture_health: capture quality, decode health, filtering/sampling summary.
- protocol_mix: TCP/UDP/ICMP/ICMP6/other counts + percentages.
- flow_summary: per-flow aggregates (counts, bytes, duration).
- tcp_handshakes: groups SYN/SYN-ACK/ACK into handshakes.
- abnormal_activity: heuristics (malformed, high RST ratio, port scan suspicion, incomplete handshakes).
- packet_chunks: count-based chunk summaries.
- time_series: time-bucketed traffic summaries.
- throughput_peaks: bps/pps now, average, and per-bucket peak values.
- packet_size_stats: captured/original length stats, histogram buckets, fragmentation counts.
- l2_l3_breakdown: Ethernet/VLAN/ARP/ICMP counts, multicast/broadcast totals.
