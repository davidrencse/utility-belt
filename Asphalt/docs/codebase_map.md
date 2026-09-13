# Asphalt Codebase Map

Last updated: 2026-01-23

This document gives a high-level map of the Asphalt codebase, with a focus on
the pipeline, objectives, and key functions/modules. It is meant to help a new
developer quickly understand how data flows through the system and where the
major responsibilities live.

## Objectives (Current Implementation)
- Deterministic packet processing: identical inputs should produce identical outputs.
- Support offline PCAP and PCAPNG loading, decoding, and analysis.
- Provide a plugin-style analysis pipeline that produces JSON reports.
- Provide basic UI options (CLI, HTTP server for a static UI, and a local Tk app).

## Architecture At A Glance
Primary data flow (offline):
PCAP/PCAPNG -> RawPacket -> DecodedPacket -> AnalysisEngine -> Analyzer results -> JSON report

Primary data flow (live, current tooling):
Capture backend -> packet queue -> RawPacket -> DecodedPacket -> UI/CLI display

Major components:
- Capture backends (live): src/capture
- Packet loaders (file): src/pcap_loader
- Data models: src/models, src/analysis/models.py
- Decoder: src/capture/packet_decoder.py
- Analysis engine + analyzers: src/analysis
- CLI entry points: src/asphalt_cli + run.py/asphalt.py
- UI entry points: ui_server.py, ui_app.py, ui/ (static), ui-react/ (React prototype)

## Repository Layout
- src/
  - asphalt_cli/: CLI commands (capture, decode, capture-decode, analyze)
  - capture/: live capture backends and packet decode integration
  - pcap_loader/: PCAP and PCAPNG readers + deterministic index builder
  - analysis/: analysis engine, flow tracking, analyzers, models
  - models/: core packet/index/session data structures
  - utils/: currently minimal placeholders
- ui/: static HTML/JS UI (served by ui_server.py)
- ui-react/: React UI prototype (not wired to runtime code)
- docs/: design and architecture docs
- testing/: unit and integration tests
- run.py / asphalt.py / asphalt_launcher.py / asphalt_cli.py: entry points

## Data Models (Key Types)
Core packet and index models:
- src/models/packet.py
  - RawPacket: immutable container for raw bytes + metadata.
  - DecodedPacket: immutable decoded representation.
- src/models/index_record.py
  - PacketIndexRecord: deterministic index entry for search and lookup.
- src/pcap_loader/session_manifest.py
  - SessionManifest + SessionManifestBuilder: deterministic session metadata.

Analysis models:
- src/analysis/models.py
  - AnalysisPacket: normalized decoded packet for analyzers.
  - FlowKey + FlowState: flow tracking and aggregates.
  - AnalysisReport + AnalyzerResult: JSON output shape.

Note: There is also src/models/session.py which defines a SessionManifest.
This is a parallel implementation to src/pcap_loader/session_manifest.py.
If you expand session handling, consider consolidating or clearly separating
these to avoid confusion.

## Pipeline Details

### Offline File Pipeline
1. Reader selection
   - src/asphalt_cli/decode.py and src/asphalt_cli/analyze.py determine the
     reader by file extension or magic number.
2. Packet loading
   - PCAP: src/pcap_loader/pcap_reader.py (PcapReader)
   - PCAPNG: src/pcap_loader/pcapng_reader.py (PcapngReader)
3. Raw packets
   - Readers yield RawPacket objects (packet_id, timestamp_us, lengths, link_type, data, pcap_ref).
4. Decoding
   - src/capture/packet_decoder.py parses L2/L3/L4 headers into DecodedPacket.
5. Analysis
   - src/analysis/engine.py wraps AnalysisPacket and forwards to analyzers.
   - Results are merged into AnalysisReport and serialized as JSON.

### Live Capture Pipeline (CLI/UI)
1. Backend selection
   - src/capture/scapy_backend.py (real capture, Windows via NpCap/Scapy)
   - src/capture/dummy_backend.py (synthetic packets for testing)
2. Capture loop
   - Packet queues are filled in the backend and pulled by CLI/UI.
3. Decode + display
   - src/asphalt_cli/capture_decode.py decodes and prints packets.
   - ui_server.py and ui_app.py run capture-decode and optionally analyze.

## Entry Points
- run.py: preferred CLI runner from project root (adds src to sys.path).
- asphalt.py / asphalt_cli.py / asphalt_launcher.py: CLI wrappers with varying behavior.
- ui_server.py: HTTP server that serves ui/ and exposes /capture endpoint.
- ui_app.py: Tkinter app that runs capture-decode + analysis locally.

## CLI Commands (src/asphalt_cli)
- capture: live capture stats and session summary (dummy or scapy backend).
- decode: decode PCAP/PCAPNG and print in table or JSON/JSONL.
- capture-decode: live capture + decode pipeline with table or JSON output.
- analyze: offline analysis over decoded packets with configurable analyzers.

## Analysis Engine and Analyzers
Engine:
- src/analysis/engine.py
  - AnalysisEngine.process_packet() converts DecodedPacket -> AnalysisPacket.
  - Flow state is tracked via src/analysis/flow.py.
  - finalize() merges AnalyzerResult outputs into AnalysisReport.

Registry:
- src/analysis/registry.py
  - register_analyzer decorator and create/list helpers.

Built-in analyzers:
- capture_health: capture quality and decode health summary.
- global_stats: totals + L4 distribution + flags.
- protocol_mix: protocol counts and percentages.
- flow_summary: per-flow summaries from FlowState.
- tcp_handshakes: SYN/SYN-ACK/ACK grouping and RTTs.
- abnormal_activity: heuristics for malformed packets, RST ratio, port scans.
- packet_chunks: fixed-size packet chunk summaries.
- time_series: time-bucketed packet/byte counts.

## Packet Indexing and Session Metadata
- src/pcap_loader/packet_index.py
  - PacketIndexBuilder produces deterministic PacketIndexRecord entries.
- src/pcap_loader/session_manifest.py
  - SessionManifestBuilder computes deterministic session_id and session stats.

## UI
Static UI (ui/):
- Minimal HTML/JS that expects /capture JSON from ui_server.py.

Tkinter UI (ui_app.py):
- Runs capture-decode, runs analysis, renders summary cards and packet table.

React UI (ui-react/):
- Prototype components and mock data, not wired to runtime.

## Testing
- testing/: unit tests for decoder, analysis, PCAP loaders, and CLI pipeline.
- dhcp.pcapng: sample capture used by tests.

## Known Gaps / Implementation Notes
- Some modules include TODOs or placeholders (for example, hash/utils and parts
  of pcapng parsing like Simple Packet Blocks).
- There are multiple CLI entry points; run.py is the cleanest for consistent imports.
- SessionManifest exists in two locations; unify or document the intended usage.

## Suggested Onboarding Path
1. Read docs/architecture.md and docs/analysis.md for conceptual flow.
2. Start with src/models/packet.py and src/capture/packet_decoder.py.
3. Walk through src/analysis/engine.py and src/analysis/analyzers/*.
4. Review src/pcap_loader/* for file ingestion and indexing.
5. Run run.py decode/analyze on a sample PCAP to see outputs.
