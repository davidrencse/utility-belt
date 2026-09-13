"""
CLI command for live capture + decode (non-intrusive to existing capture).
"""
import time
import sys
import json
from typing import Optional

import click

from models.packet import RawPacket
from capture.decoder import PacketDecoder
from capture.packet_decoder import quality_flag_names


@click.command(name="capture-decode")
@click.option("--interface", "-i", required=True, help="Interface to capture from")
@click.option("--duration", "-d", type=int, help="Duration in seconds (default: run until limit)")
@click.option("--filter", "-f", help="BPF filter (e.g., \"tcp port 80\")")
@click.option("--packet-filter", "--filter-expr", "filter_expr",
              help="Filter expression for decoded packets")
@click.option("--limit", type=int, default=50, show_default=True,
              help="Max packets to decode (0 = no limit)")
@click.option("--show-quality", is_flag=True, help="Show decode quality flags")
@click.option("--format", "format", type=click.Choice(["table", "json", "jsonl"]),
              default="table", show_default=True, help="Output format")
@click.option("--output", "output", type=click.Path(dir_okay=False),
              help="Write JSON/JSONL output to file")
def capture_decode(interface: str,
                   duration: Optional[int],
                   filter: Optional[str],
                   limit: int,
                   show_quality: bool,
                   format: str,
                   output: Optional[str],
                   filter_expr: Optional[str]):
    """
    Live capture and decode packets, printing a compact summary.
    """
    try:
        from capture.scapy_backend import ScapyBackend
        from capture.icapture_backend import CaptureConfig
    except ImportError as e:
        click.echo(f"Error importing capture modules: {e}", err=True)
        sys.exit(1)

    try:
        capture_backend = ScapyBackend()
    except Exception as e:
        click.echo(f"Error initializing scapy backend: {e}", err=True)
        sys.exit(1)

    config = CaptureConfig(
        interface=interface,
        filter=filter,
        buffer_size=10000,
    )

    decoder = PacketDecoder()
    predicate = None
    if filter_expr:
        from utils.filtering import compile_packet_filter
        predicate = compile_packet_filter(filter_expr)
    packet_id = 0

    try:
        session_id = capture_backend.start(config)
        click.echo(f"Capture started on '{interface}' (session: {session_id})")
        if filter:
            click.echo(f"Filter: {filter}")
        if duration:
            click.echo(f"Duration: {duration} seconds")
        click.echo("Press Ctrl+C to stop\n")

        if format == "table":
            click.echo("ID  Time(us)       Stack        Src -> Dst                    Ports      L4     Flags   Quality")
            click.echo("-" * 100)

        start_time = time.time()
        decoded_count = 0

        records = [] if format == "json" else None
        file_handle = None
        if format == "jsonl" and output:
            file_handle = open(output, "w", encoding="utf-8")
        wrote_output = False

        while True:
            if duration and (time.time() - start_time) >= duration:
                break

            packets = capture_backend.get_packets(session_id, count=100)
            if not packets:
                time.sleep(0.01)
                continue

            for pkt in packets:
                packet_id += 1
                raw = RawPacket(
                    packet_id=packet_id,
                    timestamp_us=int(pkt["ts"] * 1_000_000),
                    captured_length=len(pkt["data"]),
                    original_length=pkt.get("wirelen", len(pkt["data"])),
                    link_type=1,  # DLT_EN10MB
                    data=pkt["data"],
                    pcap_ref="live:0:0",
                )
                decoded = decoder.decode(raw)
                record = decoded.to_dict()
                if predicate and not predicate(record):
                    continue

                if format == "table":
                    src = decoded.src_ip or "-"
                    dst = decoded.dst_ip or "-"
                    ports = "-" if decoded.src_port is None or decoded.dst_port is None else f"{decoded.src_port}->{decoded.dst_port}"
                    l4 = decoded.l4_protocol or "-"
                    flags = ",".join(decoded.tcp_flag_names) if decoded.tcp_flag_names else "-"
                    quality = ",".join(quality_flag_names(decoded.quality_flags)) if show_quality else "-"
                    stack = decoded.stack_summary

                    click.echo(
                        f"{raw.packet_id:<3} {raw.timestamp_us:<13} "
                        f"{stack:<12} {src:<22} {dst:<22} {ports:<10} {l4:<6} {flags:<7} {quality}"
                    )
                elif format == "json":
                    records.append(record)
                else:
                    line = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
                    if file_handle:
                        file_handle.write(line + "\n")
                    else:
                        click.echo(line)

                decoded_count += 1
                if limit > 0 and decoded_count >= limit:
                    if format == "json":
                        payload = json.dumps(records, separators=(",", ":"), ensure_ascii=True)
                        if output:
                            with open(output, "w", encoding="utf-8") as f:
                                f.write(payload)
                        else:
                            click.echo(payload)
                        wrote_output = True
                    if file_handle:
                        file_handle.close()
                    return

    except KeyboardInterrupt:
        click.echo("\nStopping capture...")
    finally:
        try:
            capture_backend.stop(session_id)
        except Exception:
            pass
        if format == "json" and not wrote_output:
            payload = json.dumps(records or [], separators=(",", ":"), ensure_ascii=True)
            if output:
                with open(output, "w", encoding="utf-8") as f:
                    f.write(payload)
            else:
                click.echo(payload)
        if file_handle:
            file_handle.close()
