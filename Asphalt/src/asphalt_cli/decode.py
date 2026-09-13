"""
CLI command for packet decoding.
"""
import click
import json
import sys
from typing import Optional

from capture.decoder import PacketDecoder
from capture.packet_decoder import quality_flag_names
from pcap_loader.pcap_reader import PcapReader
from pcap_loader.pcapng_reader import PcapngReader

_PCAP_MAGIC = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def _select_reader(filepath: str):
    lower = filepath.lower()
    if lower.endswith(".pcapng"):
        return PcapngReader
    if lower.endswith(".pcap"):
        return PcapReader

    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
    except OSError as e:
        raise click.ClickException(f"Failed to open file: {e}")

    if magic == _PCAPNG_MAGIC:
        return PcapngReader
    if magic in _PCAP_MAGIC:
        return PcapReader

    raise click.ClickException("Unsupported capture file format")


def _format_ports(decoded) -> str:
    if decoded.src_port is None or decoded.dst_port is None:
        return "-"
    return f"{decoded.src_port}->{decoded.dst_port}"


@click.command()
@click.argument("filepath", type=click.Path(exists=True, dir_okay=False))
@click.option("--limit", "limit", type=int, default=50, show_default=True,
              help="Max packets to decode (0 = no limit)")
@click.option("--show-quality", is_flag=True, help="Show decode quality flags")
@click.option("--format", "format", type=click.Choice(["table", "json", "jsonl"]),
              default="table", show_default=True, help="Output format")
@click.option("--output", "output", type=click.Path(dir_okay=False),
              help="Write JSON/JSONL output to file")
@click.option("--filter", "filter_expr", help="Filter expression for decoded packets")
def decode(filepath: str, limit: int, show_quality: bool, format: str, output: Optional[str], filter_expr: Optional[str]):
    """
    Decode packets from a PCAP/PCAPNG file.

    Example:
      asphalt decode capture.pcapng --limit 20
    """
    reader_cls = _select_reader(filepath)
    decoder = PacketDecoder()
    predicate = None
    if filter_expr:
        from utils.filtering import compile_packet_filter
        predicate = compile_packet_filter(filter_expr)

    try:
        with reader_cls(filepath) as reader:
            count = 0
            records = [] if format == "json" else None

            file_handle = None
            if format == "jsonl" and output:
                file_handle = open(output, "w", encoding="utf-8")

            if format == "table":
                click.echo("ID  Time(us)       Stack        Src -> Dst                    Ports      L4     Flags   Quality")
                click.echo("-" * 100)

            for packet in reader:
                decoded = decoder.decode(packet)
                record = decoded.to_dict()
                if predicate and not predicate(record):
                    continue

                if format == "table":
                    src = decoded.src_ip or "-"
                    dst = decoded.dst_ip or "-"
                    ports = _format_ports(decoded)
                    l4 = decoded.l4_protocol or "-"
                    flags = ",".join(decoded.tcp_flag_names) if decoded.tcp_flag_names else "-"
                    quality = ",".join(quality_flag_names(decoded.quality_flags)) if show_quality else "-"
                    stack = decoded.stack_summary

                    click.echo(
                        f"{packet.packet_id:<3} {packet.timestamp_us:<13} "
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

                count += 1
                if limit > 0 and count >= limit:
                    break

            if format == "json":
                payload = json.dumps(records, separators=(",", ":"), ensure_ascii=True)
                if output:
                    with open(output, "w", encoding="utf-8") as f:
                        f.write(payload)
                else:
                    click.echo(payload)
            if file_handle:
                file_handle.close()
    except Exception as e:
        raise click.ClickException(str(e))
