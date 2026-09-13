"""CLI command for packet analysis."""
import click
from typing import Optional

from capture.decoder import PacketDecoder
from pcap_loader.pcap_reader import PcapReader
from pcap_loader.pcapng_reader import PcapngReader
from analysis.engine import AnalysisEngine
from analysis.registry import create_analyzer, list_analyzers

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


def _parse_analyzers(value: str):
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


@click.command()
@click.argument("filepath", type=click.Path(exists=True, dir_okay=False))
@click.option("--limit", "limit", type=int, default=0, show_default=True,
              help="Max packets to analyze (0 = no limit)")
@click.option(
    "--analyzers",
    "analyzers",
    default="capture_health,global_stats,protocol_mix,flow_summary,flow_analytics,tcp_handshakes,tcp_reliability,tcp_performance,abnormal_activity,scan_signals,arp_lan_signals,dns_anomalies,packet_chunks,time_series,throughput_peaks,packet_size_stats,l2_l3_breakdown,top_entities",
    show_default=True,
    help="Comma-separated analyzer list",
)
@click.option("--bucket-ms", "bucket_ms", type=int, default=1000, show_default=True,
              help="Time-series bucket size in milliseconds")
@click.option("--chunk-size", "chunk_size", type=int, default=200, show_default=True,
              help="Packet chunk size for packet_chunks analyzer")
@click.option("--scan-port-threshold", "scan_port_threshold", type=int, default=20, show_default=True,
              help="Unique dst port threshold for port scan detection")
@click.option("--rst-ratio-threshold", "rst_ratio_threshold", type=float, default=0.2, show_default=True,
              help="TCP RST ratio threshold for abnormal detection")
@click.option("--format", "format", type=click.Choice(["json"]), default="json", show_default=True)
@click.option("--output", "output", type=click.Path(dir_okay=False),
              help="Write JSON output to file")
@click.option("--filter", "filter_expr", help="Filter expression for decoded packets")
def analyze(filepath: str,
            limit: int,
            analyzers: str,
            bucket_ms: int,
            chunk_size: int,
            scan_port_threshold: int,
            rst_ratio_threshold: float,
            format: str,
            output: Optional[str],
            filter_expr: Optional[str]):
    """
    Analyze packets from a PCAP/PCAPNG file.

    Example:
      asphalt analyze capture.pcapng --analyzers global_stats,flow_summary --output report.json
    """
    analyzer_names = _parse_analyzers(analyzers)
    if not analyzer_names:
        raise click.ClickException("No analyzers specified")

    available = set(list_analyzers())
    for name in analyzer_names:
        if name not in available:
            options = ", ".join(sorted(available))
            raise click.ClickException(f"Unknown analyzer '{name}'. Available: {options}")

    instances = []
    for name in analyzer_names:
        if name == "time_series":
            instances.append(create_analyzer(name, bucket_ms=bucket_ms))
        elif name == "packet_chunks":
            instances.append(create_analyzer(name, chunk_size=chunk_size))
        elif name == "abnormal_activity":
            instances.append(create_analyzer(
                name,
                scan_port_threshold=scan_port_threshold,
                rst_ratio_threshold=rst_ratio_threshold,
            ))
        else:
            instances.append(create_analyzer(name))

    reader_cls = _select_reader(filepath)
    decoder = PacketDecoder()
    capture_info = {}
    predicate = None
    if filter_expr:
        from utils.filtering import compile_packet_filter
        predicate = compile_packet_filter(filter_expr)

    try:
        with reader_cls(filepath) as reader:
            try:
                capture_info = reader.get_session_info()
            except Exception:
                capture_info = {}
            engine = AnalysisEngine(instances, capture_path=filepath, capture_info=capture_info)
            for packet in reader:
                decoded = decoder.decode(packet)
                record = decoded.to_dict()
                if predicate and not predicate(record):
                    continue
                engine.process_packet(decoded)
                if limit > 0 and engine.context.stats["packets_total"] >= limit:
                    break
    except Exception as e:
        raise click.ClickException(str(e))

    report = engine.finalize()
    payload = report.to_json()
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(payload)
    else:
        click.echo(payload)
