"""Run the full Asphalt analyze pipeline (read -> decode -> all analyzers) for one tree.

usage: bench_asphalt.py <asphalt_root> <capture> <report_out> [--filter EXPR]
Prints best-of-N (ITERS env, default 3) wall time, import time, and a hash of the
report with its timestamp removed, so two trees can be checked for identical output.
"""
import hashlib
import json
import os
import sys
import time

t_imp = time.perf_counter()
root = sys.argv[1]
sys.path.insert(0, os.path.join(root, "src"))
from analysis.engine import AnalysisEngine  # noqa: E402
from analysis.registry import create_analyzer, list_analyzers  # noqa: E402
from capture.decoder import PacketDecoder  # noqa: E402
from pcap_loader.pcap_reader import PcapReader  # noqa: E402
from pcap_loader.pcapng_reader import PcapngReader  # noqa: E402
import_s = time.perf_counter() - t_imp

cap, out = sys.argv[2], sys.argv[3]
flt = sys.argv[5] if len(sys.argv) > 5 and sys.argv[4] == "--filter" else None
reader_cls = PcapngReader if cap.endswith(".pcapng") else PcapReader


def run():
    predicate = None
    if flt:
        from utils.filtering import compile_packet_filter
        predicate = compile_packet_filter(flt)
    engine = AnalysisEngine([create_analyzer(n) for n in list_analyzers()], capture_path=cap)
    dec = PacketDecoder()
    with reader_cls(cap) as reader:
        for p in reader:
            d = dec.decode(p)
            if predicate and not predicate(d.to_dict()):
                continue
            engine.process_packet(d)
    return engine.finalize()


best = 1e9
for _ in range(int(os.environ.get("ITERS", "3"))):
    t = time.perf_counter()
    report = run()
    best = min(best, time.perf_counter() - t)
payload = report.to_json()
with open(out, "w", encoding="utf-8") as f:
    f.write(payload)
body = json.loads(payload)
body.pop("created_at", None)
body.pop("capture_path", None)
print(json.dumps({"pipeline_s": round(best, 3), "import_s": round(import_s, 3),
                  "packets": body.get("stats", {}).get("packets_total"),
                  "report_sha": hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]}))
