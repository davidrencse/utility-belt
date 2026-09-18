# Benchmarks

Performance regression checks for the CPU-bound pipelines. Everything runs on
synthetic inputs generated on the fly, so nothing large is committed.

| Script | Measures |
|---|---|
| `compare.py` | **Entry point.** Working tree vs a git ref, same inputs, reports speedup and whether outputs are identical |
| `gen_pcaps.py` | Writes synthetic mixed-traffic captures (`aligned`/`unaligned` × `.pcap`/`.pcapng`) |
| `bench_asphalt.py` | Asphalt read → decode → all analyzers, best-of-N, plus a hash of the report |
| `bench_steg.py` | StegKit image / audio / text / PDF encode + decode, plus output hashes |

```bash
python benchmarks/compare.py                   # vs HEAD
python benchmarks/compare.py --base main~5 --packets 20000
```

Run it before merging anything that touches a hot path. A speedup with
`same output = NO` is a regression, not a win.

The benches need the packages' runtime dependencies:

```bash
pip install -r requirements-dev.txt
```
