#!/usr/bin/env python3
"""Benchmark the working tree against a git ref ("is it faster than last time?").

    python benchmarks/compare.py                  # vs HEAD
    python benchmarks/compare.py --base main~3 --packets 20000

Checks out <base> into a temporary git worktree, runs the Asphalt pipeline and
StegKit benchmarks against both trees on identical synthetic inputs, and prints
old/new timings plus whether the outputs are identical. Needs the packages'
dependencies (scapy, numpy, Pillow, soundfile, cryptography, pypdf, click).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PY = sys.executable
# The layout changed over time; the first path that exists in a tree wins.
LAYOUT = {
    "asphalt": ["packages/asphalt", "Asphalt"],
    "stegkit": ["packages/stegkit", "Steganography-Multi-Tool"],
}


def locate(tree: Path, name: str) -> Path:
    for rel in LAYOUT[name]:
        if (tree / rel).is_dir():
            return tree / rel
    raise SystemExit(f"{name} not found in {tree}")


def bench(script: str, *args) -> dict:
    env = {**os.environ, "PYTHONWARNINGS": "ignore"}
    out = subprocess.run([PY, str(HERE / script), *map(str, args)], env=env,
                         capture_output=True, text=True)
    if out.returncode:
        last = (out.stderr or out.stdout).strip().splitlines()[-1]
        return {"error": last.split(":")[0].rsplit(".", 1)[-1][:11]}   # e.g. PcapEOFErro
    return json.loads(out.stdout.strip().splitlines()[-1])


def speedup(old, new):
    if not isinstance(old, (int, float)) or not isinstance(new, (int, float)) or not new:
        return ""
    return f"{old / new:5.1f}x"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="HEAD", help="git ref to compare against (default HEAD)")
    ap.add_argument("--packets", type=int, default=10000, help="synthetic capture size")
    ap.add_argument("--iters", type=int, default=3, help="best-of-N iterations")
    opts = ap.parse_args()

    work = Path(tempfile.mkdtemp(prefix="ub-bench-"))
    base = work / "base"
    subprocess.run(["git", "worktree", "add", "--detach", "-f", str(base), opts.base],
                   cwd=ROOT, check=True, capture_output=True)
    try:
        caps = work / "caps"
        caps.mkdir()
        subprocess.run([PY, str(HERE / "gen_pcaps.py"), str(opts.packets), str(caps)],
                       check=True, env={**os.environ, "PYTHONWARNINGS": "ignore"})
        os.environ["ITERS"] = str(opts.iters)

        rows = []
        for cap in ("aligned.pcap", "aligned.pcapng", "unaligned.pcap"):
            r = {}
            for label, tree in (("old", base), ("new", ROOT)):
                r[label] = bench("bench_asphalt.py", locate(tree, "asphalt"), caps / cap,
                                 work / f"{label}-{cap}.json")
            same = r["old"].get("report_sha") == r["new"].get("report_sha")
            rows.append((f"asphalt {cap}", r["old"].get("pipeline_s", r["old"].get("error")),
                         r["new"].get("pipeline_s", r["new"].get("error")), same))
            if cap == "aligned.pcap":
                rows.append(("asphalt import", r["old"].get("import_s"), r["new"].get("import_s"), None))

        steg = {label: bench("bench_steg.py", locate(tree, "stegkit"), work / f"steg-{label}")
                for label, tree in (("old", base), ("new", ROOT))}
        for key in steg["new"]:
            if key.endswith("_ms"):
                kind = key.split("_")[0]
                same = steg["old"].get(f"{kind}_hash") == steg["new"].get(f"{kind}_hash")
                rows.append((f"stegkit {key[:-3]}", steg["old"].get(key), steg["new"].get(key), same))
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", str(base)], cwd=ROOT, capture_output=True)
        shutil.rmtree(work, ignore_errors=True)

    print(f"\n{'benchmark':<28}{'old':>12}{'new':>12}{'speedup':>9}  same output")
    for name, old, new, same in rows:
        flag = "" if same is None else ("yes" if same else "NO")
        print(f"{name:<28}{str(old):>12}{str(new):>12}{speedup(old, new):>9}  {flag}")
    print("\nasphalt times in s, stegkit in ms. 'NO' on unaligned.pcap vs a pre-fix base"
          " is expected: the old reader mis-parsed unpadded records.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
