#!/usr/bin/env python3
"""Run every project's verification pipeline. CI calls this too, so a green run
here means a green run there.

    python scripts/check.py                 # everything
    python scripts/check.py asphalt stegkit # just these
    python scripts/check.py --build         # also run the osint production build
    python scripts/check.py --list

Exit code is non-zero if any selected pipeline fails. Pipelines whose toolchain
is missing (no node_modules, no ruff) are reported as SKIP, not FAIL.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
PACKAGES = ROOT / "packages"
APPS = ROOT / "apps"
IS_WINDOWS = os.name == "nt"


class Skip(Exception):
    pass


def run(cmd, cwd=ROOT, env=None):
    print(f"  $ {' '.join(str(c) for c in cmd)}", flush=True)
    merged = {**os.environ, **(env or {})}
    result = subprocess.run([str(c) for c in cmd], cwd=cwd, env=merged)
    if result.returncode:
        raise RuntimeError(f"exit {result.returncode}")


def npx(*args):
    return ["npx.cmd" if IS_WINDOWS else "npx", *args]


# --- pipelines ---------------------------------------------------------------

def asphalt(_):
    run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd=PACKAGES / "asphalt")


def stegkit(_):
    run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd=PACKAGES / "stegkit")


def port_scanner(_):
    pkg = PACKAGES / "port-scanner"
    run([PY, "-m", "compileall", "-q", "."], cwd=pkg)
    run([PY, "port_scanner.py", "--help"], cwd=pkg)
    run([PY, "-c", "import system_info as s; assert s.memory()[0]; print('system_info ok')"], cwd=pkg)


def overlay(_):
    app = APPS / "overlay"
    run([PY, "-m", "compileall", "-q", "overlay", "main.py"], cwd=app)
    # The overlay imports the packages/ engines by path; this catches a layout
    # change that breaks those paths without needing Qt or a display.
    run([PY, "-c", (
        "import os, sys; sys.path.insert(0, 'overlay/core'); import bridge as b;"
        "assert b.ENGINE_OK, b.ENGINE_ERROR;"
        "assert os.path.isdir(b.STEGO_DIR), b.STEGO_DIR;"
        "assert os.path.isdir(b.SNIFF_DIR), b.SNIFF_DIR;"
        "print('engine paths ok')"
    )], cwd=app)


def osint(opts):
    app = APPS / "osint"
    if not (app / "node_modules").is_dir():
        raise Skip("node_modules missing - run `npm ci` in apps/osint")
    run(npx("tsc", "--noEmit", "-p", "."), cwd=app)
    run(npx("eslint", "src"), cwd=app)
    if opts.build:
        run(npx("next", "build"), cwd=app)


def lint(_):
    ruff = shutil.which("ruff")
    if not ruff:
        raise Skip("ruff not installed - `pip install ruff`")
    # Real bugs only (syntax errors, undefined names); style is left to each project.
    run([ruff, "check", "--no-cache", "--select", "E9,F63,F7,F82", "apps/overlay", "packages"])


PIPELINES = {
    "asphalt": asphalt,
    "stegkit": stegkit,
    "port-scanner": port_scanner,
    "overlay": overlay,
    "osint": osint,
    "lint": lint,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("only", nargs="*", metavar="PIPELINE",
                    help=f"subset to run: {', '.join(PIPELINES)}")
    ap.add_argument("--build", action="store_true", help="include the osint production build")
    ap.add_argument("--list", action="store_true", help="list pipelines and exit")
    opts = ap.parse_args()
    unknown = [n for n in opts.only if n not in PIPELINES]
    if unknown:
        ap.error(f"unknown pipeline(s): {', '.join(unknown)}")
    if opts.list:
        print("\n".join(PIPELINES))
        return 0

    results = []
    for name in opts.only or PIPELINES:
        print(f"\n== {name}", flush=True)
        start = time.perf_counter()
        try:
            PIPELINES[name](opts)
            status, note = "PASS", ""
        except Skip as exc:
            status, note = "SKIP", str(exc)
        except Exception as exc:  # noqa: BLE001 - report and keep going
            status, note = "FAIL", str(exc)
        results.append((name, status, time.perf_counter() - start, note))

    print("\n" + "-" * 60)
    for name, status, secs, note in results:
        print(f"{status:<5} {name:<13} {secs:6.1f}s  {note}")
    return 1 if any(s == "FAIL" for _, s, _, _ in results) else 0


if __name__ == "__main__":
    sys.exit(main())
