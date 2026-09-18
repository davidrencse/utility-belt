"""Git history carriers: trailing whitespace and timestamp parity."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .core import HEADER, bits_to_bytes, bytes_to_bits, frame_length_from_prefix, pack, unpack
from .errors import CapacityError, DecodeError, StegKitError

MARKER = "[stegkit]"


def _git(repo, *args, env=None, check=True, input_text=None):
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        env=env,
        input=input_text,
        check=False,
    )
    if check and result.returncode:
        raise StegKitError(result.stderr.strip() or "git command failed")
    return result.stdout


def encode_whitespace(repo, data: bytes, password=None, message="maintenance") -> str:
    frame = pack(data, password)
    whitespace = "".join(" " if bit == 0 else "\t" for bit in bytes_to_bits(frame))
    body = f"{message}\n\n{MARKER}{whitespace}"
    _git(repo, "commit", "--allow-empty", "--cleanup=verbatim", "--file=-", input_text=body)
    return _git(repo, "rev-parse", "HEAD").strip()


def decode_whitespace(repo, password=None, revision="HEAD") -> bytes:
    body = _git(repo, "show", "-s", "--format=%B", revision)
    line = next((line for line in body.splitlines() if line.startswith(MARKER)), None)
    if line is None:
        raise DecodeError("commit has no StegKit whitespace payload")
    bits = [0 if ch == " " else 1 for ch in line[len(MARKER):] if ch in " \t"]
    return unpack(bits_to_bytes(bits), password)


def encode_timestamps(repo, data: bytes, password=None, message="maintenance") -> list[str]:
    """Create one empty commit per bit; author/committer second parity carries it."""
    bits = bytes_to_bits(pack(data, password))
    if len(bits) > 4096:
        raise CapacityError("timestamp mode is limited to 4096 commits")
    base = int(_git(repo, "show", "-s", "--format=%ct", "HEAD").strip())
    hashes = []
    for index, bit in enumerate(bits):
        stamp = base + index * 2
        stamp += (bit - stamp) & 1
        env = dict(os.environ)
        env["GIT_AUTHOR_DATE"] = f"@{stamp} +0000"
        env["GIT_COMMITTER_DATE"] = f"@{stamp} +0000"
        _git(repo, "commit", "--allow-empty", "-m", f"{message} {index + 1}/{len(bits)}", env=env)
        hashes.append(_git(repo, "rev-parse", "HEAD").strip())
    return hashes


def decode_timestamps(repo, password=None, count=None) -> bytes:
    timestamps = [
        int(value) for value in _git(repo, "log", "--reverse", "--format=%at").splitlines()
    ]
    if count:
        timestamps = timestamps[-count:]
    bits = [value & 1 for value in timestamps]
    if len(bits) < HEADER.size * 8:
        raise DecodeError("not enough commits for a payload header")
    total = frame_length_from_prefix(bits_to_bytes(bits[: HEADER.size * 8]))
    if len(bits) < total * 8:
        raise DecodeError(f"timestamp payload needs {total * 8} commits")
    return unpack(bits_to_bytes(bits[: total * 8]), password)
