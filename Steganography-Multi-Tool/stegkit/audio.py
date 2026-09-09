"""WAV/FLAC sample LSB carrier using libsndfile via soundfile."""

from __future__ import annotations

from pathlib import Path

import numpy as np

from .core import HEADER, bits_to_bytes, bytes_to_bits, frame_length_from_prefix, pack, unpack
from .errors import CapacityError, DecodeError, StegKitError


def _sf():
    try:
        import soundfile as sf
    except ImportError as exc:
        raise StegKitError("audio support requires: pip install soundfile numpy") from exc
    return sf


def capacity(path) -> int:
    info = _sf().info(str(path))
    return max(0, info.frames * info.channels // 8 - HEADER.size)


def encode(source, output, data: bytes, password: str | None = None) -> None:
    sf = _sf()
    samples, rate = sf.read(str(source), dtype="int32", always_2d=True)
    subtype = sf.info(str(source)).subtype
    if subtype not in {"PCM_16", "PCM_24", "PCM_32"}:
        raise StegKitError("audio carrier must use 16-, 24-, or 32-bit integer PCM")
    # libsndfile presents all integer samples as left-aligned int32 values.
    shift = {"PCM_16": 16, "PCM_24": 8, "PCM_32": 0}[subtype]
    mask = np.int32(1 << shift)
    flat = samples.reshape(-1)
    bits = np.asarray(bytes_to_bits(pack(data, password)), dtype=np.int32)
    if bits.size > flat.size:
        raise CapacityError(
            f"payload needs {bits.size} samples; carrier has {flat.size}"
        )
    flat[: bits.size] = (flat[: bits.size] & ~mask) | (bits << shift)
    suffix = Path(output).suffix.lower()
    if suffix not in {".wav", ".flac"}:
        raise StegKitError("audio output must be WAV or FLAC")
    sf.write(str(output), samples, rate, subtype=subtype, format=suffix[1:].upper())


def decode(path, password: str | None = None) -> bytes:
    sf = _sf()
    info = sf.info(str(path))
    if info.subtype not in {"PCM_16", "PCM_24", "PCM_32"}:
        raise StegKitError("audio carrier must use 16-, 24-, or 32-bit integer PCM")
    shift = {"PCM_16": 16, "PCM_24": 8, "PCM_32": 0}[info.subtype]
    samples, _ = sf.read(str(path), dtype="int32", always_2d=True)
    flat = samples.reshape(-1)
    head = HEADER.size * 8
    if flat.size < head:
        raise DecodeError("audio file is too short")
    prefix = bits_to_bytes((flat[:head] >> shift) & 1)
    total = frame_length_from_prefix(prefix)
    if total * 8 > flat.size:
        raise DecodeError("declared payload exceeds audio capacity")
    return unpack(bits_to_bytes((flat[: total * 8] >> shift) & 1), password)
