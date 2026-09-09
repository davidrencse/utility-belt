"""Zero-width Unicode carrier."""

from __future__ import annotations

from .core import HEADER, bits_to_bytes, bytes_to_bits, frame_length_from_prefix, pack, unpack
from .errors import CapacityError, DecodeError

ZERO = "\u200b"
ONE = "\u200c"
SEPARATOR = "\u200d"
ALPHABET = {ZERO, ONE, SEPARATOR}


def capacity(cover: str) -> int:
    visible = sum(ch not in ALPHABET for ch in cover)
    return max(0, (visible - 1) // 8 - HEADER.size)


def encode(cover: str, data: bytes, password: str | None = None) -> str:
    visible = "".join(ch for ch in cover if ch not in ALPHABET)
    bits = bytes_to_bits(pack(data, password))
    if len(visible) < len(bits) + 1:
        raise CapacityError(
            f"cover needs at least {len(bits) + 1} visible characters; got {len(visible)}"
        )
    out = [visible[0]]
    for index, ch in enumerate(visible[1:]):
        if index < len(bits):
            out.append(ONE if bits[index] else ZERO)
        elif index == len(bits):
            out.append(SEPARATOR)
        out.append(ch)
    return "".join(out)


def decode(stego: str, password: str | None = None) -> bytes:
    bits = [0 if ch == ZERO else 1 for ch in stego if ch in {ZERO, ONE}]
    if len(bits) < HEADER.size * 8:
        raise DecodeError("text contains no complete StegKit zero-width header")
    prefix = bits_to_bytes(bits[: HEADER.size * 8])
    total = frame_length_from_prefix(prefix)
    if len(bits) < total * 8:
        raise DecodeError("zero-width payload is truncated")
    return unpack(bits_to_bytes(bits[: total * 8]), password)


def strip(text: str) -> str:
    return "".join(ch for ch in text if ch not in ALPHABET)

