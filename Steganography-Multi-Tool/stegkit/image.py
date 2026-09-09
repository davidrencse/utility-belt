"""PNG/BMP RGB-channel least-significant-bit carrier."""

from __future__ import annotations

from pathlib import Path

import numpy as np
from PIL import Image

from .core import HEADER, bits_to_bytes, bytes_to_bits, frame_length_from_prefix, pack, unpack
from .errors import CapacityError, DecodeError, StegKitError


def capacity(path: str | Path) -> int:
    with Image.open(path) as image:
        channels = 4 if image.mode == "CMYK" else min(len(image.getbands()), 3)
        return image.width * image.height * channels // 8 - HEADER.size


def encode(source, output, data: bytes, password: str | None = None) -> None:
    source, output = Path(source), Path(output)
    if output.suffix.lower() not in {".png", ".bmp"}:
        raise StegKitError("image output must be PNG or BMP (lossless)")
    with Image.open(source) as opened:
        image = opened.convert("RGB")
    pixels = np.array(image, dtype=np.uint8)
    flat = pixels.reshape(-1)
    frame = pack(data, password)
    bits = np.asarray(bytes_to_bits(frame), dtype=np.uint8)
    if bits.size > flat.size:
        raise CapacityError(
            f"payload needs {bits.size // 8} bytes; image holds {flat.size // 8}"
        )
    flat[: bits.size] = (flat[: bits.size] & 0xFE) | bits
    Image.fromarray(pixels, "RGB").save(output)


def decode(path, password: str | None = None) -> bytes:
    with Image.open(path) as opened:
        pixels = np.array(opened.convert("RGB"), dtype=np.uint8).reshape(-1)
    header_bits = HEADER.size * 8
    if pixels.size < header_bits:
        raise DecodeError("image is too small to contain a payload")
    prefix = bits_to_bytes(pixels[:header_bits] & 1)
    total = frame_length_from_prefix(prefix)
    if total * 8 > pixels.size:
        raise DecodeError("declared payload exceeds image capacity")
    return unpack(bits_to_bytes(pixels[: total * 8] & 1), password)

