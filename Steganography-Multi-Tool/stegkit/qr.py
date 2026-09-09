"""QR steganography using controlled module damage within level-H redundancy.

Extraction first decodes the public text, regenerates its pristine symbol, then
interprets selected module differences. Consequently the public QR payload is
the reference carrier and remains fully standards-compatible.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from .core import HEADER, bits_to_bytes, bytes_to_bits, frame_length_from_prefix, pack, unpack
from .errors import CapacityError, DecodeError, StegKitError


def _deps():
    try:
        import cv2
        import qrcode
    except ImportError as exc:
        raise StegKitError(
            "QR support requires: pip install qrcode[pil] opencv-python-headless"
        ) from exc
    return cv2, qrcode


def _matrix(public: str, version: int | None = None):
    _, qrcode = _deps()
    qr = qrcode.QRCode(
        version=version,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(public)
    qr.make(fit=version is None)
    return np.asarray(qr.get_matrix(), dtype=np.uint8), qr.version


def _positions(size: int):
    # Exclude quiet zone (4), finders/separators, timing and format strips.
    _, qrcode = _deps()
    core = size - 8
    version = (core - 17) // 4
    alignment = qrcode.util.pattern_position(version)

    def is_function(row, col):
        finder = (
            (row < 9 and col < 9)
            or (row < 9 and col >= core - 8)
            or (row >= core - 8 and col < 9)
        )
        if finder or row == 6 or col == 6 or row == 8 or col == 8:
            return True
        # Alignment patterns are 5x5; corner overlaps are already finder areas.
        if any(abs(row - ar) <= 2 and abs(col - ac) <= 2
               for ar in alignment for ac in alignment):
            return True
        if version >= 7 and (
            (row < 6 and core - 11 <= col <= core - 9)
            or (col < 6 and core - 11 <= row <= core - 9)
        ):
            return True
        return False

    positions = []
    for row in range(4, size - 4):
        for col in range(4, size - 4):
            local_r, local_c = row - 4, col - 4
            if is_function(local_r, local_c):
                continue
            positions.append((row, col))
    yield from positions


def capacity(public: str, version: int | None = None) -> int:
    matrix, _ = _matrix(public, version)
    # Constrain deliberate damage to 10% of non-function candidates.
    return max(0, int(sum(1 for _ in _positions(len(matrix))) * 0.10) // 8 - HEADER.size)


def encode(public: str, output, data: bytes, password=None, version=None) -> None:
    cv2, _ = _deps()
    frame = pack(data, password)
    bits = bytes_to_bits(frame)
    matrix, version = _matrix(public, version)
    candidates = list(_positions(len(matrix)))
    allowed = int(len(candidates) * 0.10)
    if len(bits) > allowed:
        raise CapacityError(
            f"QR payload needs {len(bits)} modules; conservative level-H budget is {allowed}. "
            "Use a larger --qr-version or shorter payload."
        )
    damaged = matrix.copy()
    for bit, (row, col) in zip(bits, candidates):
        if bit:
            damaged[row, col] ^= 1
    image = np.where(damaged, 0, 255).astype(np.uint8)
    image = cv2.resize(image, None, fx=10, fy=10, interpolation=cv2.INTER_NEAREST)
    cv2.imwrite(str(output), image)
    decoded, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
    if decoded != public:
        Path(output).unlink(missing_ok=True)
        raise StegKitError(
            "QR validation failed: payload damage exceeded this symbol's practical correction "
            "margin; use a larger version or shorter secret"
        )


def decode(path, password=None) -> tuple[str, bytes]:
    cv2, _ = _deps()
    image = cv2.imread(str(path), cv2.IMREAD_GRAYSCALE)
    public, points, straight = cv2.QRCodeDetector().detectAndDecode(image)
    if not public:
        raise DecodeError("QR code does not scan")
    # OpenCV's straightened QR is one pixel per module, so it reveals version.
    straight_size = int(straight.shape[0])
    inferred_version = (straight_size - 17) // 4
    if inferred_version not in range(1, 41):
        raise DecodeError("could not infer QR version")
    reference, version = _matrix(public, inferred_version)
    size = len(reference)
    # Sample directly from detected straight symbol, normalized to module count.
    normalized = cv2.resize(straight, (size - 8, size - 8), interpolation=cv2.INTER_AREA)
    observed_core = normalized < 128
    observed = reference.copy()
    observed[4:-4, 4:-4] = observed_core
    bits = [int(observed[r, c] != reference[r, c]) for r, c in _positions(size)]
    if len(bits) < HEADER.size * 8:
        raise DecodeError("QR has insufficient carrier modules")
    total = frame_length_from_prefix(bits_to_bytes(bits[: HEADER.size * 8]))
    if total * 8 > len(bits):
        raise DecodeError("QR hidden payload is truncated")
    return public, unpack(bits_to_bytes(bits[: total * 8]), password)
