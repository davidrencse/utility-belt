"""Authenticated payload framing shared by every carrier."""

from __future__ import annotations

import os
import struct
import zlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import DecodeError

MAGIC = b"STGK"
VERSION = 1
HEADER = struct.Struct(">4sBI")
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_N = 2**14


@dataclass(frozen=True)
class FrameInfo:
    encrypted: bool
    payload_bytes: int
    framed_bytes: int


def _key(password: str, salt: bytes) -> bytes:
    if not password:
        raise DecodeError("an encryption key/passphrase is required")
    return Scrypt(salt=salt, length=32, n=KDF_N, r=8, p=1).derive(
        password.encode("utf-8")
    )


def pack(data: bytes, password: str | None = None) -> bytes:
    """Compress, optionally AES-256-GCM encrypt, and length-prefix bytes."""
    compressed = zlib.compress(data, level=9)
    flags = 1 if password else 0
    if password:
        salt, nonce = os.urandom(SALT_SIZE), os.urandom(NONCE_SIZE)
        body = salt + nonce + AESGCM(_key(password, salt)).encrypt(
            nonce, compressed, MAGIC + bytes([VERSION, flags])
        )
    else:
        body = compressed
    return HEADER.pack(MAGIC, (VERSION << 4) | flags, len(body)) + body


def unpack(frame: bytes, password: str | None = None) -> bytes:
    if len(frame) < HEADER.size:
        raise DecodeError("payload header is missing or truncated")
    magic, version_flags, size = HEADER.unpack_from(frame)
    version, flags = version_flags >> 4, version_flags & 0x0F
    if magic != MAGIC or version != VERSION:
        raise DecodeError("no supported StegKit payload found")
    body = frame[HEADER.size : HEADER.size + size]
    if len(body) != size:
        raise DecodeError("payload is truncated")
    if flags & 1:
        if len(body) < SALT_SIZE + NONCE_SIZE + 16:
            raise DecodeError("encrypted payload is truncated")
        salt = body[:SALT_SIZE]
        nonce = body[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
        ciphertext = body[SALT_SIZE + NONCE_SIZE :]
        try:
            body = AESGCM(_key(password or "", salt)).decrypt(
                nonce, ciphertext, MAGIC + bytes([VERSION, flags])
            )
        except (InvalidTag, ValueError) as exc:
            raise DecodeError("wrong key or damaged payload") from exc
    try:
        return zlib.decompress(body)
    except zlib.error as exc:
        raise DecodeError("payload checksum/decompression failed") from exc


def frame_size(data: bytes, encrypted: bool = True) -> int:
    overhead = SALT_SIZE + NONCE_SIZE + 16 if encrypted else 0
    return HEADER.size + len(zlib.compress(data, 9)) + overhead


def frame_length_from_prefix(prefix: bytes) -> int:
    if len(prefix) < HEADER.size:
        raise DecodeError("payload header is missing")
    magic, version_flags, size = HEADER.unpack(prefix[: HEADER.size])
    if magic != MAGIC or version_flags >> 4 != VERSION:
        raise DecodeError("no supported StegKit payload found")
    return HEADER.size + size


def bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def bits_to_bytes(bits) -> bytes:
    values = list(bits)
    return bytes(
        sum(values[i + bit] << (7 - bit) for bit in range(8))
        for i in range(0, len(values) - 7, 8)
    )

