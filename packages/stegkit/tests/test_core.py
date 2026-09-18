import pytest

from stegkit.core import pack, unpack
from stegkit.errors import DecodeError


def test_encrypted_frame_round_trip():
    payload = b"\x00secret\xff" * 20
    assert unpack(pack(payload, "correct horse"), "correct horse") == payload


def test_wrong_key_is_rejected():
    with pytest.raises(DecodeError, match="wrong key"):
        unpack(pack(b"secret", "right"), "wrong")


def test_unencrypted_frame_round_trip():
    assert unpack(pack(b"public")) == b"public"

