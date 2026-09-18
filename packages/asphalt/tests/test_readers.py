import os
import struct
import tempfile
import unittest

from pcap_loader.pcap_reader import PcapReader
from pcap_loader.pcapng_reader import PcapngReader


def _frame(n: int) -> bytes:
    # Minimal Ethernet header (IPv4 ethertype) plus filler to reach n bytes.
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + b"\x00" * (n - 14)


def _write(data: bytes, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def _pcapng(tsresol_byte: int, ts_raw: int) -> bytes:
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = struct.pack("<II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body + struct.pack("<I", 12 + len(shb_body))
    opts = struct.pack("<HHB3x", 9, 1, tsresol_byte) + struct.pack("<HH", 0, 0)
    idb_body = struct.pack("<HHI", 1, 0, 65535) + opts
    idb = struct.pack("<II", 1, 12 + len(idb_body)) + idb_body + struct.pack("<I", 12 + len(idb_body))
    pkt = _frame(60)
    epb_body = struct.pack("<IIIII", 0, ts_raw >> 32, ts_raw & 0xFFFFFFFF, len(pkt), len(pkt)) + pkt
    epb = struct.pack("<II", 6, 12 + len(epb_body)) + epb_body + struct.pack("<I", 12 + len(epb_body))
    return shb + idb + epb


def _read_all(cls, path):
    with cls(path) as reader:
        return list(reader)


class PcapReaderTests(unittest.TestCase):
    def test_records_are_not_padded(self):
        # Classic pcap has no inter-record padding; odd caplens must not desync parsing.
        lengths = [61, 63, 64, 97]
        data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        for i, n in enumerate(lengths):
            data += struct.pack("<IIII", 1_700_000_000 + i, 5, n, n) + _frame(n)
        path = _write(data, ".pcap")
        try:
            packets = _read_all(PcapReader, path)
        finally:
            os.unlink(path)
        self.assertEqual([p.captured_length for p in packets], lengths)
        self.assertEqual(packets[-1].timestamp_us, (1_700_000_000 + 3) * 1_000_000 + 5)


class PcapngTsresolTests(unittest.TestCase):
    def _ts(self, tsresol_byte, ts_raw):
        path = _write(_pcapng(tsresol_byte, ts_raw), ".pcapng")
        try:
            (packet,) = _read_all(PcapngReader, path)
        finally:
            os.unlink(path)
        return packet.timestamp_us

    def test_decimal_resolutions(self):
        self.assertEqual(self._ts(6, 1_234_567), 1_234_567)
        self.assertEqual(self._ts(9, 1_234_567_000), 1_234_567)
        self.assertEqual(self._ts(3, 1_234), 1_234_000)

    def test_binary_resolution_is_not_mistaken_for_decimal(self):
        # 0x89 = 2**-9 s units, not nanoseconds: 512 ticks is exactly one second.
        self.assertEqual(self._ts(0x80 | 9, 512 * 3), 3_000_000)
        self.assertEqual(self._ts(0x80 | 6, 64), 1_000_000)


if __name__ == "__main__":
    unittest.main()
