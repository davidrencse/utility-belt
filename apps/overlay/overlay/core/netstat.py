"""
Dependency-free network throughput counter.

Windows uses iphlpapi's GetIfTable2 (64-bit MIB_IF_ROW2). Linux reads
/proc/net/dev. NetMeter diffs per-interface counters to get bytes/sec.

Falls back to (0, 0) if the platform API is unavailable, so the graph just
flatlines instead of crashing.
"""
import ctypes
import platform
import time

IS_WINDOWS = platform.system().lower().startswith("win")
IS_LINUX = platform.system().lower() == "linux"


class _GUID(ctypes.Structure):
    _fields_ = [("d1", ctypes.c_uint32), ("d2", ctypes.c_uint16),
                ("d3", ctypes.c_uint16), ("d4", ctypes.c_ubyte * 8)]


_U64_COUNTERS = (
    "InOctets", "InUcastPkts", "InNUcastPkts", "InDiscards", "InErrors",
    "InUnknownProtos", "InUcastOctets", "InMulticastOctets",
    "InBroadcastOctets", "OutOctets", "OutUcastPkts", "OutNUcastPkts",
    "OutDiscards", "OutErrors", "OutUcastOctets", "OutMulticastOctets",
    "OutBroadcastOctets", "OutQLen")


class MIB_IF_ROW2(ctypes.Structure):
    """64-bit counters (GetIfTable2). The legacy GetIfTable's 32-bit octet
    counters wrap every ~34 s at 1 Gbit/s, which silently dropped samples."""
    _fields_ = [
        ("InterfaceLuid", ctypes.c_uint64),
        ("InterfaceIndex", ctypes.c_uint32),
        ("InterfaceGuid", _GUID),
        ("Alias", ctypes.c_wchar * 257),
        ("Description", ctypes.c_wchar * 257),
        ("PhysicalAddressLength", ctypes.c_uint32),
        ("PhysicalAddress", ctypes.c_ubyte * 32),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
        ("Mtu", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("TunnelType", ctypes.c_uint32),
        ("MediaType", ctypes.c_uint32),
        ("PhysicalMediumType", ctypes.c_uint32),
        ("AccessType", ctypes.c_uint32),
        ("DirectionType", ctypes.c_uint32),
        ("StatusFlags", ctypes.c_ubyte),     # InterfaceAndOperStatusFlags
        ("OperStatus", ctypes.c_uint32),
        ("AdminStatus", ctypes.c_uint32),
        ("MediaConnectState", ctypes.c_uint32),
        ("NetworkGuid", _GUID),
        ("ConnectionType", ctypes.c_uint32),
        ("TransmitLinkSpeed", ctypes.c_uint64),
        ("ReceiveLinkSpeed", ctypes.c_uint64),
    ] + [(name, ctypes.c_uint64) for name in _U64_COUNTERS]


_HARDWARE = 0x01          # StatusFlags bits
_FILTER = 0x02
_OPER_UP = 1
_iphlp_api = None


def _iphlp():
    global _iphlp_api
    if _iphlp_api is None:
        lib = ctypes.WinDLL("iphlpapi.dll")
        lib.GetIfTable2.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        lib.GetIfTable2.restype = ctypes.c_uint32
        lib.FreeMibTable.argtypes = [ctypes.c_void_p]
        lib.FreeMibTable.restype = None
        _iphlp_api = lib
    return _iphlp_api


def _windows_counters():
    """{luid: (in, out)} for physical interfaces that are up. Filter (LWF)
    and virtual/tunnel interfaces mirror a physical adapter's traffic and
    would double-count it, so they are skipped."""
    lib = _iphlp()
    ptr = ctypes.c_void_p()
    if lib.GetIfTable2(ctypes.byref(ptr)) != 0 or not ptr.value:
        return {}
    try:
        n = ctypes.c_uint32.from_address(ptr.value).value
        rows = (MIB_IF_ROW2 * n).from_address(
            ptr.value + ctypes.alignment(MIB_IF_ROW2))
        out = {}
        for r in rows:
            if (r.StatusFlags & _HARDWARE and not r.StatusFlags & _FILTER
                    and r.OperStatus == _OPER_UP):
                out[r.InterfaceLuid] = (r.InOctets, r.OutOctets)
        return out
    finally:
        lib.FreeMibTable(ptr)


_LINUX_SKIP = ("docker", "veth", "br-", "virbr", "tun", "tap", "wg", "tailscale")


def _linux_counters():
    out = {}
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as f:
            lines = f.readlines()[2:]
    except OSError:
        return out
    for line in lines:
        if ":" not in line:
            continue
        name, data = line.split(":", 1)
        iface = name.strip()
        if iface == "lo" or iface.startswith(_LINUX_SKIP):
            continue
        fields = data.split()
        if len(fields) < 16:
            continue
        try:
            out[iface] = (int(fields[0]), int(fields[8]))
        except ValueError:
            continue
    return out


def counters():
    """{interface_key: (in_bytes, out_bytes)}; empty if unsupported."""
    try:
        if IS_WINDOWS:
            return _windows_counters()
        if IS_LINUX:
            return _linux_counters()
    except (OSError, AttributeError, ValueError):
        pass
    return {}


def total_octets():
    """Return (in_bytes, out_bytes) summed across active interfaces."""
    c = counters().values()
    return sum(v[0] for v in c), sum(v[1] for v in c)


class NetMeter:
    """Throughput from per-interface deltas. Diffing a summed total spikes or
    dips whenever an adapter appears or drops (VPN up, Wi-Fi roam); here only
    interfaces present in both samples contribute, and counter resets are
    ignored instead of producing negative or huge values."""

    def __init__(self):
        self._prev = None
        self._t = 0.0
        self.session_in = 0       # bytes since the meter was created
        self.session_out = 0

    def reset(self):
        """Forget the last sample (e.g. after a pause) without losing the
        session totals."""
        self._prev = None

    def read(self):
        """(down_bps, up_bps) since the previous read; (0, 0) on the first."""
        now = time.perf_counter()
        cur = counters()
        prev, t = self._prev, self._t
        self._prev, self._t = cur, now
        if prev is None:
            return 0.0, 0.0
        din = dout = 0
        for key, (i, o) in cur.items():
            p = prev.get(key)
            if p is None:
                continue
            if i >= p[0]:
                din += i - p[0]
            if o >= p[1]:
                dout += o - p[1]
        self.session_in += din
        self.session_out += dout
        dt = max(1e-3, now - t)
        return din / dt, dout / dt


# --------------------------------------------------------------------- ping --
# In-process ICMP echo via iphlpapi (no admin rights needed). Launching ping.exe
# every sample costs a process spawn per second; this is a single API call.

class _IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte),
                ("Flags", ctypes.c_ubyte), ("OptionsSize", ctypes.c_ubyte),
                ("OptionsData", ctypes.c_void_p)]


class _ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [("Address", ctypes.c_uint32), ("Status", ctypes.c_uint32),
                ("RoundTripTime", ctypes.c_uint32), ("DataSize", ctypes.c_uint16),
                ("Reserved", ctypes.c_uint16), ("Data", ctypes.c_void_p),
                ("Options", _IP_OPTION_INFORMATION)]


_icmp_api = None
_icmp_handle = None
_resolved = {}            # host -> (addr, resolved_at)
_DNS_TTL = 300.0


def _icmp():
    global _icmp_api
    if _icmp_api is None:
        lib = ctypes.WinDLL("iphlpapi.dll")
        lib.IcmpCreateFile.restype = ctypes.c_void_p
        lib.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
        lib.IcmpSendEcho.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                                     ctypes.c_uint16, ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_uint32, ctypes.c_uint32]
        lib.IcmpSendEcho.restype = ctypes.c_uint32
        _icmp_api = lib
    return _icmp_api


def icmp_ping_ms(host, timeout=1.5):
    """Round-trip time in ms for one IPv4 echo, None on timeout/unreachable.
    Raises OSError if the API is unavailable so callers can fall back."""
    import socket
    import struct
    global _icmp_handle
    if not IS_WINDOWS:
        raise OSError("ICMP API only available on Windows")
    cached = _resolved.get(host)
    if cached is None or time.monotonic() - cached[1] > _DNS_TTL:
        # resolved before the timed echo, so DNS latency never skews the RTT;
        # re-resolved periodically so a moved host is followed
        addr = struct.unpack("<I", socket.inet_aton(socket.gethostbyname(host)))[0]
        _resolved[host] = (addr, time.monotonic())
    else:
        addr = cached[0]
    lib = _icmp()
    if _icmp_handle is None:                 # one handle for the process
        handle = lib.IcmpCreateFile()
        if not handle or handle == ctypes.c_void_p(-1).value:
            raise OSError("IcmpCreateFile failed")
        _icmp_handle = handle
    payload = b"overlay-ping"
    reply_size = ctypes.sizeof(_ICMP_ECHO_REPLY) + len(payload) + 8
    reply = ctypes.create_string_buffer(reply_size)
    t0 = time.perf_counter()
    count = lib.IcmpSendEcho(_icmp_handle, addr, payload, len(payload), None,
                             reply, reply_size, max(1, int(timeout * 1000)))
    wall = (time.perf_counter() - t0) * 1000
    if not count:
        return None
    echo = _ICMP_ECHO_REPLY.from_buffer_copy(reply)
    if echo.Status != 0:
        return None
    # RoundTripTime is whole milliseconds (0 for sub-ms LAN hosts). The wall
    # clock adds sub-ms precision; trust it only when it agrees.
    rtt = float(echo.RoundTripTime)
    return round(wall, 2) if rtt <= wall < rtt + 1.0 else rtt
