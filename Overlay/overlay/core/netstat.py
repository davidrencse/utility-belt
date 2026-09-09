"""
Dependency-free network throughput counter for Windows, via iphlpapi's
GetIfTable (MIB_IFTABLE / MIB_IFROW). Sums in/out octets across the real
interfaces; the caller diffs successive totals to get bytes/sec.

Falls back to (0, 0) on non-Windows or if the API is unavailable, so the
graph just flatlines instead of crashing.
"""
import ctypes
import platform

IS_WINDOWS = platform.system().lower().startswith("win")

MAX_INTERFACE_NAME_LEN = 256
MAXLEN_IFDESCR = 256
# dwType values we count as "real" traffic-bearing interfaces
IF_TYPE_ETHERNET = 6
IF_TYPE_IEEE80211 = 71   # Wi-Fi
IF_TYPE_PPP = 23
_COUNTED = {IF_TYPE_ETHERNET, IF_TYPE_IEEE80211, IF_TYPE_PPP}


class MIB_IFROW(ctypes.Structure):
    _fields_ = [
        ("wszName", ctypes.c_wchar * MAX_INTERFACE_NAME_LEN),
        ("dwIndex", ctypes.c_uint),
        ("dwType", ctypes.c_uint),
        ("dwMtu", ctypes.c_uint),
        ("dwSpeed", ctypes.c_uint),
        ("dwPhysAddrLen", ctypes.c_uint),
        ("bPhysAddr", ctypes.c_ubyte * 8),
        ("dwAdminStatus", ctypes.c_uint),
        ("dwOperStatus", ctypes.c_uint),
        ("dwLastChange", ctypes.c_uint),
        ("dwInOctets", ctypes.c_uint),
        ("dwInUcastPkts", ctypes.c_uint),
        ("dwInNUcastPkts", ctypes.c_uint),
        ("dwInDiscards", ctypes.c_uint),
        ("dwInErrors", ctypes.c_uint),
        ("dwInUnknownProtos", ctypes.c_uint),
        ("dwOutOctets", ctypes.c_uint),
        ("dwOutUcastPkts", ctypes.c_uint),
        ("dwOutNUcastPkts", ctypes.c_uint),
        ("dwOutDiscards", ctypes.c_uint),
        ("dwOutErrors", ctypes.c_uint),
        ("dwOutQLen", ctypes.c_uint),
        ("dwDescrLen", ctypes.c_uint),
        ("bDescr", ctypes.c_ubyte * MAXLEN_IFDESCR),
    ]


def _make_iftable(n):
    class MIB_IFTABLE(ctypes.Structure):
        _fields_ = [("dwNumEntries", ctypes.c_uint),
                    ("table", MIB_IFROW * n)]
    return MIB_IFTABLE


def total_octets():
    """Return (in_bytes, out_bytes) summed across active interfaces.
    32-bit counters wrap at 4 GiB; the caller's delta logic clamps negatives."""
    if not IS_WINDOWS:
        return 0, 0
    try:
        iphlpapi = ctypes.windll.iphlpapi
    except (OSError, AttributeError):
        return 0, 0

    size = ctypes.c_ulong(0)
    ERROR_INSUFFICIENT_BUFFER = 122
    # First call sizes the buffer.
    rv = iphlpapi.GetIfTable(None, ctypes.byref(size), False)
    if rv not in (ERROR_INSUFFICIENT_BUFFER, 0) or size.value == 0:
        return 0, 0
    # Roomy estimate of entry count, then a real typed struct.
    approx = max(1, (size.value // ctypes.sizeof(MIB_IFROW)) + 4)
    table = _make_iftable(approx)()
    size = ctypes.c_ulong(ctypes.sizeof(table))
    rv = iphlpapi.GetIfTable(ctypes.byref(table), ctypes.byref(size), False)
    if rv != 0:
        return 0, 0

    in_b = out_b = 0
    for i in range(min(table.dwNumEntries, approx)):
        row = table.table[i]
        if row.dwType in _COUNTED:
            in_b += row.dwInOctets
            out_b += row.dwOutOctets
    return in_b, out_b
