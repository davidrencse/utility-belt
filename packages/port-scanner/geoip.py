#!/usr/bin/env python3
"""
Approximate IP geolocation for the dashboard's map view.

HONEST SCOPE: IP geolocation resolves to the *registered location of the
network/ISP* — typically city-level, sometimes only the ISP's home city
hundreds of km from the actual host. It cannot pinpoint a street address
or a specific building, and private/LAN addresses have no public location
at all. The 3D "street/building" view is therefore a stylised
representation centred on these coordinates, not a surveyed address.

Uses the free ip-api.com endpoint (no key, ~45 req/min). This makes an
outbound HTTP request containing the target IP — it only runs when the
user explicitly asks to geolocate. Results are cached; private IPs never
leave the machine. Everything degrades to a clear message on failure.
"""

import functools
import ipaddress
import json
import urllib.request

_FIELDS = ("status,message,country,countryCode,regionName,region,city,zip,"
           "lat,lon,timezone,isp,org,as,query")


def _is_private(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_unspecified or addr.is_multicast)


@functools.lru_cache(maxsize=512)
def locate(ip, timeout=6.0):
    """Geolocate a public IP. Returns a dict that always has:
        ok (bool), private (bool), query (str), message (str, if not ok)
    and, when ok, the ip-api fields (city, regionName, country, lat, lon,
    org, isp, as/asn, timezone, zip)."""
    if _is_private(ip):
        return {"ok": False, "private": True, "query": ip,
                "message": "Private / LAN address — no public geolocation."}
    url = f"http://ip-api.com/json/{ip}?fields={_FIELDS}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PortScanner/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as exc:  # network down, DNS, timeout, bad JSON — all non-fatal
        return {"ok": False, "private": False, "query": ip,
                "message": f"Lookup failed: {exc}"}
    if data.get("status") != "success":
        return {"ok": False, "private": False, "query": ip,
                "message": data.get("message", "lookup failed")}
    data["ok"] = True
    data["private"] = False
    return data


@functools.lru_cache(maxsize=1)
def locate_self(timeout=6.0):
    """Geolocate this machine's own public IP (ip-api with no address).
    Used as the 'you are here' origin for the map arc. Best-effort."""
    url = f"http://ip-api.com/json/?fields={_FIELDS}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PortScanner/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as exc:
        return {"ok": False, "message": f"Lookup failed: {exc}"}
    if data.get("status") != "success":
        return {"ok": False, "message": data.get("message", "lookup failed")}
    data["ok"] = True
    return data


def summary(geo):
    """One-line human summary of a locate() result."""
    if not geo.get("ok"):
        return geo.get("message", "unknown")
    bits = [geo.get("city"), geo.get("regionName"), geo.get("country")]
    place = ", ".join(b for b in bits if b)
    coords = f"{geo.get('lat')}, {geo.get('lon')}"
    org = geo.get("org") or geo.get("isp") or ""
    return f"{place} ({coords})" + (f" · {org}" if org else "")


if __name__ == "__main__":
    import sys
    ip = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    g = locate(ip)
    print(summary(g))
    for k in ("city", "regionName", "country", "lat", "lon", "org", "isp", "as", "timezone"):
        if k in g:
            print(f"  {k:>12}: {g[k]}")
