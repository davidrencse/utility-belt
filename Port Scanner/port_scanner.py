#!/usr/bin/env python3
"""
Concurrent TCP port scanner with service detection and banner grabbing.

WARNING: Only scan hosts and networks you own or have explicit written
permission to test. Unauthorized port scanning may violate computer
misuse laws (e.g. the CFAA in the US) and the acceptable use policies
of most networks and cloud/hosting providers.
"""

import argparse
import concurrent.futures
import os
import random
import re
import socket
import ssl
import sys
import tempfile
import threading
import time

try:
    import colorama
    colorama.init()
    COLOR_OK = True
except ImportError:
    COLOR_OK = False


class Color:
    GREEN = "\033[92m" if COLOR_OK else ""
    RED = "\033[91m" if COLOR_OK else ""
    YELLOW = "\033[93m" if COLOR_OK else ""
    CYAN = "\033[96m" if COLOR_OK else ""
    BOLD = "\033[1m" if COLOR_OK else ""
    RESET = "\033[0m" if COLOR_OK else ""


# Common port -> service name mapping. Not exhaustive, but covers the
# services you're most likely to encounter during a standard sweep.
COMMON_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 111: "RPCbind", 119: "NNTP",
    123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 515: "LPD", 543: "Kerberos-Login",
    544: "Kerberos-Shell", 587: "SMTP-Submission", 631: "IPP",
    636: "LDAPS", 873: "Rsync", 989: "FTPS-Data", 990: "FTPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1434: "MSSQL-Monitor", 1521: "Oracle-DB",
    1723: "PPTP", 1883: "MQTT", 2049: "NFS", 2082: "cPanel",
    2083: "cPanel-SSL", 2181: "ZooKeeper", 2375: "Docker",
    2376: "Docker-SSL", 27017: "MongoDB", 27018: "MongoDB",
    3000: "Dev-HTTP", 3128: "Squid-Proxy", 3268: "LDAP-GC",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4000: "Dev-HTTP",
    4444: "Metasploit/Backdoor", 4505: "SaltStack", 4506: "SaltStack",
    5000: "Dev-HTTP/UPnP", 5432: "PostgreSQL", 5601: "Kibana",
    5672: "AMQP", 5900: "VNC", 5901: "VNC", 5984: "CouchDB",
    6000: "X11", 6379: "Redis", 6443: "Kubernetes-API",
    6660: "IRC", 6667: "IRC", 7001: "WebLogic", 7077: "Spark",
    8000: "Dev-HTTP", 8008: "HTTP-Alt", 8080: "HTTP-Proxy",
    8081: "HTTP-Alt", 8086: "InfluxDB", 8443: "HTTPS-Alt",
    8888: "Dev-HTTP", 9000: "Dev-HTTP/PHP-FPM", 9042: "Cassandra",
    9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
    11211: "Memcached", 15672: "RabbitMQ-Mgmt", 27019: "MongoDB-Config",
    50000: "SAP", 50070: "Hadoop-NameNode",
}


# Short, human-readable blurb for the most commonly seen services —
# used in the GUI's detail popup and CLI verbose output.
SERVICE_DESCRIPTIONS = {
    "SSH": "Remote shell", "FTP": "File transfer", "FTP-DATA": "File transfer (data)",
    "Telnet": "Unencrypted remote shell", "SMTP": "Mail transfer", "DNS": "Name resolution",
    "HTTP": "Web server", "HTTPS": "Encrypted web server", "HTTPS-Alt": "Encrypted web server (alt port)",
    "POP3": "Mail retrieval", "IMAP": "Mail retrieval", "IMAPS": "Mail retrieval (TLS)",
    "POP3S": "Mail retrieval (TLS)", "SMTPS": "Mail transfer (TLS)", "SMB": "Windows file sharing",
    "NetBIOS-SSN": "Windows file sharing (legacy)", "RDP": "Remote administration",
    "VNC": "Remote desktop", "MySQL": "Database", "PostgreSQL": "Database",
    "MSSQL": "Database", "MongoDB": "Database", "Redis": "In-memory database/cache",
    "Elasticsearch": "Search/analytics database", "Memcached": "In-memory cache",
    "MS-RPC": "Windows RPC endpoint mapper", "LDAP": "Directory services", "LDAPS": "Directory services (TLS)",
    "NTP": "Time sync", "SNMP": "Network management", "Docker": "Container API",
    "Kubernetes-API": "Cluster management API", "SOCKS": "Proxy", "HTTP-Proxy": "Proxy",
    "Rsync": "File sync", "NFS": "Network file system",
}

# Ports where the TLS handshake happens immediately on connect (no
# STARTTLS negotiation needed), so a plain TLS wrap-and-read works.
TLS_IMPLICIT_PORTS = {443, 8443, 9443, 993, 995, 465, 636}
# Ports that speak plaintext HTTP.
HTTP_PLAIN_PORTS = {80, 8080, 8000, 8008, 8081, 8888, 3000, 4000, 5000, 9000}


def _load_os_services():
    """Parse the OS services database once into {(port, proto): name}.

    socket.getservbyport() does this lookup per call, and it costs
    ~0.7 ms/port — on a 4000-port sweep that's ~2.7 s of pure overhead,
    incurred inside every worker thread. Parsing the file a single time
    turns the per-port lookup into a plain dict access.
    """
    if os.name == "nt":
        path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "drivers", "etc", "services")
    else:
        path = "/etc/services"
    table = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0].split()
                if len(line) < 2 or "/" not in line[1]:
                    continue
                name, portproto = line[0], line[1]
                num, _, proto = portproto.partition("/")
                if num.isdigit():
                    table.setdefault((int(num), proto.lower()), name)
    except OSError:
        pass
    return table


_OS_SERVICES = _load_os_services()


def get_service_name(port, proto="tcp"):
    # Curated names win; then the pre-parsed OS table; then a live syscall
    # only as a last resort (reached only if the services file was missing).
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    name = _OS_SERVICES.get((port, proto))
    if name is not None:
        return name
    if not _OS_SERVICES:
        try:
            return socket.getservbyport(port, proto)
        except OSError:
            pass
    return "unknown"


def parse_ports(spec):
    """Parse a port spec like '80', '1-1024', or '22,80,443,8000-8100'."""
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))
    invalid = [p for p in ports if p < 1 or p > 65535]
    if invalid:
        raise ValueError(f"Ports out of range (1-65535): {sorted(invalid)}")
    return sorted(ports)


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target '{target}': {exc}")


def grab_banner(sock, port):
    """Try to read a service banner. Send a protocol-specific nudge for
    services that stay silent until spoken to."""
    try:
        sock.settimeout(1.0)
        try:
            banner = sock.recv(256)
        except socket.timeout:
            banner = b""

        if not banner and port in HTTP_PLAIN_PORTS:
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(256)
            except (socket.timeout, OSError):
                banner = b""
        elif not banner and port == 6379:  # Redis stays silent until spoken to
            try:
                sock.sendall(b"PING\r\n")
                banner = sock.recv(256)
            except (socket.timeout, OSError):
                banner = b""

        if port == 3306 and banner:
            # MySQL's initial handshake is binary: [3-byte len][seq][proto ver][null-term version]
            try:
                version_end = banner.index(b"\x00", 5)
                version = banner[5:version_end].decode(errors="replace")
                return f"MySQL handshake, server version {version}"
            except (ValueError, IndexError):
                pass

        return banner.decode(errors="replace").strip().replace("\r\n", " | ")[:160]
    except OSError:
        return ""


_VERSION_PATTERNS = [
    re.compile(r"SSH-\d\.\d-(OpenSSH_[\w.]+)", re.I),
    re.compile(r"SSH-\d\.\d-([\w.\-]+)", re.I),
    re.compile(r"\b(vsFTPd|ProFTPD|FileZilla|Pure-?FTPd|Microsoft FTP Service)[\s/]*([\d.]+)?", re.I),
    re.compile(r"\b(Exim|Postfix|Sendmail|Microsoft ESMTP MAIL)[\s/]*([\d.]+)?", re.I),
    re.compile(r"server version\s+([\w.\-]+)", re.I),
    re.compile(r"\b(nginx|Apache|Microsoft-IIS|lighttpd|Werkzeug|Caddy)[/\s]([\d.]+)", re.I),
]


def extract_version(banner):
    """Best-effort service/version string pulled out of a banner using a
    handful of known patterns. Returns '' if nothing recognizable."""
    if not banner:
        return ""
    for pattern in _VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            groups = [g for g in m.groups() if g]
            return " ".join(groups) if groups else m.group(0)
    return ""


def _decode_cert_pem(pem_text):
    """Pull subject/issuer/validity out of a PEM cert without validating
    it, using CPython's internal test decoder (best-effort — falls back
    to None if unavailable, which is fine, this is purely informational)."""
    try:
        fd, path = tempfile.mkstemp(suffix=".pem")
        os.close(fd)
        try:
            with open(path, "w") as f:
                f.write(pem_text)
            decoded = ssl._ssl._test_decode_cert(path)
        finally:
            os.remove(path)
        subject = dict(x[0] for x in decoded.get("subject", ()))
        issuer = dict(x[0] for x in decoded.get("issuer", ()))
        return {
            "subject_cn": subject.get("commonName", ""),
            "issuer_cn": issuer.get("commonName", ""),
            "not_before": decoded.get("notBefore", ""),
            "not_after": decoded.get("notAfter", ""),
        }
    except Exception:
        return None


def probe_tls(ip, port, timeout):
    """Connect with TLS (no cert validation) and report the negotiated
    protocol/cipher plus best-effort certificate subject/issuer/validity."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as tls_sock:
                cert_bin = tls_sock.getpeercert(binary_form=True)
                cipher = tls_sock.cipher()
                tls_version = tls_sock.version()
        info = {"tls_version": tls_version, "cipher": cipher[0] if cipher else None}
        if cert_bin:
            decoded = _decode_cert_pem(ssl.DER_cert_to_PEM_cert(cert_bin))
            if decoded:
                info.update(decoded)
        return info
    except Exception as exc:
        return {"error": str(exc)}


def probe_http(ip, port, timeout, use_tls):
    """Issue a minimal GET and pull out the status line, Server header,
    and <title> — enough to identify what's running a web port."""
    sock = None
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=ip)
        else:
            sock = raw
        sock.settimeout(timeout)
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: PortScanner/1.0\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())

        data = b""
        try:
            while len(data) < 16384:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass

        text = data.decode(errors="replace")
        status_line = text.split("\r\n", 1)[0].strip() if text else ""
        server_match = re.search(r"^Server:\s*(.+)$", text, re.I | re.M)
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        return {
            "status_line": status_line,
            "server": server_match.group(1).strip() if server_match else "",
            "title": re.sub(r"\s+", " ", title_match.group(1)).strip()[:150] if title_match else "",
        }
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


class RateLimiter:
    """Caps how many new connection attempts start per second, shared
    across all worker threads.

    Scanning as fast as the thread pool allows is exactly the traffic
    pattern IDS/firewalls flag — after which THEY rate-limit or blackhole
    your source IP, so the scan silently turns into all-filtered garbage.
    Pacing the source keeps you under those thresholds.

    A worker calls acquire() before opening its socket; the sleep happens
    under the lock on purpose, so the *starts* are serialised to `rate`
    per second while the socket I/O itself still runs concurrently.
    """

    def __init__(self, rate_per_sec):
        self.min_interval = 1.0 / rate_per_sec if rate_per_sec and rate_per_sec > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def acquire(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.perf_counter()
            wait = self._next - now
            if wait > 0:
                time.sleep(wait)
                self._next += self.min_interval
            else:
                self._next = now + self.min_interval


def scan_port(ip, port, timeout, do_banner, deep_probe=False, limiter=None):
    """Scan a single TCP port. With deep_probe=True, open web/TLS ports
    also get an HTTP header/title fetch and/or a certificate probe —
    slower, so it's opt-in. `limiter`, if given, paces connection starts."""
    if limiter is not None:
        limiter.acquire()
    result = {
        "port": port, "protocol": "tcp", "status": "closed",
        "service": get_service_name(port), "banner": "", "version": "",
        "response_ms": None, "tls": None, "http": None,
    }
    start = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            err = sock.connect_ex((ip, port))
            result["response_ms"] = round((time.perf_counter() - start) * 1000, 1)
            if err == 0:
                result["status"] = "open"
                if do_banner:
                    result["banner"] = grab_banner(sock, port)
                    result["version"] = extract_version(result["banner"])
    except (socket.timeout, OSError):
        result["status"] = "filtered"
        result["response_ms"] = round((time.perf_counter() - start) * 1000, 1)

    if deep_probe and result["status"] == "open":
        if port in TLS_IMPLICIT_PORTS:
            result["tls"] = probe_tls(ip, port, timeout)
        if port in HTTP_PLAIN_PORTS or port in TLS_IMPLICIT_PORTS:
            result["http"] = probe_http(ip, port, timeout, use_tls=port in TLS_IMPLICIT_PORTS)
            if result["http"] and result["http"].get("server") and not result["version"]:
                result["version"] = result["http"]["server"]

    return result


# UDP services that stay silent unless you send a protocol-correct probe.
# Everything else gets a 1-byte nudge, which many services ignore —
# that's expected, and is why a non-response is reported as
# "open|filtered" rather than a hard "closed" (standard UDP-scan caveat).
_UDP_PROBES = {
    53: bytes.fromhex("0001010000010000000000000000")
    + b"\x07example\x03com\x00\x00\x01\x00\x01",  # minimal A-record query
    123: b"\x1b" + b"\x00" * 47,  # NTP client request
}


def scan_udp_port(ip, port, timeout, limiter=None):
    if limiter is not None:
        limiter.acquire()
    result = {
        "port": port, "protocol": "udp", "status": "open|filtered",
        "service": get_service_name(port, "udp"), "banner": "", "version": "",
        "response_ms": None, "tls": None, "http": None,
    }
    start = time.perf_counter()
    probe = _UDP_PROBES.get(port, b"\x00")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(probe, (ip, port))
            try:
                data, _ = sock.recvfrom(512)
                result["status"] = "open"
                result["banner"] = data[:120].decode(errors="replace")
            except socket.timeout:
                result["status"] = "open|filtered"
            except ConnectionResetError:
                result["status"] = "closed"  # ICMP port-unreachable surfaces this way
    except OSError:
        result["status"] = "error"
    result["response_ms"] = round((time.perf_counter() - start) * 1000, 1)
    return result


def run_scan(ip, ports, timeout, max_workers, do_banner, show_progress,
             protocol="tcp", deep_probe=False, rate=0, randomize=False):
    results = []
    total = len(ports)
    done_count = 0
    lock = threading.Lock()
    limiter = RateLimiter(rate)

    # Sequential 1..N is a classic scan signature; shuffling the order
    # makes the traffic look less like a sweep. Results are re-sorted below.
    scan_ports = list(ports)
    if randomize:
        random.shuffle(scan_ports)

    def worker(p):
        nonlocal done_count
        if protocol == "udp":
            r = scan_udp_port(ip, p, timeout, limiter=limiter)
        else:
            r = scan_port(ip, p, timeout, do_banner, deep_probe=deep_probe, limiter=limiter)
        with lock:
            done_count += 1
            if show_progress and done_count % 50 == 0:
                sys.stderr.write(f"\r{Color.CYAN}Scanned {done_count}/{total} ports...{Color.RESET}")
                sys.stderr.flush()
        return r

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for r in pool.map(worker, scan_ports):
            results.append(r)

    if show_progress:
        sys.stderr.write("\r" + " " * 40 + "\r")
        sys.stderr.flush()

    return sorted(results, key=lambda r: r["port"])


def print_recon(target, ip):
    import net_recon

    print(f"\n{Color.BOLD}Host recon for {target} ({ip}){Color.RESET}")
    ping = net_recon.ping_host(ip)
    status_color = Color.GREEN if ping["status"] == "online" else Color.RED
    print(f"  Status:    {status_color}{ping['status']}{Color.RESET}")
    if ping["latency_ms"] is not None:
        print(f"  Latency:   {ping['latency_ms']} ms")
    if ping["ttl"] is not None:
        print(f"  TTL:       {ping['ttl']}  (OS guess: {net_recon.guess_os_from_ttl(ping['ttl'])})")

    hostname = net_recon.reverse_dns(ip)
    print(f"  Hostname:  {hostname or '(none)'}")

    addrs = net_recon.forward_dns(target)
    if addrs:
        print(f"  DNS A/AAAA: {', '.join(addrs)}")

    mac = net_recon.get_mac_address(ip)
    if mac:
        print(f"  MAC:       {mac}  (vendor guess: {net_recon.guess_vendor(mac)})")
    else:
        print("  MAC:       not available (off-subnet or not yet in ARP cache)")


def print_results(target, ip, results, show_all):
    open_results = [r for r in results if r["status"] == "open"]

    print(f"\n{Color.BOLD}Scan results for {target} ({ip}){Color.RESET}")
    header = f"{'PORT':<8}{'PROTO':<7}{'STATUS':<14}{'SERVICE':<16}{'VERSION':<24}{'RESP(ms)':<10}BANNER"
    print(header)
    print("-" * min(140, max(80, len(header) + 40)))

    rows = results if show_all else open_results
    if not rows:
        print("No open ports found in the scanned range.")
        return

    for r in rows:
        if r["status"] == "open":
            color = Color.GREEN
        elif r["status"] in ("filtered", "open|filtered"):
            color = Color.YELLOW
        else:
            color = Color.RED
        banner = (r.get("banner") or "")[:60]
        version = (r.get("version") or "")[:22]
        resp = r.get("response_ms")
        resp_str = f"{resp}" if resp is not None else ""
        print(f"{color}{r['port']:<8}{r.get('protocol', 'tcp'):<7}{r['status']:<14}"
              f"{r['service']:<16}{version:<24}{resp_str:<10}{banner}{Color.RESET}")

    print("-" * min(140, max(80, len(header) + 40)))
    print(f"{Color.BOLD}{len(open_results)} open port(s) found out of {len(results)} scanned.{Color.RESET}")


def confirm_authorization(target, ip, assume_yes):
    localhost_aliases = {"127.0.0.1", "localhost", "::1"}
    if target in localhost_aliases or ip in localhost_aliases:
        return True
    if assume_yes:
        return True

    print(f"{Color.YELLOW}{Color.BOLD}WARNING:{Color.RESET} You are about to scan "
          f"{Color.BOLD}{target} ({ip}){Color.RESET}, which is not localhost.")
    print("Port scanning systems you do not own or lack explicit permission to test")
    print("may violate the law and the target network's acceptable use policy.")
    try:
        answer = input("Do you have explicit authorization to scan this target? [y/N]: ")
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.strip().lower() in ("y", "yes")


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="port_scanner.py",
        description="Concurrent TCP port scanner with banner grabbing and service detection.",
        epilog=(
            "Examples:\n"
            "  python port_scanner.py -t 127.0.0.1\n"
            "  python port_scanner.py -t 127.0.0.1 -p 1-65535 --threads 200\n"
            "  python port_scanner.py -t scanme.example.com -p 22,80,443,8080-8090 -v\n"
            "  python port_scanner.py -t 10.0.0.5 -p 1-1024 --no-banner --timeout 1.0\n\n"
            "LEGAL/ETHICAL NOTICE: Only scan systems and networks you own or have\n"
            "explicit written permission to test. Unauthorized scanning may be illegal."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP address or hostname.")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Port(s) to scan: single (80), range (1-1024), or list "
                              "(22,80,443,8000-8100). Default: 1-1024.")
    parser.add_argument("--timeout", type=float, default=2.0,
                         help="Per-connection timeout in seconds (default: 2.0).")
    parser.add_argument("--threads", type=int, default=100,
                         help="Maximum concurrent connections (default: 100).")
    parser.add_argument("--no-banner", action="store_true",
                         help="Skip banner grabbing (faster scans).")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Show closed/filtered ports too, not just open ones.")
    parser.add_argument("-y", "--yes", action="store_true",
                         help="Skip the authorization confirmation prompt "
                              "(use only when you already have permission).")
    parser.add_argument("--no-progress", action="store_true",
                         help="Suppress the live progress indicator.")
    parser.add_argument("--udp", action="store_true",
                         help="Scan UDP instead of TCP (best-effort — UDP has no handshake, "
                              "so non-responses are reported as 'open|filtered').")
    parser.add_argument("--recon", action="store_true",
                         help="Run host recon first: ping/latency/TTL, OS guess, MAC + vendor "
                              "guess (local subnet only), reverse/forward DNS.")
    parser.add_argument("--deep", action="store_true",
                         help="Deep-probe open web/TLS ports for HTTP headers, page title, "
                              "and certificate subject/issuer/expiry. Slower.")
    parser.add_argument("--traceroute", action="store_true",
                         help="Run a traceroute to the target after scanning. Can take a while.")
    parser.add_argument("--rate", type=float, default=0, metavar="N",
                         help="Throttle to at most N new connections per second across all "
                              "threads (0 = unlimited). Keeps you under IDS/firewall thresholds "
                              "so the target doesn't rate-limit or block your IP.")
    parser.add_argument("--polite", action="store_true",
                         help="Shorthand for a gentle, low-profile scan: --rate 50 --random-order.")
    parser.add_argument("--random-order", action="store_true",
                         help="Scan ports in randomized order so the traffic looks less like "
                              "a sequential sweep.")
    parser.add_argument("--geo", action="store_true",
                         help="Look up approximate IP geolocation (city/region/country/org/ASN) "
                              "via ip-api.com — city-level only, not a street address.")
    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))
        return

    try:
        ip = resolve_target(args.target)
    except ValueError as exc:
        print(f"{Color.RED}Error: {exc}{Color.RESET}", file=sys.stderr)
        sys.exit(1)

    if not confirm_authorization(args.target, ip, args.yes):
        print(f"{Color.RED}Authorization not confirmed. Aborting scan.{Color.RESET}")
        sys.exit(1)

    if args.recon:
        print_recon(args.target, ip)

    if args.geo:
        import geoip
        geo = geoip.locate(ip)
        print(f"\n{Color.BOLD}Geolocation for {args.target} ({ip}){Color.RESET}")
        if geo.get("ok"):
            print(f"  Location:  {geo.get('city')}, {geo.get('regionName')}, {geo.get('country')}")
            print(f"  Lat/Lon:   {geo.get('lat')}, {geo.get('lon')}  ({geo.get('timezone')})")
            print(f"  Org/ISP:   {geo.get('org') or geo.get('isp')}")
            print(f"  ASN:       {geo.get('as')}")
            print(f"  {Color.YELLOW}(city-level ISP registration — not a street address){Color.RESET}")
        else:
            print(f"  {Color.YELLOW}{geo.get('message')}{Color.RESET}")

    rate = 50.0 if args.polite and not args.rate else args.rate
    randomize = args.random_order or args.polite

    max_workers = max(1, min(args.threads, len(ports)))
    protocol = "udp" if args.udp else "tcp"
    rate_note = f", {rate:g}/s rate cap" if rate > 0 else ""
    order_note = ", randomized order" if randomize else ""
    print(f"\n{Color.CYAN}Scanning {args.target} ({ip}) — {len(ports)} {protocol.upper()} port(s), "
          f"{max_workers} threads, {args.timeout}s timeout{rate_note}{order_note}...{Color.RESET}")

    scan_start_wall = time.strftime("%Y-%m-%d %H:%M:%S")
    start = time.time()
    results = run_scan(
        ip, ports, args.timeout, max_workers,
        do_banner=not args.no_banner,
        show_progress=not args.no_progress,
        protocol=protocol,
        deep_probe=args.deep,
        rate=rate,
        randomize=randomize,
    )
    elapsed = time.time() - start
    scan_end_wall = time.strftime("%Y-%m-%d %H:%M:%S")

    print_results(args.target, ip, results, show_all=args.verbose)
    print(f"Scan started:  {scan_start_wall}")
    print(f"Scan finished: {scan_end_wall}")
    print(f"Duration:      {elapsed:.2f} seconds")
    print(f"Ports scanned: {len(ports)}  |  Hosts scanned: 1")

    if args.traceroute:
        import net_recon
        print(f"\n{Color.CYAN}Tracing route to {args.target} (this can take a while)...{Color.RESET}")
        trace = net_recon.traceroute(args.target)
        if trace["error"]:
            print(f"{Color.RED}Traceroute failed: {trace['error']}{Color.RESET}")
        else:
            for hop in trace["hops"]:
                if hop["timeout"]:
                    print(f"  {hop['hop']:>3}  * * *  (no response)")
                else:
                    lat = f"{hop['latency_ms']:.1f} ms" if hop["latency_ms"] is not None else "?"
                    print(f"  {hop['hop']:>3}  {hop['ip']:<16} {lat}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Color.RED}Scan interrupted by user.{Color.RESET}")
        sys.exit(130)
