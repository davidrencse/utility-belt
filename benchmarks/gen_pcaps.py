"""Generate synthetic captures: mixed TCP/UDP/DNS/ARP/IPv6/ICMP traffic."""
import random
import sys

from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, IPv6, Raw, TCP, UDP, wrpcap
from scapy.utils import PcapNgWriter

random.seed(7)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 60000
out_dir = sys.argv[2]

hosts = [f"10.0.{i // 250}.{i % 250 + 1}" for i in range(400)]
servers = ["93.184.216.34", "1.1.1.1", "8.8.8.8", "142.250.1.1", "224.0.0.251"]
pkts = []
t = 1_700_000_000.0


def frame(p, align):
    raw = bytes(p)
    if align and len(raw) % 4:
        raw += b"\x00" * (4 - len(raw) % 4)   # trailing padding only; keeps L4 parse identical
    return raw


for i in range(N):
    t += random.random() * 0.002
    r = random.random()
    src = random.choice(hosts)
    dst = random.choice(servers)
    eth = Ether(src="02:00:00:%02x:%02x:01" % (i % 200, i % 13), dst="02:00:00:aa:bb:cc")
    if r < 0.55:
        sport = 40000 + (i % 3000)
        flags = random.choice(["S", "SA", "A", "PA", "PA", "FA", "R"])
        seq = (i // 3) * 1000 + random.choice([0, 0, 0, -1000])     # some retransmits / OOO
        p = eth / IP(src=src, dst=dst) / TCP(sport=sport, dport=random.choice([80, 443, 22, 8080]),
                                             flags=flags, seq=seq % 2**32, ack=i * 7 % 2**32,
                                             options=[("MSS", 1460)] if flags == "S" else [])
        p = p / Raw(b"x" * random.randint(0, 900))
    elif r < 0.75:
        p = eth / IP(src=src, dst="8.8.8.8") / UDP(sport=50000 + i % 500, dport=53) / DNS(
            rd=1, qd=DNSQR(qname=f"host{i % 900}.example{'x' * (i % 3)}.com"))
    elif r < 0.85:
        p = eth / IPv6(src=f"fe80::{i % 300:x}", dst=f"2001:db8::{i % 50:x}") / UDP(sport=1234, dport=5353) / Raw(b"y" * 40)
    elif r < 0.92:
        p = Ether(src="02:00:00:00:00:%02x" % (i % 250), dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=src, pdst=random.choice(hosts))
    elif r < 0.97:
        p = eth / IP(src=src, dst=dst) / ICMP()
    else:  # port-scan burst from one host
        p = eth / IP(src="10.9.9.9", dst="93.184.216.34") / TCP(sport=55555, dport=1 + i % 1024, flags="S")
    pkts.append((t, p))

for align, name in ((True, "aligned"), (False, "unaligned")):
    frames = []
    for ts, p in pkts:
        e = Ether(frame(p, align))
        e.time = ts
        frames.append(e)
    wrpcap(f"{out_dir}/{name}.pcap", frames)
    w = PcapNgWriter(f"{out_dir}/{name}.pcapng")
    for e in frames:
        w.write(e)
    w.close()
print("wrote", N, "packets")
