"""
Network container - everything that talks to or listens on the wire:
connection speed, active port scanning and passive packet capture.
Reuses the shared SubTabHost.
"""
from ..subtabs import SubTabHost
from .net_panel import NetPanel
from .portscan_panel import PortScanPanel
from .sniffer_panel import SnifferPanel


class NetworkPanel(SubTabHost):
    def __init__(self, parent=None):
        super().__init__([
            ("Speed Test", NetPanel),   # lazy: keyless Cloudflare speed test
            ("Port Scan", PortScanPanel),
            # lazy: building the sniffer queries Npcap for the interface list,
            # so the HUD only pays for that once someone opens it.
            ("Sniffer", SnifferPanel),
        ], parent)
