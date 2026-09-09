"""
Tools container - groups the utility-belt panels under one top-level tab with
a shared SubTabHost, so the top tab bar stays uncluttered as tools grow.
"""
from ..subtabs import SubTabHost
from .portscan_panel import PortScanPanel
from .stego_panel import StegoPanel
from .osint_panel import OsintPanel
from .virustotal_panel import VirusTotalPanel


class ToolsPanel(SubTabHost):
    def __init__(self, parent=None):
        self.ports = PortScanPanel()
        self.stego = StegoPanel()
        self.osint = OsintPanel()
        self.vt = VirusTotalPanel()
        super().__init__([
            ("Port Scan", self.ports),
            ("Steganography", self.stego),
            ("OSINT Geo", self.osint),
            ("VirusTotal", self.vt),
        ], parent)
