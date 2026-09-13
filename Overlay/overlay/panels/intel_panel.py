"""
Intel container - analysis of artifacts rather than live traffic: file
reputation (VirusTotal), hidden data in media (steganography) and image
geolocation (OSINT). Reuses the shared SubTabHost.
"""
from ..subtabs import SubTabHost
from .osint_panel import OsintPanel
from .stego_panel import StegoPanel
from .virustotal_panel import VirusTotalPanel


class IntelPanel(SubTabHost):
    def __init__(self, parent=None):
        self.vt = VirusTotalPanel()
        self.stego = StegoPanel()
        self.osint = OsintPanel()
        super().__init__([
            ("VirusTotal", self.vt),
            ("Steganography", self.stego),
            ("OSINT Geo", self.osint),
        ], parent)
