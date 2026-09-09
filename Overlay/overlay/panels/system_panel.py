"""
System container - the SYSTEM tab split into LIVE (real-time gauges + graphs)
and SPECS (Task-Manager-style machine info). SPECS is built lazily because its
CIM/network query is slow. Reuses the shared SubTabHost.
"""
from ..subtabs import SubTabHost
from .metrics_panel import MetricsPanel
from .specs_panel import SpecsPanel


class SystemPanel(SubTabHost):
    def __init__(self, parent=None):
        self.live = MetricsPanel()
        super().__init__([
            ("Live", self.live),
            ("Specs", SpecsPanel),   # lazy: constructed on first visit
        ], parent)

    # forwarded so the window can pause telemetry while the HUD is hidden
    def set_paused(self, paused):
        self.live.set_paused(paused)
