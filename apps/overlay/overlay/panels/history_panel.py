"""
History container - things you captured while working: clipboard text and
screenshots. Reuses the shared SubTabHost.
"""
from ..subtabs import SubTabHost
from .clipboard_panel import ClipboardPanel
from .screenshot_panel import ScreenshotPanel


class HistoryPanel(SubTabHost):
    def __init__(self, take_screenshot=None, send_to_chat=None, parent=None):
        self.clipboard = ClipboardPanel()
        self.screenshots = ScreenshotPanel(take=take_screenshot,
                                           send_to_chat=send_to_chat)
        super().__init__([
            ("Clipboard", self.clipboard),
            ("Screenshots", self.screenshots),
        ], parent)

    def show_screenshots(self):
        self._select(1)
