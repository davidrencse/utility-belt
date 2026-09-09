"""
Tiny reactive settings store for the overlay. Values persist to a JSON file
next to this module; changing one emits `changed(key, value)` so widgets can
react live (opacity, which graphs show, sample rate, stealth toggles, ...).

Use the module-level singleton:  from settings import settings
"""
import json
import os
import platform

from PySide6.QtCore import QObject, Signal

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_settings.json")
_IS_WINDOWS = platform.system().lower().startswith("win")

DEFAULTS = {
    # UI
    "card_opacity": 200,     # alpha of the card background, 110..245
    "graph_fill": True,      # filled sparklines vs. line only
    "show_cpu": True,
    "show_ping": True,
    "show_net": True,
    "start_tab": 0,          # tab shown on launch
    # behaviour / stealth
    "capture_exclusion": _IS_WINDOWS,
    "click_through": False,
    "always_on_top": True,
    # performance
    "sample_ms": 1000,       # telemetry cadence (500 / 1000 / 2000)
    # data
    "ping_target": "8.8.8.8",
    "vt_api_key": "",        # optional VirusTotal API key for inline stats
    # quick launch: list of {"label": str, "path": str}; path may be a folder,
    # a file, or an http(s) URL. Opened from the header menu.
    "shortcuts": [],
    # customizable global hotkeys (action id -> combo string, e.g. "alt+y").
    "hotkeys": {
        "toggle_visible": "alt+y",
        "cycle_tab": "alt+t",
        "capture": "ctrl+alt+x",
        "click_through": "ctrl+alt+c",
        "panic": "ctrl+alt+h",
        "nudge_left": "ctrl+alt+left",
        "nudge_right": "ctrl+alt+right",
        "nudge_up": "ctrl+alt+up",
        "nudge_down": "ctrl+alt+down",
    },
}


class Settings(QObject):
    changed = Signal(str, object)

    def __init__(self):
        super().__init__()
        self._d = dict(DEFAULTS)
        self._load()

    def _load(self):
        try:
            with open(_PATH, "r", encoding="utf-8") as f:
                saved = json.load(f)
            for k, v in saved.items():
                if k in DEFAULTS and isinstance(v, type(DEFAULTS[k])):
                    self._d[k] = v
        except (OSError, ValueError):
            pass

    def _save(self):
        try:
            with open(_PATH, "w", encoding="utf-8") as f:
                json.dump(self._d, f, indent=2)
        except OSError:
            pass

    def get(self, key):
        return self._d.get(key, DEFAULTS.get(key))

    def set(self, key, value):
        if self._d.get(key) == value:
            return
        self._d[key] = value
        self._save()
        self.changed.emit(key, value)


settings = Settings()
