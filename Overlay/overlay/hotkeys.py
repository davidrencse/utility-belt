r"""
Global, customizable hotkeys via Win32 RegisterHotKey, delivered through a Qt
native event filter (no third-party package, no admin rights). Works even
when the overlay is unfocused.

Bindings are data-driven: each action maps to a combo string like "alt+y" or
"ctrl+alt+left", stored in settings["hotkeys"] and editable in the Settings
tab. On any change the whole set is re-registered. The manager emits
`triggered(action_id)`; the app decides what each action does.
"""
import ctypes
import platform

from PySide6.QtCore import QAbstractNativeEventFilter, QObject, Signal

from .settings import settings

IS_WINDOWS = platform.system().lower().startswith("win")

WM_HOTKEY = 0x0312
MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN = 0x0001, 0x0002, 0x0004, 0x0008
MOD_NOREPEAT = 0x4000
_MODS = {"ctrl": MOD_CONTROL, "control": MOD_CONTROL, "alt": MOD_ALT,
         "shift": MOD_SHIFT, "win": MOD_WIN, "meta": MOD_WIN, "cmd": MOD_WIN}

# named keys -> virtual-key code
_NAMED = {
    "left": 0x25, "up": 0x26, "right": 0x27, "down": 0x28,
    "space": 0x20, "enter": 0x0D, "return": 0x0D, "tab": 0x09,
    "esc": 0x1B, "escape": 0x1B, "backspace": 0x08, "delete": 0x2E,
    "\\": 0xDC, "|": 0xDC, "[": 0xDB, "]": 0xDD, ";": 0xBA, "'": 0xDE,
    ",": 0xBC, ".": 0xBE, "/": 0xBF, "-": 0xBD, "=": 0xBB, "`": 0xC0,
}
for _i in range(1, 13):      # F1..F12
    _NAMED[f"f{_i}"] = 0x70 + (_i - 1)

# action id -> human label (order defines the Settings list)
ACTIONS = [
    ("toggle_visible", "Show / hide overlay"),
    ("cycle_tab", "Next tab"),
    ("capture", "Toggle screen-capture hiding"),
    ("click_through", "Toggle click-through"),
    ("panic", "Panic hide"),
    ("nudge_left", "Move left"),
    ("nudge_right", "Move right"),
    ("nudge_up", "Move up"),
    ("nudge_down", "Move down"),
]
ACTION_LABELS = dict(ACTIONS)


def parse_combo(combo):
    """"alt+y" -> (mods|NOREPEAT, vk) or None if unparseable."""
    if not combo:
        return None
    mods, vk = 0, None
    for part in str(combo).lower().replace(" ", "").split("+"):
        if not part:
            continue
        if part in _MODS:
            mods |= _MODS[part]
        elif part in _NAMED:
            vk = _NAMED[part]
        elif len(part) == 1 and (part.isalnum()):
            vk = ord(part.upper())
        else:
            return None
    if vk is None:
        return None
    return (mods | MOD_NOREPEAT, vk)


class HotkeyManager(QAbstractNativeEventFilter, QObject):
    triggered = Signal(str)   # action id

    def __init__(self, parent=None):
        QObject.__init__(self, parent)
        QAbstractNativeEventFilter.__init__(self)
        self._by_id = {}          # hotkey id -> action
        self._registered = False

    def _combos(self):
        saved = settings.get("hotkeys") or {}
        return {aid: saved.get(aid, "") for aid, _ in ACTIONS}

    def register(self):
        if not IS_WINDOWS:
            return False
        self.unregister()
        user32 = ctypes.windll.user32
        ok_any = False
        for i, (aid, combo) in enumerate(self._combos().items(), start=1):
            parsed = parse_combo(combo)
            if not parsed:
                continue
            mods, vk = parsed
            if user32.RegisterHotKey(None, i, mods, vk):
                self._by_id[i] = aid
                ok_any = True
        self._registered = ok_any
        return ok_any

    def unregister(self):
        if not IS_WINDOWS:
            return
        user32 = ctypes.windll.user32
        for hid in list(self._by_id):
            user32.UnregisterHotKey(None, hid)
        self._by_id.clear()
        self._registered = False

    def reregister(self):
        self.register()

    def nativeEventFilter(self, event_type, message):
        if IS_WINDOWS and event_type == b"windows_generic_MSG":
            msg = ctypes.wintypes.MSG.from_address(int(message))
            if msg.message == WM_HOTKEY:
                action = self._by_id.get(msg.wParam)
                if action:
                    self.triggered.emit(action)
        return False, 0


if IS_WINDOWS:
    import ctypes.wintypes  # noqa: E402,F401
