"""
Central design system for the overlay - one source of truth for colour,
type, radius and spacing so every panel reads as one system.

Palette: a disciplined slate-on-black "data-dense dashboard" surface set with
a single neon-teal accent (the Cluely/Interview-Coder signature). Status
colours are deliberately slightly desaturated so a legitimately-full 94% disk
gauge reads as information, not an alarm.

Fonts resolve to the best thing actually installed on this box (checked at
import): Cascadia Mono for data/numerics, Segoe UI Variable for labels, with
graceful fallbacks.
"""
from PySide6.QtGui import QColor, QFontDatabase

# ---------------------------------------------------------------- palette --
# Monochrome: pure black-and-white. There is no hue anywhere - severity and
# emphasis are carried by brightness alone.
# surfaces
BG_CARD      = QColor(10, 10, 11, 238)     # the translucent card body
SURFACE      = QColor(20, 20, 21)          # inputs, rows, tracks
SURFACE_2    = QColor(28, 28, 30)          # raised chips, header cells
SURFACE_HOVER= QColor(40, 40, 42)
BORDER       = QColor(58, 58, 60)
BORDER_SOFT  = QColor(255, 255, 255, 16)
HAIRLINE     = QColor(255, 255, 255, 22)

# text
TEXT         = QColor(244, 244, 245)
TEXT_MUTED   = QColor(160, 160, 162)
TEXT_DIM     = QColor(102, 102, 105)

# "accent" is simply white; ink on top of it is near-black
ACCENT       = QColor(240, 240, 242)
ACCENT_INK   = QColor(10, 10, 11)
ACCENT_SOFT  = QColor(255, 255, 255, 34)
# status by brightness: normal = mid grey, elevated = light, critical = white
POSITIVE     = QColor(200, 200, 202)
WARN         = QColor(224, 224, 226)
DANGER       = QColor(255, 255, 255)

# graph series - three distinguishable greys
G_CPU        = QColor(210, 210, 212)
G_PING       = QColor(244, 244, 245)
G_NET        = QColor(150, 150, 152)

# ----------------------------------------------------------------- radius --
R_CARD = 16
R_CTRL = 7
R_CHIP = 5

# ------------------------------------------------------------------ fonts --
def _first_installed(candidates, fallback):
    fams = set(QFontDatabase.families())
    for c in candidates:
        if c in fams:
            return c
    return fallback

# Resolved once QApplication exists (call resolve_fonts() after app start).
MONO = "Consolas"
UI = "Segoe UI"
DISPLAY = "Segoe UI"


def resolve_fonts():
    global MONO, UI, DISPLAY
    MONO = _first_installed(["Cascadia Mono", "JetBrains Mono", "Consolas"], "Consolas")
    UI = _first_installed(["Segoe UI Variable", "Segoe UI"], "Segoe UI")
    DISPLAY = _first_installed(["Segoe UI Variable Display", "Segoe UI Semibold",
                               "Segoe UI"], "Segoe UI")


# ----------------------------------------------------------- qss helpers ---
def rgba(c: QColor):
    return f"rgba({c.red()},{c.green()},{c.blue()},{c.alpha()})"


def hexs(c: QColor):
    return f"#{c.red():02x}{c.green():02x}{c.blue():02x}"


def input_qss(height=26):
    return (
        f"QLineEdit,QComboBox,QSpinBox{{background:{hexs(SURFACE)};color:{hexs(TEXT)};"
        f"border:1px solid {hexs(BORDER)};border-radius:{R_CTRL}px;"
        f"padding:3px 8px;min-height:{height}px;"
        f"font:9pt '{MONO}';selection-background-color:{hexs(ACCENT)};"
        f"selection-color:{hexs(ACCENT_INK)};}}"
        f"QLineEdit:focus,QComboBox:focus,QSpinBox:focus{{border:1px solid {hexs(ACCENT)};}}"
        f"QLineEdit::placeholder{{color:{hexs(TEXT_DIM)};}}"
        f"QComboBox::drop-down{{border:none;width:16px;}}"
        f"QComboBox QAbstractItemView{{background:{hexs(SURFACE_2)};color:{hexs(TEXT)};"
        f"border:1px solid {hexs(BORDER)};selection-background-color:{hexs(ACCENT)};"
        f"selection-color:{hexs(ACCENT_INK)};outline:none;}}"
        f"QSpinBox::up-button,QSpinBox::down-button{{width:14px;border:none;"
        f"background:{hexs(SURFACE_2)};}}"
        f"QSpinBox::up-arrow,QSpinBox::down-arrow{{width:7px;height:7px;}}"
    )


def primary_btn_qss():
    return (
        f"QPushButton{{background:{hexs(ACCENT)};color:{hexs(ACCENT_INK)};border:none;"
        f"border-radius:{R_CTRL}px;padding:6px 20px;font:700 9pt '{UI}';}}"
        f"QPushButton:hover{{background:#ffffff;}}"
        f"QPushButton:pressed{{background:{hexs(QColor(200,200,202))};}}"
        f"QPushButton:disabled{{background:{hexs(SURFACE_2)};color:{hexs(TEXT_DIM)};}}"
    )


def ghost_btn_qss():
    return (
        f"QPushButton{{background:{hexs(SURFACE_2)};color:{hexs(TEXT_MUTED)};"
        f"border:1px solid {hexs(BORDER)};border-radius:{R_CTRL}px;"
        f"padding:5px 12px;font:600 8pt '{UI}';}}"
        f"QPushButton:hover{{background:{hexs(SURFACE_HOVER)};color:{hexs(TEXT)};"
        f"border:1px solid {hexs(ACCENT)};}}"
    )


def checkbox_qss():
    return (
        f"QCheckBox{{color:{hexs(TEXT_MUTED)};font:600 8pt '{UI}';spacing:5px;}}"
        f"QCheckBox:hover{{color:{hexs(TEXT)};}}"
        f"QCheckBox::indicator{{width:14px;height:14px;border-radius:4px;"
        f"border:1px solid {hexs(BORDER)};background:{hexs(SURFACE)};}}"
        f"QCheckBox::indicator:checked{{background:{hexs(ACCENT)};"
        f"border:1px solid {hexs(ACCENT)};}}"
    )


def table_qss():
    return (
        f"QTableWidget{{background:{hexs(QColor(8,11,15))};color:{hexs(TEXT)};"
        f"gridline-color:transparent;border:1px solid {hexs(BORDER)};"
        f"border-radius:{R_CTRL}px;font:9pt '{MONO}';"
        f"alternate-background-color:{rgba(QColor(255,255,255,6))};}}"
        f"QTableWidget::item{{padding:3px 6px;border:none;}}"
        f"QTableWidget::item:selected{{background:{rgba(ACCENT_SOFT)};color:{hexs(TEXT)};}}"
        f"QTableWidget::item:hover{{background:{rgba(QColor(255,255,255,14))};}}"
        f"QHeaderView::section{{background:{hexs(SURFACE_2)};color:{hexs(ACCENT)};"
        f"border:none;padding:5px 6px;font:700 8pt '{MONO}';letter-spacing:1px;}}"
        f"QTableCornerButton::section{{background:{hexs(SURFACE_2)};border:none;}}"
    )


def scrollbar_qss():
    return (
        "QScrollBar:vertical{background:transparent;width:8px;margin:2px;}"
        f"QScrollBar::handle:vertical{{background:{hexs(BORDER)};border-radius:4px;"
        "min-height:24px;}"
        f"QScrollBar::handle:vertical:hover{{background:{hexs(TEXT_DIM)};}}"
        "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}"
        "QScrollBar::add-page,QScrollBar::sub-page{background:transparent;}"
        "QScrollBar:horizontal{background:transparent;height:8px;margin:2px;}"
        f"QScrollBar::handle:horizontal{{background:{hexs(BORDER)};border-radius:4px;"
        "min-width:24px;}"
        "QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{width:0;}"
    )


def tooltip_qss():
    return (
        f"QToolTip{{background:{hexs(SURFACE_2)};color:{hexs(TEXT)};"
        f"border:1px solid {hexs(ACCENT)};border-radius:5px;padding:3px 7px;"
        f"font:8pt '{UI}';}}"
    )


def app_qss():
    """Global chrome applied once on the QApplication."""
    return scrollbar_qss() + tooltip_qss()
