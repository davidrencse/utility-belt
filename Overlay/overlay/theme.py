"""
Central design system for the overlay - one source of truth for colour,
type, spacing, radius and motion so every panel reads as one system.

Direction: OLED monochrome. Pure black glass, white ink, no hue anywhere -
severity and emphasis are carried by brightness and weight alone. Depth
comes from three stacked white-alpha layers (surface / raised / hover) and
hairline borders rather than drop shadows or colour.

Contrast (on the card body, ~#09090b): TEXT 18.9:1, TEXT_MUTED 8.1:1,
TEXT_DIM 4.9:1 - every text token clears WCAG AA for its size.

Motion lives next to colour on purpose: springs and durations are tokens
too (see SPRING_* / DUR_*), consumed by motion.py.
"""
from PySide6.QtGui import QColor, QFontDatabase

# ---------------------------------------------------------------- palette --
# surfaces (opaque, so hexs() stays exact; they read as white-alpha layers
# over the ~#09090b card body)
BG           = QColor(9, 9, 11)
BG_CARD      = QColor(9, 9, 11, 238)
SURFACE      = QColor(17, 17, 19)          # inputs, rows, tracks
SURFACE_2    = QColor(24, 24, 27)          # raised chips, header cells
SURFACE_HOVER= QColor(34, 34, 38)
BORDER       = QColor(39, 39, 42)          # control outlines
BORDER_STRONG= QColor(82, 82, 91)          # hover / focus outlines
BORDER_SOFT  = QColor(255, 255, 255, 14)
HAIRLINE     = QColor(255, 255, 255, 20)

# text
TEXT         = QColor(250, 250, 250)
TEXT_MUTED   = QColor(161, 161, 170)
TEXT_DIM     = QColor(120, 120, 128)

# "accent" is white; ink on top of it is near-black
ACCENT       = QColor(250, 250, 250)
ACCENT_INK   = QColor(9, 9, 11)
ACCENT_SOFT  = QColor(255, 255, 255, 30)
# status by brightness: normal = mid grey, elevated = light, critical = white
POSITIVE     = QColor(190, 190, 196)
WARN         = QColor(228, 228, 231)
DANGER       = QColor(255, 255, 255)

# graph series - three distinguishable greys
G_CPU        = QColor(212, 212, 216)
G_PING       = QColor(250, 250, 250)
G_NET        = QColor(140, 140, 148)

# ----------------------------------------------------------------- radius --
R_CARD = 14
R_CTRL = 8
R_CHIP = 6
R_PILL = 999

# ---------------------------------------------------------------- spacing --
# 4px base grid (dense dashboard scale)
S1, S2, S3, S4, S5, S6 = 4, 8, 12, 16, 20, 24

# ----------------------------------------------------------------- motion --
# Springs are (stiffness, damping, mass) - same model as Framer Motion's
# `type: "spring"`. SNAPPY for indicators/knobs, SOFT for panels & values,
# GENTLE for data that should glide rather than jump.
SPRING_SNAPPY = (520, 40, 1.0)
SPRING_SOFT   = (300, 30, 1.0)
SPRING_GENTLE = (140, 22, 1.0)
DUR_FAST = 110        # exits, hovers - exit is always faster than enter
DUR_BASE = 180        # enters, crossfades
DUR_SLOW = 260

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
    # Bahnschrift (DIN-style industrial sans, ships with Windows) gives the HUD
    # a technical identity; fall back to Segoe where it isn't present.
    UI = _first_installed(["Bahnschrift", "Segoe UI Variable", "Segoe UI"], "Segoe UI")
    DISPLAY = _first_installed(["Bahnschrift SemiBold", "Bahnschrift",
                               "Segoe UI Variable Display", "Segoe UI Semibold",
                               "Segoe UI"], "Segoe UI")


# ----------------------------------------------------------- qss helpers ---
def rgba(c: QColor):
    return f"rgba({c.red()},{c.green()},{c.blue()},{c.alpha()})"


def hexs(c: QColor):
    return f"#{c.red():02x}{c.green():02x}{c.blue():02x}"


def _asset(name):
    import os
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", name)
    return '"' + path.replace("\\", "/") + '"'


def label_qss(role="body"):
    """Typography roles so panels stop hand-rolling font strings."""
    roles = {
        "eyebrow": f"color:{hexs(TEXT_DIM)};font:700 7pt '{MONO}';letter-spacing:2px;",
        "caption": f"color:{hexs(TEXT_DIM)};font:8pt '{MONO}';",
        "body":    f"color:{hexs(TEXT)};font:9pt '{UI}';",
        "muted":   f"color:{hexs(TEXT_MUTED)};font:9pt '{UI}';",
        "value":   f"color:{hexs(TEXT)};font:600 9pt '{MONO}';",
        "title":   f"color:{hexs(TEXT)};font:600 12pt '{UI}';",
    }
    return roles[role] + "background:transparent;border:none;"


def input_qss(height=26):
    return (
        f"QLineEdit,QComboBox,QSpinBox{{background:{hexs(SURFACE)};color:{hexs(TEXT)};"
        f"border:1px solid {hexs(BORDER)};border-radius:{R_CTRL}px;"
        f"padding:3px 9px;min-height:{height}px;"
        f"font:9pt '{MONO}';selection-background-color:{hexs(ACCENT)};"
        f"selection-color:{hexs(ACCENT_INK)};}}"
        f"QLineEdit:hover,QComboBox:hover,QSpinBox:hover{{border:1px solid {hexs(BORDER_STRONG)};}}"
        f"QLineEdit:focus,QComboBox:focus,QSpinBox:focus{{border:1px solid {hexs(TEXT_MUTED)};"
        f"background:{hexs(SURFACE_2)};}}"
        f"QLineEdit:disabled,QComboBox:disabled,QSpinBox:disabled{{color:{hexs(TEXT_DIM)};}}"
        f"QComboBox::drop-down{{border:none;width:20px;}}"
        f"QComboBox::down-arrow{{image:url({_asset('chevron-down.svg')});width:10px;height:6px;}}"
        f"QComboBox QAbstractItemView{{background:{hexs(SURFACE_2)};color:{hexs(TEXT)};"
        f"border:1px solid {hexs(BORDER)};border-radius:{R_CTRL}px;padding:4px;"
        f"selection-background-color:{hexs(SURFACE_HOVER)};"
        f"selection-color:{hexs(TEXT)};outline:none;}}"
        f"QSpinBox::up-button,QSpinBox::down-button{{width:16px;border:none;"
        f"background:transparent;}}"
        f"QSpinBox::up-button:hover,QSpinBox::down-button:hover{{background:{hexs(SURFACE_HOVER)};"
        f"border-radius:4px;}}"
        f"QSpinBox::up-arrow{{image:url({_asset('chevron-up.svg')});width:8px;height:5px;}}"
        f"QSpinBox::down-arrow{{image:url({_asset('chevron-down.svg')});width:8px;height:5px;}}"
    )


def primary_btn_qss():
    return (
        f"QPushButton{{background:{hexs(ACCENT)};color:{hexs(ACCENT_INK)};border:none;"
        f"border-radius:{R_CTRL}px;padding:6px 18px;font:700 9pt '{UI}';letter-spacing:0.5px;}}"
        f"QPushButton:hover{{background:#ffffff;}}"
        f"QPushButton:pressed{{background:{hexs(QColor(212,212,216))};}}"
        f"QPushButton:focus{{outline:none;}}"
        f"QPushButton:disabled{{background:{hexs(SURFACE_2)};color:{hexs(TEXT_DIM)};}}"
    )


def ghost_btn_qss():
    return (
        f"QPushButton{{background:{hexs(SURFACE)};color:{hexs(TEXT_MUTED)};"
        f"border:1px solid {hexs(BORDER)};border-radius:{R_CTRL}px;"
        f"padding:5px 12px;font:600 8pt '{UI}';}}"
        f"QPushButton:hover{{background:{hexs(SURFACE_2)};color:{hexs(TEXT)};"
        f"border:1px solid {hexs(BORDER_STRONG)};}}"
        f"QPushButton:pressed{{background:{hexs(SURFACE_HOVER)};}}"
        f"QPushButton:checked{{background:{hexs(SURFACE_HOVER)};color:{hexs(TEXT)};"
        f"border:1px solid {hexs(TEXT_DIM)};}}"
        f"QPushButton:disabled{{color:{hexs(TEXT_DIM)};border:1px solid {hexs(SURFACE_2)};}}"
    )


def icon_btn_qss():
    return (
        f"QPushButton{{background:transparent;color:{hexs(TEXT_MUTED)};border:none;"
        f"border-radius:{R_CHIP}px;font:11pt '{UI}';padding:0;}}"
        f"QPushButton:hover{{background:{hexs(SURFACE_2)};color:{hexs(TEXT)};}}"
        f"QPushButton:pressed{{background:{hexs(SURFACE_HOVER)};}}"
    )


def checkbox_qss():
    return (
        f"QCheckBox{{color:{hexs(TEXT_MUTED)};font:600 8pt '{UI}';spacing:6px;"
        "background:transparent;}"
        f"QCheckBox:hover{{color:{hexs(TEXT)};}}"
        f"QCheckBox::indicator{{width:13px;height:13px;border-radius:4px;"
        f"border:1px solid {hexs(BORDER_STRONG)};background:{hexs(SURFACE)};}}"
        f"QCheckBox::indicator:hover{{border:1px solid {hexs(TEXT_MUTED)};}}"
        f"QCheckBox::indicator:checked{{background:{hexs(ACCENT)};"
        f"border:1px solid {hexs(ACCENT)};}}"
        f"QCheckBox::indicator:disabled{{background:{hexs(SURFACE_2)};"
        f"border:1px solid {hexs(BORDER)};}}"
    )


def slider_qss():
    return (
        "QSlider{background:transparent;min-height:18px;}"
        f"QSlider::groove:horizontal{{height:4px;background:{hexs(SURFACE_HOVER)};"
        "border-radius:2px;}"
        f"QSlider::sub-page:horizontal{{background:{hexs(TEXT_MUTED)};border-radius:2px;}}"
        "QSlider::handle:horizontal{width:14px;height:14px;margin:-5px 0;"
        f"border-radius:7px;background:{hexs(TEXT)};}}"
        "QSlider::handle:horizontal:hover{background:#ffffff;width:16px;height:16px;"
        "margin:-6px 0;border-radius:8px;}"
    )


def table_qss():
    return (
        f"QTableWidget{{background:{hexs(BG)};color:{hexs(TEXT)};"
        f"gridline-color:transparent;border:1px solid {hexs(BORDER)};"
        f"border-radius:{R_CTRL}px;font:9pt '{MONO}';"
        f"alternate-background-color:{rgba(QColor(255,255,255,5))};}}"
        f"QTableWidget::item{{padding:3px 8px;border:none;}}"
        f"QTableWidget::item:selected{{background:{rgba(ACCENT_SOFT)};color:{hexs(TEXT)};}}"
        f"QTableWidget::item:hover{{background:{rgba(QColor(255,255,255,12))};}}"
        f"QHeaderView{{background:transparent;border:none;}}"
        f"QHeaderView::section{{background:{hexs(SURFACE)};color:{hexs(TEXT_DIM)};"
        f"border:none;border-bottom:1px solid {hexs(BORDER)};padding:6px 8px;"
        f"font:700 7pt '{MONO}';letter-spacing:1.5px;}}"
        f"QTableCornerButton::section{{background:{hexs(SURFACE)};border:none;}}"
    )


def menu_qss():
    return (
        f"QMenu{{background:{hexs(SURFACE)};color:{hexs(TEXT)};"
        f"border:1px solid {hexs(BORDER)};border-radius:10px;padding:5px;"
        f"font:9pt '{UI}';}}"
        f"QMenu::item{{padding:6px 14px;border-radius:6px;background:transparent;}}"
        f"QMenu::item:selected{{background:{hexs(SURFACE_HOVER)};}}"
        f"QMenu::item:disabled{{color:{hexs(TEXT_DIM)};}}"
        f"QMenu::separator{{height:1px;background:{hexs(BORDER)};margin:4px 8px;}}"
    )


def scrollbar_qss():
    return (
        "QScrollBar:vertical{background:transparent;width:6px;margin:2px;}"
        f"QScrollBar::handle:vertical{{background:{hexs(BORDER)};border-radius:3px;"
        "min-height:28px;}"
        f"QScrollBar::handle:vertical:hover{{background:{hexs(BORDER_STRONG)};}}"
        "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}"
        "QScrollBar::add-page,QScrollBar::sub-page{background:transparent;}"
        "QScrollBar:horizontal{background:transparent;height:6px;margin:2px;}"
        f"QScrollBar::handle:horizontal{{background:{hexs(BORDER)};border-radius:3px;"
        "min-width:28px;}"
        f"QScrollBar::handle:horizontal:hover{{background:{hexs(BORDER_STRONG)};}}"
        "QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{width:0;}"
    )


def tooltip_qss():
    return (
        f"QToolTip{{background:{hexs(SURFACE_2)};color:{hexs(TEXT)};"
        f"border:1px solid {hexs(BORDER)};border-radius:6px;padding:4px 8px;"
        f"font:8pt '{UI}';}}"
    )


def app_qss():
    """Global chrome applied once on the QApplication."""
    return scrollbar_qss() + tooltip_qss() + menu_qss()
