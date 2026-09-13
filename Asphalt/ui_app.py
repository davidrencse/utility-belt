"""
Asphalt UI app (PySide6) that runs the full pipeline:
Capture -> Decode -> Display

Run:
  python ui_app.py
"""
import json
import os
import sys
import threading
import subprocess
import time
from datetime import datetime, timezone

try:
    from PySide6 import QtCore, QtWidgets, QtGui
except Exception as exc:
    raise SystemExit("PySide6 is required to run this UI. Install it with: pip install PySide6") from exc

try:
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    _HAS_MPL = True
except Exception:
    Figure = None
    FigureCanvas = None
    _HAS_MPL = False

def _resolve_project_root() -> str:
    """Return project root for both source and PyInstaller builds."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS  # type: ignore[attr-defined]
    return os.path.dirname(os.path.abspath(__file__))

PROJECT_ROOT = _resolve_project_root()
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from analysis.engine import AnalysisEngine
from analysis.registry import create_analyzer
from capture.decoder import PacketDecoder
from capture.icapture_backend import CaptureConfig
from models.packet import RawPacket
from pcap_loader.pcap_reader import PcapReader
from pcap_loader.pcapng_reader import PcapngReader


BG_MAIN = "#000000"
BG_PANEL = "#0a0a0a"
BG_HEADER = "#050505"
BG_CARD = "#101010"
FG_TEXT = "#ffffff"
FG_MUTED = "#c7c7c7"
ACCENT = "#ffffff"
ACCENT_BTN_BG = "#ffffff"
ACCENT_BTN_FG = "#000000"
WARN = "#e0e0e0"
GOOD = "#4caf50"
WARN_BADGE = "#ffb300"
BAD = "#e53935"
INFO_BADGE = "#9e9e9e"
BORDER_DARK = "#111111"
TITLEBAR_BG = "#050505"
TITLEBAR_BTN_BG = "#0d0d0d"
TITLEBAR_BTN_HOVER = "#1a1a1a"
TITLEBAR_BTN_DANGER = "#3a0c0c"
TITLEBAR_BTN_DANGER_HOVER = "#5a1414"

DROP_RATE_WARN = 1.0
DROP_RATE_BAD = 5.0
HANDSHAKE_WARN_LO = 85.0
HANDSHAKE_GOOD_LO = 95.0
RETX_WARN = 1.0
RETX_BAD = 3.0
RST_WARN = 1.0
RST_BAD = 3.0
SCAN_PORTS_WARN = 100
ARP_CONFLICT_WARN = 1
NXDOMAIN_SPIKE_WARN = True
ABNORMAL_RST_RATIO_THRESHOLD = 20.0

DEFAULT_ANALYZERS = [
    "capture_health",
    "global_stats",
    "protocol_mix",
    "flow_summary",
    "tcp_handshakes",
    "tcp_reliability",
    "tcp_performance",
    "abnormal_activity",
    "scan_signals",
    "arp_lan_signals",
    "dns_anomalies",
    "packet_chunks",
    "time_series",
    "throughput_peaks",
    "packet_size_stats",
    "l2_l3_breakdown",
    "top_entities",
    "flow_analytics",
]

REQUIRED_UI_ANALYZERS = {
    "global_stats",
    "capture_health",
    "tcp_reliability",
    "protocol_mix",
    "flow_analytics",
}

_PCAP_MAGIC = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def _extract_json_array(text: str):
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("No JSON array found in output")
    return json.loads(text[start:end + 1])


def _run_capture_direct(backend: str, interface: str, duration: int, limit: int):
    if backend != "scapy":
        raise RuntimeError("Only scapy backend is supported.")
    try:
        from capture.scapy_backend import ScapyBackend
    except Exception as exc:
        raise RuntimeError(f"Failed to import scapy backend: {exc}") from exc

    capture_backend = ScapyBackend()
    config = CaptureConfig(interface=interface, filter=None, buffer_size=10000)

    decoder = PacketDecoder()
    records = []
    decoded_count = 0
    start_time = datetime.now().timestamp()
    session_id = None

    try:
        session_id = capture_backend.start(config)
        idle_start = datetime.now().timestamp()
        while True:
            now = datetime.now().timestamp()
            if duration and (now - start_time) >= duration:
                break

            packets = capture_backend.get_packets(session_id, count=100)
            if not packets:
                time.sleep(0.01)
                # Avoid hanging forever when limit is set but no packets arrive
                if duration <= 0 and limit > 0 and (now - start_time) > 10:
                    break
                continue

            idle_start = now
            for pkt in packets:
                raw = RawPacket(
                    packet_id=decoded_count + 1,
                    timestamp_us=int(pkt["ts"] * 1_000_000),
                    captured_length=len(pkt["data"]),
                    original_length=pkt.get("wirelen", len(pkt["data"])),
                    link_type=1,
                    data=pkt["data"],
                    pcap_ref="live:0:0",
                )
                decoded = decoder.decode(raw)
                records.append(decoded.to_dict())
                decoded_count += 1
                if limit > 0 and decoded_count >= limit:
                    return records
    finally:
        if session_id:
            try:
                capture_backend.stop(session_id)
            except Exception:
                pass

    return records


def run_capture(backend: str, interface: str, duration: int, limit: int):
    env = os.environ.copy()
    env["PYTHONPATH"] = SRC_DIR

    cmd = [
        sys.executable,
        os.path.join(PROJECT_ROOT, "run.py"),
        "capture-decode",
        "--format",
        "json",
    ]

    if interface:
        cmd += ["--interface", interface]
    if duration > 0:
        cmd += ["--duration", str(duration)]
    if limit > 0:
        cmd += ["--limit", str(limit)]

    timeout = None
    if duration and duration > 0:
        timeout = duration + 10
    elif limit and limit > 0:
        timeout = 30

    try:
        # Prefer direct capture to avoid subprocess hangs.
        return _run_capture_direct("scapy", interface, duration, limit)
    except Exception:
        pass

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=PROJECT_ROOT, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("capture timed out") from exc
    if result.returncode != 0:
        msg = (result.stderr or result.stdout or "capture failed").strip()
        raise RuntimeError(msg)

    output = (result.stdout or "").strip()
    if not output:
        return []

    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return _extract_json_array(output)


def get_default_scapy_iface():
    try:
        from scapy.arch.windows import get_windows_if_list
    except Exception:
        return ""

    win_ifaces = get_windows_if_list()
    preferred = None
    for iface in win_ifaces:
        name = (iface.get("name") or "").lower()
        desc = (iface.get("description") or "").lower()
        ips = iface.get("ips") or []
        guid = iface.get("guid")
        if not guid or not ips:
            continue
        if "wi-fi" in name or "wireless" in desc:
            preferred = iface
            break
    if not preferred:
        for iface in win_ifaces:
            desc = (iface.get("description") or "").lower()
            ips = iface.get("ips") or []
            guid = iface.get("guid")
            if guid and ips and "wan miniport" not in desc:
                preferred = iface
                break
    if not preferred:
        return ""
    return rf"\Device\NPF_{preferred.get('guid')}"


def _select_reader(filepath: str):
    lower = filepath.lower()
    if lower.endswith(".pcapng"):
        return PcapngReader
    if lower.endswith(".pcap"):
        return PcapReader

    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
    except OSError as exc:
        raise RuntimeError(f"Failed to open file: {exc}") from exc

    if magic == _PCAPNG_MAGIC:
        return PcapngReader
    if magic in _PCAP_MAGIC:
        return PcapReader

    raise RuntimeError("Unsupported capture file format")


def _build_analyzers(
    analyzer_names,
    bucket_ms: int,
    chunk_size: int,
    scan_port_threshold: int,
    rst_ratio_threshold: float,
):
    analyzers = []
    for name in analyzer_names:
        if name == "time_series":
            analyzers.append(create_analyzer(name, bucket_ms=bucket_ms))
        elif name == "packet_chunks":
            analyzers.append(create_analyzer(name, chunk_size=chunk_size))
        elif name == "abnormal_activity":
            analyzers.append(create_analyzer(
                name,
                scan_port_threshold=scan_port_threshold,
                rst_ratio_threshold=rst_ratio_threshold,
            ))
        else:
            analyzers.append(create_analyzer(name))
    return analyzers


def _decode_capture_file(
    filepath: str,
    analyzer_names=None,
    bucket_ms: int = 1000,
    chunk_size: int = 200,
    scan_port_threshold: int = SCAN_PORTS_WARN,
    rst_ratio_threshold: float = 0.2,
):
    reader_cls = _select_reader(filepath)
    decoder = PacketDecoder()
    packets = []
    capture_info = {}

    analyzers = None
    engine = None
    if analyzer_names:
        analyzers = _build_analyzers(
            analyzer_names,
            bucket_ms=bucket_ms,
            chunk_size=chunk_size,
            scan_port_threshold=scan_port_threshold,
            rst_ratio_threshold=rst_ratio_threshold,
        )
        engine = AnalysisEngine(analyzers, capture_path=filepath, capture_info=capture_info)

    with reader_cls(filepath) as reader:
        try:
            capture_info = reader.get_session_info()
        except Exception:
            capture_info = {}
        if engine:
            engine.context.capture_info = capture_info or {}

        for packet in reader:
            decoded = decoder.decode(packet)
            record = decoded.to_dict()
            packets.append(record)
            if engine:
                engine.process_packet(decoded)

    analysis = engine.finalize().to_dict() if engine else {}
    return packets, analysis


def run_analysis(
    packets,
    bucket_ms: int = 1000,
    chunk_size: int = 200,
    scan_port_threshold: int = SCAN_PORTS_WARN,
    rst_ratio_threshold: float = 0.2,
):
    analyzers = _build_analyzers(
        DEFAULT_ANALYZERS,
        bucket_ms=bucket_ms,
        chunk_size=chunk_size,
        scan_port_threshold=scan_port_threshold,
        rst_ratio_threshold=rst_ratio_threshold,
    )
    engine = AnalysisEngine(analyzers)
    for packet in packets:
        engine.process_packet_dict(packet)
    return engine.finalize().to_dict()


def _fmt_number(value, digits=2):
    if value is None:
        return "n/a"
    try:
        return f"{float(value):.{digits}f}".rstrip("0").rstrip(".")
    except (TypeError, ValueError):
        return "n/a"


def _fmt_count(value):
    if value is None:
        return "n/a"
    try:
        return f"{int(round(float(value))):,}"
    except (TypeError, ValueError):
        return "n/a"


def _fmt_bps(value):
    if value is None:
        return "n/a"
    try:
        units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"]
        v = float(value)
        idx = 0
        while v >= 1000 and idx < len(units) - 1:
            v /= 1000
            idx += 1
        return f"{_fmt_number(v, 2)} {units[idx]}"
    except (TypeError, ValueError):
        return "n/a"


def _fmt_pps(value):
    if value is None:
        return "n/a"
    try:
        units = ["pps", "Kpps", "Mpps", "Gpps"]
        v = float(value)
        idx = 0
        while v >= 1000 and idx < len(units) - 1:
            v /= 1000
            idx += 1
        return f"{_fmt_number(v, 2)} {units[idx]}"
    except (TypeError, ValueError):
        return "n/a"


def _fmt_bytes(value):
    if value is None:
        return "n/a"
    try:
        units = ["B", "KB", "MB", "GB"]
        v = float(value)
        idx = 0
        while v >= 1024 and idx < len(units) - 1:
            v /= 1024
            idx += 1
        digits = 0 if idx == 0 else 2
        return f"{_fmt_number(v, digits)} {units[idx]}"
    except (TypeError, ValueError):
        return "n/a"


def _fmt_ts_utc(ts_us):
    if ts_us is None:
        return "n/a"
    try:
        dt = datetime.fromtimestamp(ts_us / 1_000_000)
        return dt.strftime("%I:%M:%S %p").lstrip("0")
    except (TypeError, ValueError, OSError):
        return "n/a"


def _fmt_pct(value):
    if value is None:
        return "n/a"
    try:
        return f"{float(value):.2f}%"
    except (TypeError, ValueError):
        return "n/a"


def _fmt_duration_us(value):
    if value is None:
        return "n/a"
    try:
        us = float(value)
        if us < 1_000:
            return f"{_fmt_number(us, 0)} us"
        if us < 1_000_000:
            return f"{_fmt_number(us / 1_000, 2)} ms"
        return f"{_fmt_number(us / 1_000_000, 2)} s"
    except (TypeError, ValueError):
        return "n/a"


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

class AsphaltApp(QtWidgets.QMainWindow):
    ui_call = QtCore.Signal(object)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Asphalt")
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.Window)
        self.resize(1280, 860)
        self.has_mpl = _HAS_MPL
        self._drag_pos = None

        self.latest_packets = []
        self.latest_analysis = {}
        self._packet_search_cache = []
        self._capture_stop_flag = threading.Event()
        self._last_capture_note = ""
        self._home_progress_timer = None
        self._capture_started_at = None
        self._capture_duration_s = 0
        self._home_progress_mode = "idle"

        self.ui_call.connect(lambda fn: fn())
        self._build_ui()

    def _build_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        outer = QtWidgets.QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        chrome = QtWidgets.QFrame()
        chrome.setObjectName("chrome")
        chrome_layout = QtWidgets.QVBoxLayout(chrome)
        chrome_layout.setContentsMargins(1, 1, 1, 1)
        chrome_layout.setSpacing(0)
        outer.addWidget(chrome)

        self.title_bar = self._build_title_bar()
        chrome_layout.addWidget(self.title_bar)

        # Initialize stat labels first (needed by info cards)
        self.stat_packets = self._value_label("0")
        self.stat_ip = self._value_label("0 / 0")
        self.stat_l4 = self._value_label("0 / 0")
        self.stat_flows = self._value_label("0")
        self.stat_rst = self._value_label("-")
        self.stat_drops = self._value_label("-")
        self.stat_top_proto = self._value_label("-")
        self.analysis_protocol = self._value_label("-")
        self.analysis_bytes = self._value_label("-")
        self.analysis_handshake = self._value_label("-")
        self.analysis_chunks = self._value_label("-")
        self.analysis_eth = self._value_label("-")
        self.analysis_dns = self._value_label("-")
        self.analysis_unique_ips = self._value_label("-")
        
        # Header Navigation (like reference image)
        header_nav = self._build_header_nav()
        chrome_layout.addWidget(header_nav)
        
        # Info Cards Row (restored to header)
        info_cards_row = self._build_info_cards_row()
        chrome_layout.addWidget(info_cards_row)

        body = QtWidgets.QFrame()
        body.setObjectName("body")
        body.setStyleSheet("""
            QFrame#body {
                background-color: %s;
                background-image: 
                    linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
                background-size: 40px 40px;
            }
        """ % BG_MAIN)
        body_layout = QtWidgets.QVBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)
        chrome_layout.addWidget(body, 1)

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent; border: none;")
        body_layout.addWidget(scroll)

        content = QtWidgets.QWidget()
        scroll.setWidget(content)
        root = QtWidgets.QVBoxLayout(content)
        root.setContentsMargins(40, 40, 40, 40)
        root.setSpacing(30)

        # Central Branding Section (like reference image)
        branding_section = self._build_branding_section()
        root.addWidget(branding_section, 0, QtCore.Qt.AlignCenter)

        # Home status text (capture state)
        self.home_status_label = QtWidgets.QLabel("CAPTURE UNINITIALIZED")
        self.home_status_label.setStyleSheet("""
            color: %s;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        """ % FG_MUTED)
        root.addWidget(self.home_status_label, 0, QtCore.Qt.AlignCenter)

        # Utilities Container - All utilities clearly visible
        utilities_container = QtWidgets.QWidget()
        utilities_layout = QtWidgets.QGridLayout(utilities_container)
        utilities_layout.setSpacing(20)
        
        # Capture Panel
        capture_panel = self._build_capture_panel()
        utilities_layout.addWidget(capture_panel, 0, 0)
        
        # Decode Panel
        decode_panel = self._build_decode_panel()
        utilities_layout.addWidget(decode_panel, 0, 1)
        
        # Analyze Panel
        analyze_panel = self._build_analyze_panel()
        utilities_layout.addWidget(analyze_panel, 0, 2)
        
        # Stats Panel
        stats_panel = self._build_stats_panel()
        utilities_layout.addWidget(stats_panel, 1, 0, 1, 3)
        
        root.addWidget(utilities_container)

        # OSI filter controls (for packet overview)
        self.osi_l2_eth = QtWidgets.QCheckBox("Ethernet")
        self.osi_l2_arp = QtWidgets.QCheckBox("ARP")
        self.osi_l3_ipv4 = QtWidgets.QCheckBox("IPv4")
        self.osi_l3_ipv6 = QtWidgets.QCheckBox("IPv6")
        self.osi_l4_tcp = QtWidgets.QCheckBox("TCP")
        self.osi_l4_udp = QtWidgets.QCheckBox("UDP")
        self.osi_app_dns = QtWidgets.QCheckBox("DNS")
        self.osi_clear_btn = QtWidgets.QPushButton("Clear")
        self.osi_clear_btn.setObjectName("overviewClearBtn")
        self.osi_clear_btn.setCursor(QtCore.Qt.PointingHandCursor)
        self.osi_clear_btn.setStyleSheet(
            "QPushButton { background-color: %s; color: %s; border: 1px solid %s; padding: 4px 10px; border-radius: 8px; }"
            % (ACCENT_BTN_BG, ACCENT_BTN_FG, BORDER_DARK)
        )

        # Packet overview section
        overview_box, overview_layout = self._make_section("PACKET OVERVIEW")
        overview_controls = QtWidgets.QHBoxLayout()
        overview_controls.addWidget(QtWidgets.QLabel("Group by"))
        self.group_ip_btn = QtWidgets.QPushButton("IP Version")
        self.group_ip_btn.setCheckable(True)
        self.group_l4_btn = QtWidgets.QPushButton("L4 Protocol")
        self.group_l4_btn.setCheckable(True)
        self.group_ip_btn.setChecked(True)
        group_buttons = QtWidgets.QButtonGroup(self)
        group_buttons.setExclusive(True)
        group_buttons.addButton(self.group_ip_btn)
        group_buttons.addButton(self.group_l4_btn)
        overview_btn_style = (
            "QPushButton { background-color: %s; color: %s; border: 1px solid %s; padding: 4px 10px; border-radius: 8px; }"
            "QPushButton:checked { background-color: %s; color: %s; }"
            % (BG_HEADER, FG_TEXT, BORDER_DARK, ACCENT_BTN_BG, ACCENT_BTN_FG)
        )
        self.group_ip_btn.setStyleSheet(overview_btn_style)
        self.group_l4_btn.setStyleSheet(overview_btn_style)
        overview_check_style = (
            "QCheckBox { color: %s; }"
            "QCheckBox::indicator { width: 14px; height: 14px; }"
            "QCheckBox::indicator:unchecked { background: %s; border: 1px solid %s; border-radius: 4px; }"
            "QCheckBox::indicator:checked { background: %s; border: 1px solid %s; border-radius: 4px; }"
            % (FG_TEXT, BG_HEADER, INFO_BADGE, ACCENT_BTN_BG, INFO_BADGE)
        )
        for cb in (
            self.osi_l2_eth, self.osi_l2_arp,
            self.osi_l3_ipv4, self.osi_l3_ipv6,
            self.osi_l4_tcp, self.osi_l4_udp,
            self.osi_app_dns,
        ):
            cb.setStyleSheet(overview_check_style)
        overview_controls.addWidget(self.group_ip_btn)
        overview_controls.addWidget(self.group_l4_btn)
        overview_controls.addSpacing(10)
        overview_controls.addWidget(self.osi_l2_eth)
        overview_controls.addWidget(self.osi_l2_arp)
        overview_controls.addWidget(self.osi_l3_ipv4)
        overview_controls.addWidget(self.osi_l3_ipv6)
        overview_controls.addWidget(self.osi_l4_tcp)
        overview_controls.addWidget(self.osi_l4_udp)
        overview_controls.addWidget(self.osi_app_dns)
        overview_controls.addWidget(self.osi_clear_btn)
        overview_controls.addStretch(1)
        overview_layout.addLayout(overview_controls)

        self.packet_overview = QtWidgets.QTreeWidget()
        self.packet_overview.setColumnCount(8)
        self.packet_overview.setHeaderLabels(["No.", "Time", "Source", "Destination", "Protocol", "Length", "OSI", "Info"])
        self.packet_overview.setRootIsDecorated(True)
        self.packet_overview.setAlternatingRowColors(True)
        self.packet_overview.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        self.packet_overview.setMinimumHeight(280)
        self._packet_overview_resized = False
        self._packet_overview_loaded_ids = set()
        self._packet_group_cache = {"ip": None, "l4": None}
        header = self.packet_overview.header()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QtWidgets.QHeaderView.ResizeToContents)
        self.packet_overview.setTextElideMode(QtCore.Qt.ElideNone)
        overview_layout.addWidget(self.packet_overview)
        root.addWidget(overview_box)

        # Tabs for detailed views
        self.main_tabs = QtWidgets.QTabWidget()
        self.main_tabs.setStyleSheet(
            "QTabWidget::pane { border: 0; }"
            "QTabBar::tab { background: %s; color: %s; padding: 6px 10px; }"
            "QTabBar::tab:selected { background: %s; color: %s; }" % (BG_HEADER, FG_TEXT, BG_PANEL, ACCENT)
        )
        root.addWidget(self.main_tabs, 1)

        self.raw_data_tab = QtWidgets.QWidget()
        self.tech_info_tab = QtWidgets.QWidget()
        self.dashboard_tab = QtWidgets.QWidget()
        self.packet_tab = QtWidgets.QWidget()

        self.main_tabs.addTab(self.raw_data_tab, "Raw Data")
        self.main_tabs.addTab(self.tech_info_tab, "Technical Information")
        self.main_tabs.addTab(self.dashboard_tab, "Dashboard")
        self.main_tabs.addTab(self.packet_tab, "Packets")

        self._build_raw_data_tab()
        self._build_technical_info_tab()
        self._build_dashboard_tab()
        self._build_packet_tab()
        
        # Footer (like reference image)
        footer = self._build_footer()
        chrome_layout.addWidget(footer)

        self._apply_theme()
        self._init_home_progress_timer()
        self.group_ip_btn.clicked.connect(lambda _checked=False: self.refresh_packet_overview())
        self.group_l4_btn.clicked.connect(lambda _checked=False: self.refresh_packet_overview())
        self.packet_overview.itemClicked.connect(self._on_packet_overview_click)
        self.packet_overview.itemExpanded.connect(self._on_packet_overview_expand)
        for cb in [
            self.osi_l2_eth, self.osi_l2_arp,
            self.osi_l3_ipv4, self.osi_l3_ipv6,
            self.osi_l4_tcp, self.osi_l4_udp,
            self.osi_app_dns,
        ]:
            cb.stateChanged.connect(self.refresh_packet_overview)
        self.osi_clear_btn.clicked.connect(self._clear_packet_overview_settings)

    def _build_header_nav(self):
        """Build header navigation in row/column layout."""
        nav_frame = QtWidgets.QFrame()
        nav_frame.setObjectName("headerNav")
        nav_frame.setFixedHeight(80)
        nav_frame.setStyleSheet("""
            QFrame#headerNav {
                background-color: %s;
                border-bottom: 1px solid %s;
            }
        """ % (BG_HEADER, BORDER_DARK))
        
        layout = QtWidgets.QHBoxLayout(nav_frame)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(30)
        
        # CAPTURE
        capture_label = QtWidgets.QLabel("CAPTURE")
        capture_label.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        """ % FG_TEXT)
        layout.addWidget(capture_label)
        
        # ANALYZE
        analyze_label = QtWidgets.QLabel("ANALYZE")
        analyze_label.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        """ % FG_TEXT)
        layout.addWidget(analyze_label)
        
        # UTILITIES
        utils_label = QtWidgets.QLabel("UTILITIES")
        utils_label.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        """ % FG_TEXT)
        layout.addWidget(utils_label)
        
        layout.addStretch()
        
        # SESSION
        session_label = QtWidgets.QLabel("SESSION [0]")
        session_label.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        """ % FG_TEXT)
        layout.addWidget(session_label)
        
        # Session grid (8 boxes)
        session_grid = QtWidgets.QWidget()
        grid_layout = QtWidgets.QGridLayout(session_grid)
        grid_layout.setSpacing(4)
        grid_layout.setContentsMargins(0, 0, 0, 0)
        self.session_boxes = []
        for i in range(8):
            box = QtWidgets.QFrame()
            box.setFixedSize(20, 20)
            box.setStyleSheet("background-color: %s; border: 1px solid %s;" % (BG_PANEL, BORDER_DARK))
            self.session_boxes.append(box)
            grid_layout.addWidget(box, i // 4, i % 4)
        layout.addWidget(session_grid)
        
        return nav_frame
    
    def _build_info_cards_row(self):
        """Build info cards in two rows in header."""
        cards_frame = QtWidgets.QFrame()
        cards_frame.setObjectName("infoCards")
        cards_frame.setStyleSheet("""
            QFrame#infoCards {
                background-color: %s;
                border-bottom: 1px solid %s;
            }
        """ % (BG_HEADER, BORDER_DARK))
        
        main_layout = QtWidgets.QVBoxLayout(cards_frame)
        main_layout.setContentsMargins(20, 10, 20, 10)
        main_layout.setSpacing(10)
        
        # First row
        row1 = QtWidgets.QHBoxLayout()
        row1.setSpacing(15)
        row1.addStretch()
        row1.addWidget(self._stat_block("Packets", self.stat_packets, width=150))
        row1.addWidget(self._stat_block("RST %%", self.stat_rst, width=150))
        row1.addWidget(self._stat_block("IPv4 / IPv6", self.stat_ip, width=150))
        row1.addWidget(self._stat_block("Drops", self.stat_drops, width=150))
        row1.addWidget(self._stat_block("TCP / UDP", self.stat_l4, width=150))
        row1.addWidget(self._stat_block("Top Protocol", self.stat_top_proto, width=150))
        row1.addWidget(self._stat_block("Flows", self.stat_flows, width=150))
        row1.addStretch()
        main_layout.addLayout(row1)
        
        # Second row
        row2 = QtWidgets.QHBoxLayout()
        row2.setSpacing(15)
        row2.addStretch()
        row2.addWidget(self._stat_block("Protocol Mix", self.analysis_protocol, width=150))
        row2.addWidget(self._stat_block("Ethernet Connections", self.analysis_eth, width=150))
        row2.addWidget(self._stat_block("Bytes Captured", self.analysis_bytes, width=150))
        row2.addWidget(self._stat_block("DNS Connections", self.analysis_dns, width=150))
        row2.addWidget(self._stat_block("TCP Handshakes", self.analysis_handshake, width=150))
        row2.addWidget(self._stat_block("Packet Chunks", self.analysis_chunks, width=150))
        row2.addWidget(self._stat_block("Unique IPs", self.analysis_unique_ips, width=150))
        row2.addStretch()
        main_layout.addLayout(row2)
        
        return cards_frame
    
    def _build_branding_section(self):
        """Build central branding section with L-bracket accents."""
        branding = QtWidgets.QFrame()
        branding.setObjectName("brandingSection")
        branding.setStyleSheet("""
            QFrame#brandingSection {
                background-color: %s;
                border: 2px solid %s;
                padding: 40px;
            }
        """ % (BG_PANEL, ACCENT))
        
        layout = QtWidgets.QVBoxLayout(branding)
        layout.setSpacing(10)
        layout.setAlignment(QtCore.Qt.AlignCenter)
        
        title = QtWidgets.QLabel("ASPHALT.NETWORK")
        title.setStyleSheet("""
            color: %s;
            font-size: 48px;
            font-weight: 700;
            letter-spacing: 4px;
            text-transform: uppercase;
        """ % FG_TEXT)
        layout.addWidget(title, 0, QtCore.Qt.AlignCenter)

        self.branding_progress = QtWidgets.QProgressBar()
        self.branding_progress.setRange(0, 100)
        self.branding_progress.setValue(0)
        self.branding_progress.setTextVisible(False)
        self.branding_progress.setFixedWidth(420)
        self.branding_progress.setFixedHeight(6)
        self.branding_progress.setStyleSheet("""
            QProgressBar {
                background-color: %s;
                border: 1px solid %s;
            }
            QProgressBar::chunk {
                background-color: %s;
            }
        """ % (BG_MAIN, BORDER_DARK, ACCENT))
        layout.addWidget(self.branding_progress, 0, QtCore.Qt.AlignCenter)
        
        tagline = QtWidgets.QLabel("IP.AXIS.NETWORK.DIAGNOSTICS")
        tagline.setStyleSheet("""
            color: %s;
            font-size: 14px;
            letter-spacing: 2px;
            text-transform: uppercase;
        """ % FG_MUTED)
        layout.addWidget(tagline, 0, QtCore.Qt.AlignCenter)
        
        return branding

    def _init_home_progress_timer(self):
        if self._home_progress_timer is not None:
            return
        self._home_progress_timer = QtCore.QTimer(self)
        self._home_progress_timer.setInterval(100)
        self._home_progress_timer.timeout.connect(self._update_home_progress)

    def _start_home_progress(self, duration_s: int, limit: int):
        if not hasattr(self, "branding_progress"):
            return
        self._capture_started_at = time.time()
        self._capture_duration_s = max(0, int(duration_s or 0))
        if self._capture_duration_s > 0:
            self._home_progress_mode = "time"
            self.branding_progress.setRange(0, 100)
            self.branding_progress.setValue(0)
        else:
            self._home_progress_mode = "busy"
            self.branding_progress.setRange(0, 0)  # indeterminate
        if self._home_progress_timer:
            self._home_progress_timer.start()

    def _stop_home_progress(self):
        if not hasattr(self, "branding_progress"):
            return
        if self._home_progress_timer:
            self._home_progress_timer.stop()
        if self._home_progress_mode == "time":
            self.branding_progress.setRange(0, 100)
            self.branding_progress.setValue(100)
        else:
            self.branding_progress.setRange(0, 100)
            self.branding_progress.setValue(100)
        self._home_progress_mode = "idle"

    def _update_home_progress(self):
        if not hasattr(self, "branding_progress"):
            return
        if self._home_progress_mode == "time":
            if not self._capture_started_at or self._capture_duration_s <= 0:
                return
            elapsed = time.time() - self._capture_started_at
            pct = int(min(100, max(0, (elapsed / self._capture_duration_s) * 100.0)))
            self.branding_progress.setValue(pct)
    
    def _build_capture_panel(self):
        """Build capture utility panel."""
        panel = QtWidgets.QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: %s;
                border: 1px solid %s;
            }
        """ % (BG_PANEL, BORDER_DARK))
        
        layout = QtWidgets.QVBoxLayout(panel)
        layout.setContentsMargins(20, 15, 20, 20)
        layout.setSpacing(15)
        
        header = QtWidgets.QLabel("CAPTURE")
        header.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 8px 0px;
            border-bottom: 1px solid %s;
        """ % (FG_TEXT, BORDER_DARK))
        layout.addWidget(header)
        
        # Interface
        iface_label = QtWidgets.QLabel("INTERFACE")
        iface_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(iface_label)
        default_iface = get_default_scapy_iface()
        self.interface_edit = QtWidgets.QLineEdit(default_iface)
        self.interface_edit.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        layout.addWidget(self.interface_edit)
        
        # Duration
        dur_label = QtWidgets.QLabel("DURATION (s)")
        dur_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(dur_label)
        self.duration_edit = QtWidgets.QLineEdit("10")
        self.duration_edit.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        layout.addWidget(self.duration_edit)
        
        # Limit
        limit_label = QtWidgets.QLabel("PACKET LIMIT")
        limit_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(limit_label)
        self.limit_edit = QtWidgets.QLineEdit("1000")
        self.limit_edit.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        layout.addWidget(self.limit_edit)
        
        # Filter
        filter_label = QtWidgets.QLabel("FILTER (BPF)")
        filter_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(filter_label)
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("tcp port 80")
        self.filter_edit.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        self.filter_edit.textChanged.connect(self.apply_filter)
        layout.addWidget(self.filter_edit)
        
        # Buttons
        btn_layout = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("START")
        self.start_btn.setStyleSheet("background-color: %s; color: %s; border: 1px solid %s; padding: 10px; font-weight: 600; text-transform: uppercase;" % (ACCENT_BTN_BG, ACCENT_BTN_FG, ACCENT))
        self.start_btn.clicked.connect(self.start_capture)
        btn_layout.addWidget(self.start_btn)
        
        self.stop_btn = QtWidgets.QPushButton("STOP")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("background-color: transparent; color: %s; border: 1px solid %s; padding: 10px; font-weight: 600; text-transform: uppercase;" % (FG_TEXT, BORDER_DARK))
        self.stop_btn.clicked.connect(self.stop_capture)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)
        
        # Status
        self.status_label = QtWidgets.QLabel("IDLE")
        self.status_label.setStyleSheet("color: %s; font-size: 11px;" % WARN)
        layout.addWidget(self.status_label)

        # Export
        export_layout = QtWidgets.QHBoxLayout()
        self.download_btn = QtWidgets.QPushButton("EXPORT CAPTURE")
        self.download_btn.setEnabled(False)
        self.download_btn.setStyleSheet("background-color: transparent; color: %s; border: 1px solid %s; padding: 8px; font-weight: 600; text-transform: uppercase;" % (FG_TEXT, BORDER_DARK))
        self.download_btn.clicked.connect(self.download_capture)
        export_layout.addWidget(self.download_btn)

        self.export_analysis_btn = QtWidgets.QPushButton("EXPORT ANALYSIS")
        self.export_analysis_btn.setEnabled(False)
        self.export_analysis_btn.setStyleSheet("background-color: transparent; color: %s; border: 1px solid %s; padding: 8px; font-weight: 600; text-transform: uppercase;" % (FG_TEXT, BORDER_DARK))
        self.export_analysis_btn.clicked.connect(self.export_analysis)
        export_layout.addWidget(self.export_analysis_btn)
        layout.addLayout(export_layout)
        
        return panel
    
    def _build_decode_panel(self):
        """Build decode utility panel."""
        panel = QtWidgets.QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: %s;
                border: 1px solid %s;
            }
        """ % (BG_PANEL, BORDER_DARK))
        
        layout = QtWidgets.QVBoxLayout(panel)
        layout.setContentsMargins(20, 15, 20, 20)
        layout.setSpacing(15)
        
        header = QtWidgets.QLabel("DECODE")
        header.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 8px 0px;
            border-bottom: 1px solid %s;
        """ % (FG_TEXT, BORDER_DARK))
        layout.addWidget(header)
        
        file_label = QtWidgets.QLabel("PCAP/PCAPNG FILE")
        file_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(file_label)
        
        file_layout = QtWidgets.QHBoxLayout()
        self.decode_file_edit = QtWidgets.QLineEdit()
        self.decode_file_edit.setPlaceholderText("Select file...")
        self.decode_file_edit.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        file_layout.addWidget(self.decode_file_edit)
        
        browse_btn = QtWidgets.QPushButton("BROWSE")
        browse_btn.setStyleSheet("background-color: %s; color: %s; border: 1px solid %s; padding: 8px; font-weight: 600; text-transform: uppercase;" % (ACCENT_BTN_BG, ACCENT_BTN_FG, ACCENT))
        browse_btn.clicked.connect(self._browse_decode_file)
        file_layout.addWidget(browse_btn)
        layout.addLayout(file_layout)
        
        format_label = QtWidgets.QLabel("OUTPUT FORMAT")
        format_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(format_label)
        self.format_combo = QtWidgets.QComboBox()
        self.format_combo.addItems(["JSON", "TABLE"])
        self.format_combo.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        layout.addWidget(self.format_combo)
        
        self.decode_btn = QtWidgets.QPushButton("DECODE")
        self.decode_btn.setStyleSheet("background-color: %s; color: %s; border: 1px solid %s; padding: 10px; font-weight: 600; text-transform: uppercase;" % (ACCENT_BTN_BG, ACCENT_BTN_FG, ACCENT))
        self.decode_btn.clicked.connect(self._decode_file)
        layout.addWidget(self.decode_btn)
        
        return panel
    
    def _build_analyze_panel(self):
        """Build analyze utility panel."""
        panel = QtWidgets.QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: %s;
                border: 1px solid %s;
            }
        """ % (BG_PANEL, BORDER_DARK))
        
        layout = QtWidgets.QVBoxLayout(panel)
        layout.setContentsMargins(20, 15, 20, 20)
        layout.setSpacing(15)
        
        header = QtWidgets.QLabel("ANALYZE")
        header.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 8px 0px;
            border-bottom: 1px solid %s;
        """ % (FG_TEXT, BORDER_DARK))
        layout.addWidget(header)
        
        file_label = QtWidgets.QLabel("PCAP/PCAPNG FILE")
        file_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(file_label)
        
        file_layout = QtWidgets.QHBoxLayout()
        self.analyze_file_edit = QtWidgets.QLineEdit()
        self.analyze_file_edit.setPlaceholderText("Select file...")
        self.analyze_file_edit.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        file_layout.addWidget(self.analyze_file_edit)
        
        browse_btn = QtWidgets.QPushButton("BROWSE")
        browse_btn.setStyleSheet("background-color: %s; color: %s; border: 1px solid %s; padding: 8px; font-weight: 600; text-transform: uppercase;" % (ACCENT_BTN_BG, ACCENT_BTN_FG, ACCENT))
        browse_btn.clicked.connect(self._browse_analyze_file)
        file_layout.addWidget(browse_btn)
        layout.addLayout(file_layout)
        
        analyzers_label = QtWidgets.QLabel("ANALYZERS")
        analyzers_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(analyzers_label)
        
        # Analyzers list (scrollable)
        from analysis.registry import list_analyzers
        analyzers_list = QtWidgets.QListWidget()
        analyzers_list.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        analyzers_list.setSelectionMode(QtWidgets.QAbstractItemView.MultiSelection)
        for analyzer in sorted(list_analyzers()):
            item = QtWidgets.QListWidgetItem(analyzer)
            item.setCheckState(QtCore.Qt.Checked)
            analyzers_list.addItem(item)
        analyzers_list.setMaximumHeight(150)
        layout.addWidget(analyzers_list)
        self.analyzers_list = analyzers_list
        
        bucket_label = QtWidgets.QLabel("BUCKET SIZE (ms)")
        bucket_label.setStyleSheet("color: %s; font-size: 11px; text-transform: uppercase;" % FG_MUTED)
        layout.addWidget(bucket_label)
        self.bucket_ms_edit = QtWidgets.QLineEdit("1000")
        self.bucket_ms_edit.setStyleSheet("background-color: %s; border: 1px solid %s; color: %s; padding: 8px;" % (BG_MAIN, BORDER_DARK, FG_TEXT))
        layout.addWidget(self.bucket_ms_edit)
        
        self.analyze_btn = QtWidgets.QPushButton("ANALYZE")
        self.analyze_btn.setStyleSheet("background-color: %s; color: %s; border: 1px solid %s; padding: 10px; font-weight: 600; text-transform: uppercase;" % (ACCENT_BTN_BG, ACCENT_BTN_FG, ACCENT))
        self.analyze_btn.clicked.connect(self._analyze_file)
        layout.addWidget(self.analyze_btn)
        
        return panel
    
    def _build_stats_panel(self):
        """Build top domains display panel."""
        panel = QtWidgets.QFrame()
        panel.setStyleSheet("""
            QFrame {
                background-color: %s;
                border: 1px solid %s;
            }
        """ % (BG_PANEL, BORDER_DARK))
        
        layout = QtWidgets.QVBoxLayout(panel)
        layout.setContentsMargins(20, 15, 20, 20)
        layout.setSpacing(15)
        
        header = QtWidgets.QLabel("STATISTICS")
        header.setStyleSheet("""
            color: %s;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 8px 0px;
            border-bottom: 1px solid %s;
        """ % (FG_TEXT, BORDER_DARK))
        layout.addWidget(header)
        
        stats_grid = QtWidgets.QGridLayout()
        stats_grid.setSpacing(20)
        
        # Placeholder stats (top domain + upload/download + empty slots)
        self.top_domain_labels = [
            self._value_label("-"),
            self._value_label("-"),
            self._value_label("-"),
            self._value_label("-"),
            self._value_label("-"),
            self._value_label("-"),
            self._value_label("-"),
            self._value_label("-"),
        ]

        stats_grid.addWidget(self._stat_block("TOP DOMAIN", self.top_domain_labels[0]), 0, 0)
        stats_grid.addWidget(self._stat_block("UPLOAD / DOWNLOAD", self.top_domain_labels[1]), 0, 1)
        stats_grid.addWidget(self._stat_block("DOWNLOAD / UPLOAD SPEED", self.top_domain_labels[2]), 0, 2)
        stats_grid.addWidget(self._stat_block("SEARCH QUERIES", self.top_domain_labels[3]), 0, 3)
        stats_grid.addWidget(self._stat_block("NETWORK QUALITY", self.top_domain_labels[4]), 1, 0)
        stats_grid.addWidget(self._stat_block("UNUSUAL PORTS", self.top_domain_labels[5]), 1, 1)
        stats_grid.addWidget(self._stat_block("TOP EXTERNAL IP", self.top_domain_labels[6]), 1, 2)
        stats_grid.addWidget(self._stat_block("—", self.top_domain_labels[7]), 1, 3)
        
        layout.addLayout(stats_grid)
        
        return panel
    
    def _build_footer_legacy(self):
        """Build footer like reference image."""
        footer = QtWidgets.QFrame()
        footer.setObjectName("footer")
        footer.setStyleSheet("""
            QFrame#footer {
                background-color: %s;
                border-top: 1px solid %s;
            }
        """ % (BG_HEADER, BORDER_DARK))
        
        layout = QtWidgets.QHBoxLayout(footer)
        layout.setContentsMargins(40, 15, 40, 15)
        layout.setSpacing(40)
        
        # Left: Logo and brand
        left_section = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left_section)
        left_layout.setSpacing(5)
        
        logo_label = QtWidgets.QLabel("⚙")
        logo_label.setStyleSheet("font-size: 24px;")
        left_layout.addWidget(logo_label)
        
        trademark_label = QtWidgets.QLabel("TRADEMARK")
        trademark_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase;" % FG_MUTED)
        left_layout.addWidget(trademark_label)
        
        brand_label = QtWidgets.QLabel("ASPHALT.NETWORK")
        brand_label.setStyleSheet("color: %s; font-size: 14px; font-weight: 600; text-transform: uppercase;" % FG_TEXT)
        left_layout.addWidget(brand_label)
        
        layout.addWidget(left_section)
        
        # Middle: Company info
        middle_section = QtWidgets.QWidget()
        middle_layout = QtWidgets.QVBoxLayout(middle_section)
        middle_layout.setSpacing(4)
        
        company_label = QtWidgets.QLabel("COMPANY")
        company_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase;" % FG_MUTED)
        middle_layout.addWidget(company_label)
        
        company_value = QtWidgets.QLabel("ASPHALT.NETWORK.STUDIO")
        company_value.setStyleSheet("color: %s; font-size: 11px;" % FG_TEXT)
        middle_layout.addWidget(company_value)
        
        date_label = QtWidgets.QLabel("DATE")
        date_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase; margin-top: 5px;" % FG_MUTED)
        middle_layout.addWidget(date_label)
        
        self.footer_date = QtWidgets.QLabel(datetime.now().strftime("%d/%m/%Y"))
        self.footer_date.setStyleSheet("color: %s; font-size: 11px;" % FG_TEXT)
        middle_layout.addWidget(self.footer_date)
        
        time_label = QtWidgets.QLabel("TIME")
        time_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase; margin-top: 5px;" % FG_MUTED)
        middle_layout.addWidget(time_label)
        
        self.footer_time = QtWidgets.QLabel(datetime.now().strftime("%H:%M:%S"))
        self.footer_time.setStyleSheet("color: %s; font-size: 11px;" % FG_TEXT)
        middle_layout.addWidget(self.footer_time)
        
        # Update time every second
        timer = QtCore.QTimer(self)
        timer.timeout.connect(lambda: self.footer_time.setText(datetime.now().strftime("%H:%M:%S")))
        timer.start(1000)
        
        layout.addWidget(middle_section)
        
        # Right: Description
        right_section = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_section)
        right_layout.setSpacing(4)
        
        desc_label = QtWidgets.QLabel("DESCRIPTION")
        desc_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase;" % FG_MUTED)
        right_layout.addWidget(desc_label)
        
        desc_text = QtWidgets.QLabel(
            "ASPHALT is a production-grade network diagnostics platform combining "
            "Wireshark-level packet capture capabilities with an opinionated analytics "
            "and diagnostics layer. It provides full-fidelity packet capture, real-time "
            "protocol decoding, configurable analysis pipelines, and a unified diagnostic UI."
        )
        desc_text.setStyleSheet("color: %s; font-size: 9px; line-height: 1.4;" % FG_MUTED)
        desc_text.setWordWrap(True)
        desc_text.setMaximumWidth(400)
        right_layout.addWidget(desc_text)
        
        layout.addWidget(right_section)
        
        # Far right: Copyright
        copyright_section = QtWidgets.QWidget()
        copyright_layout = QtWidgets.QVBoxLayout(copyright_section)
        copyright_layout.setSpacing(4)
        
        note_label = QtWidgets.QLabel("NOTE")
        note_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase;" % FG_MUTED)
        copyright_layout.addWidget(note_label)
        
        copyright_text = QtWidgets.QLabel(
            "CONTENTS OF THIS APPLICATION ARE THE PROPERTY OF ASPHALT.NETWORK.STUDIO. "
            "NO PART OF THIS SITE MAY BE REPRODUCED WITHOUT CONSENT. "
            "COPYRIGHT © 2024. ALL RIGHTS RESERVED."
        )
        copyright_text.setStyleSheet("color: %s; font-size: 9px; line-height: 1.4;" % FG_MUTED)
        copyright_text.setWordWrap(True)
        copyright_text.setMaximumWidth(300)
        copyright_layout.addWidget(copyright_text)
        
        layout.addWidget(copyright_section)
        layout.addStretch()
        
        return footer

    def _build_footer(self):
        """Build compact footer."""
        footer = QtWidgets.QFrame()
        footer.setObjectName("footer")
        footer.setStyleSheet("""
            QFrame#footer {
                background-color: %s;
                border-top: 1px solid %s;
            }
        """ % (BG_HEADER, BORDER_DARK))

        layout = QtWidgets.QHBoxLayout(footer)
        layout.setContentsMargins(40, 10, 40, 10)
        layout.setSpacing(30)

        left_section = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left_section)
        left_layout.setSpacing(4)

        date_label = QtWidgets.QLabel("DATE")
        date_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase;" % FG_MUTED)
        left_layout.addWidget(date_label)

        self.footer_date = QtWidgets.QLabel(datetime.now().strftime("%d/%m/%Y"))
        self.footer_date.setStyleSheet("color: %s; font-size: 11px;" % FG_TEXT)
        left_layout.addWidget(self.footer_date)

        time_label = QtWidgets.QLabel("TIME")
        time_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase; margin-top: 5px;" % FG_MUTED)
        left_layout.addWidget(time_label)

        self.footer_time = QtWidgets.QLabel(datetime.now().strftime("%H:%M:%S"))
        self.footer_time.setStyleSheet("color: %s; font-size: 11px;" % FG_TEXT)
        left_layout.addWidget(self.footer_time)

        timer = QtCore.QTimer(self)
        timer.timeout.connect(lambda: self.footer_time.setText(datetime.now().strftime("%H:%M:%S")))
        timer.start(1000)

        layout.addWidget(left_section)

        right_section = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_section)
        right_layout.setSpacing(4)

        desc_label = QtWidgets.QLabel("DESCRIPTION")
        desc_label.setStyleSheet("color: %s; font-size: 10px; text-transform: uppercase;" % FG_MUTED)
        right_layout.addWidget(desc_label)

        desc_text = QtWidgets.QLabel(
            "ASPHALT is a production-grade network diagnostics platform combining "
            "Wireshark-level packet capture capabilities with an opinionated analytics "
            "and diagnostics layer. It provides full-fidelity packet capture, real-time "
            "protocol decoding, configurable analysis pipelines, and a unified diagnostic UI."
        )
        desc_text.setStyleSheet("color: %s; font-size: 9px; line-height: 1.4;" % FG_MUTED)
        desc_text.setWordWrap(True)
        desc_text.setMaximumWidth(420)
        right_layout.addWidget(desc_text)

        layout.addWidget(right_section)
        layout.addStretch()

        return footer
    
    def _browse_decode_file(self):
        """Browse for decode file."""
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select PCAP/PCAPNG File", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        if file_path:
            self.decode_file_edit.setText(file_path)
    
    def _browse_analyze_file(self):
        """Browse for analyze file."""
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select PCAP/PCAPNG File", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        if file_path:
            self.analyze_file_edit.setText(file_path)
    
    def _decode_file(self):
        """Decode selected file."""
        file_path = (self.decode_file_edit.text() or "").strip()
        if not file_path:
            QtWidgets.QMessageBox.warning(self, "Error", "Please select a file")
            return

        if hasattr(self, "decode_btn"):
            self.decode_btn.setEnabled(False)
        if hasattr(self, "analyze_btn"):
            self.analyze_btn.setEnabled(False)

        self.status_label.setText(f"Decoding {os.path.basename(file_path)}...")
        thread = threading.Thread(target=self._decode_file_thread, args=(file_path,), daemon=True)
        thread.start()
    
    def _analyze_file(self):
        """Analyze selected file."""
        file_path = (self.analyze_file_edit.text() or "").strip()
        if not file_path:
            QtWidgets.QMessageBox.warning(self, "Error", "Please select a file")
            return
        
        selected_analyzers = []
        for i in range(self.analyzers_list.count()):
            item = self.analyzers_list.item(i)
            if item.checkState() == QtCore.Qt.Checked:
                selected_analyzers.append(item.text())
        
        if not selected_analyzers:
            QtWidgets.QMessageBox.warning(self, "Error", "Please select at least one analyzer")
            return
        
        bucket_ms = _safe_int(self.bucket_ms_edit.text()) or 1000

        if hasattr(self, "analyze_btn"):
            self.analyze_btn.setEnabled(False)
        if hasattr(self, "decode_btn"):
            self.decode_btn.setEnabled(False)

        self.status_label.setText(f"Analyzing {os.path.basename(file_path)}...")
        thread = threading.Thread(
            target=self._analyze_file_thread,
            args=(file_path, selected_analyzers, bucket_ms),
            daemon=True,
        )
        thread.start()

    def _decode_file_thread(self, file_path: str):
        try:
            thresholds = self._get_thresholds()
            packets, analysis = _decode_capture_file(
                file_path,
                analyzer_names=DEFAULT_ANALYZERS,
                bucket_ms=1000,
                chunk_size=200,
                scan_port_threshold=int(thresholds["scan_ports_warn"]),
                rst_ratio_threshold=float(thresholds["abnormal_rst_ratio"]) / 100.0,
            )
            self.latest_packets = packets
            self.latest_analysis = analysis
            self._packet_search_cache = self._build_packet_search_cache(packets)
            self._packet_search_cache_id = id(packets)
            self._packet_search_cache_len = len(packets)
            self.ui_call.emit(self.refresh_all)
            self.ui_call.emit(
                lambda: self.status_label.setText(f"Decoded {len(packets)} packets from file")
            )
        except Exception as exc:
            msg = str(exc)
            self.ui_call.emit(lambda: self.status_label.setText(msg))
            self.ui_call.emit(lambda: QtWidgets.QMessageBox.critical(self, "Decode failed", msg))
        finally:
            if hasattr(self, "decode_btn"):
                self.ui_call.emit(lambda: self.decode_btn.setEnabled(True))
            if hasattr(self, "analyze_btn"):
                self.ui_call.emit(lambda: self.analyze_btn.setEnabled(True))

    def _analyze_file_thread(self, file_path: str, selected_analyzers, bucket_ms: int):
        try:
            thresholds = self._get_thresholds()
            analyzer_names = list(dict.fromkeys(list(selected_analyzers) + list(REQUIRED_UI_ANALYZERS)))
            packets, analysis = _decode_capture_file(
                file_path,
                analyzer_names=analyzer_names,
                bucket_ms=bucket_ms,
                chunk_size=200,
                scan_port_threshold=int(thresholds["scan_ports_warn"]),
                rst_ratio_threshold=float(thresholds["abnormal_rst_ratio"]) / 100.0,
            )
            self.latest_packets = packets
            self.latest_analysis = analysis
            self._packet_search_cache = self._build_packet_search_cache(packets)
            self._packet_search_cache_id = id(packets)
            self._packet_search_cache_len = len(packets)
            self.ui_call.emit(self.refresh_all)
            self.ui_call.emit(
                lambda: self.status_label.setText(
                    f"Analyzed {len(packets)} packets with {len(selected_analyzers)} analyzers"
                )
            )
        except Exception as exc:
            msg = str(exc)
            self.ui_call.emit(lambda: self.status_label.setText(msg))
            self.ui_call.emit(lambda: QtWidgets.QMessageBox.critical(self, "Analyze failed", msg))
        finally:
            if hasattr(self, "analyze_btn"):
                self.ui_call.emit(lambda: self.analyze_btn.setEnabled(True))
            if hasattr(self, "decode_btn"):
                self.ui_call.emit(lambda: self.decode_btn.setEnabled(True))
    
    def _build_title_bar(self):
        bar = QtWidgets.QFrame()
        bar.setObjectName("titlebar")
        bar.setFixedHeight(36)

        layout = QtWidgets.QHBoxLayout(bar)
        layout.setContentsMargins(10, 0, 8, 0)
        layout.setSpacing(8)

        title = QtWidgets.QLabel("Asphalt")
        title.setObjectName("titlebarTitle")
        layout.addWidget(title)
        layout.addStretch(1)

        self.btn_min = QtWidgets.QPushButton("_")
        self.btn_min.setObjectName("titlebarBtn")
        self.btn_min.setFixedSize(36, 24)
        self.btn_min.clicked.connect(self.showMinimized)

        self.btn_max = QtWidgets.QPushButton("[]")
        self.btn_max.setObjectName("titlebarBtn")
        self.btn_max.setFixedSize(36, 24)
        self.btn_max.clicked.connect(self._toggle_max_restore)

        self.btn_close = QtWidgets.QPushButton("X")
        self.btn_close.setObjectName("titlebarClose")
        self.btn_close.setFixedSize(36, 24)
        self.btn_close.clicked.connect(self.close)

        layout.addWidget(self.btn_min)
        layout.addWidget(self.btn_max)
        layout.addWidget(self.btn_close)

        bar.mousePressEvent = self._titlebar_mouse_press
        bar.mouseMoveEvent = self._titlebar_mouse_move
        bar.mouseReleaseEvent = self._titlebar_mouse_release
        bar.mouseDoubleClickEvent = self._titlebar_mouse_double_click
        return bar

    def _toggle_max_restore(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()
        self._update_window_controls()

    def _update_window_controls(self):
        if self.isMaximized():
            self.btn_max.setText("O")
        else:
            self.btn_max.setText("[]")

    def _titlebar_mouse_press(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def _titlebar_mouse_move(self, event):
        if event.buttons() & QtCore.Qt.LeftButton and self._drag_pos is not None:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def _titlebar_mouse_release(self, event):
        self._drag_pos = None
        event.accept()

    def _titlebar_mouse_double_click(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            self._toggle_max_restore()
            event.accept()

    def changeEvent(self, event):
        if event.type() == QtCore.QEvent.WindowStateChange:
            self._update_window_controls()
        super().changeEvent(event)

    def _resolve_scapy_interface(self, requested):
        try:
            from capture.scapy_backend import ScapyBackend
        except Exception:
            return requested
        try:
            backend = ScapyBackend()
            interfaces = backend.list_interfaces()
        except Exception:
            return requested

        if not interfaces:
            return requested

        req = (requested or "").strip()
        if req and req.startswith(r"\Device\NPF_"):
            return req

        # Try match by display name / description / name
        for iface in interfaces:
            name = (iface.get("name") or "").strip()
            display = (iface.get("display_name") or "").strip()
            desc = (iface.get("description") or "").strip()
            if req and (req.lower() == name.lower() or req.lower() == display.lower() or req.lower() == desc.lower()):
                return name
            if req and req.lower() in desc.lower():
                return name

        # Fallback: first interface with IPs (non-loopback)
        for iface in interfaces:
            name = iface.get("name") or ""
            ips = iface.get("ips") or []
            if name.startswith(r"\Device\NPF_") and ips and "127.0.0.1" not in ips:
                return name

        # Final fallback: first NPF interface
        for iface in interfaces:
            name = iface.get("name") or ""
            if name.startswith(r"\Device\NPF_"):
                return name

        return requested

    def _list_scapy_interfaces(self):
        try:
            from capture.scapy_backend import ScapyBackend
        except Exception:
            return []
        try:
            backend = ScapyBackend()
            interfaces = backend.list_interfaces()
        except Exception:
            return []
        names = []
        for iface in interfaces:
            name = iface.get("name") or ""
            ips = iface.get("ips") or []
            if name.startswith(r"\Device\NPF_") and "127.0.0.1" not in ips:
                names.append(name)
        if not names:
            for iface in interfaces:
                name = iface.get("name") or ""
                if name.startswith(r"\Device\NPF_"):
                    names.append(name)
        return names

    def _apply_theme(self):
        palette = self.palette()
        palette.setColor(QtGui.QPalette.Window, QtGui.QColor(BG_MAIN))
        palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(FG_TEXT))
        palette.setColor(QtGui.QPalette.Base, QtGui.QColor(BG_PANEL))
        palette.setColor(QtGui.QPalette.Text, QtGui.QColor(FG_TEXT))
        palette.setColor(QtGui.QPalette.Button, QtGui.QColor(BG_PANEL))
        palette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor(FG_TEXT))
        self.setPalette(palette)
        self.setStyleSheet(
            "QFrame#chrome { background: %s; border: 1px solid %s; }"
            "QFrame#body { background: %s; }"
            "QFrame#titlebar { background: %s; }"
            "QLabel#titlebarTitle { color: %s; font-weight: 600; }"
            "QPushButton#titlebarBtn { background: %s; color: %s; border: 1px solid %s; }"
            "QPushButton#titlebarBtn:hover { background: %s; }"
            "QPushButton#titlebarClose { background: %s; color: %s; border: 1px solid %s; }"
            "QPushButton#titlebarClose:hover { background: %s; }"
            "QPushButton#overviewClearBtn { background: %s; color: %s; border: 1px solid %s; padding: 4px 10px; }"
            "QPushButton#overviewClearBtn:hover { background: %s; }"
            % (
                BG_MAIN,
                BORDER_DARK,
                BG_MAIN,
                TITLEBAR_BG,
                FG_TEXT,
                TITLEBAR_BTN_BG,
                FG_TEXT,
                BORDER_DARK,
                TITLEBAR_BTN_HOVER,
                TITLEBAR_BTN_DANGER,
                FG_TEXT,
                BORDER_DARK,
                TITLEBAR_BTN_DANGER_HOVER,
                ACCENT_BTN_BG,
                ACCENT_BTN_FG,
                BORDER_DARK,
                BG_CARD,
            )
        )

    def _get_global_totals(self, analysis):
        gs = analysis.get("global_results", {}).get("global_stats", {})
        totals = {}
        if isinstance(gs, dict):
            raw_totals = gs.get("totals")
            if isinstance(raw_totals, dict):
                totals.update(raw_totals)
            else:
                # normalize from flat keys
                if "packets_total" in gs:
                    totals["packets"] = gs.get("packets_total")
                if "bytes_captured_total" in gs:
                    totals["bytes_captured"] = gs.get("bytes_captured_total")
                if "bytes_original_total" in gs:
                    totals["bytes_original"] = gs.get("bytes_original_total")
                if "duration_us" in gs:
                    totals["duration_us"] = gs.get("duration_us")

            ip_versions = gs.get("ip_versions") or gs.get("distributions", {}).get("ip_versions")
            if isinstance(ip_versions, dict):
                totals["ipv4_packets"] = ip_versions.get("4") or ip_versions.get(4)
                totals["ipv6_packets"] = ip_versions.get("6") or ip_versions.get(6)

            l4 = gs.get("l4_protocols") or gs.get("distributions", {}).get("l4_protocols")
            if isinstance(l4, dict):
                totals["tcp_packets"] = l4.get("TCP") or l4.get("tcp")
                totals["udp_packets"] = l4.get("UDP") or l4.get("udp")

        # fallback to engine stats
        stats = analysis.get("stats", {})
        if isinstance(stats, dict):
            totals.setdefault("packets", stats.get("packets_total"))
            totals.setdefault("bytes_captured", stats.get("bytes_captured_total"))
            totals.setdefault("bytes_original", stats.get("bytes_original_total"))
            totals.setdefault("duration_us", stats.get("duration_us"))

        return totals

    def _compute_totals_from_packets(self, packets):
        totals = {
            "packets": 0,
            "bytes_captured": 0,
            "bytes_original": 0,
            "ipv4_packets": 0,
            "ipv6_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "duration_us": 0,
        }
        if not packets:
            return totals

        first_ts = None
        last_ts = None
        for pkt in packets:
            if not isinstance(pkt, dict):
                continue
            totals["packets"] += 1
            totals["bytes_captured"] += int(pkt.get("captured_length") or 0)
            totals["bytes_original"] += int(pkt.get("original_length") or 0)
            ip_version = pkt.get("ip_version")
            if ip_version == 4:
                totals["ipv4_packets"] += 1
            elif ip_version == 6:
                totals["ipv6_packets"] += 1
            l4 = (pkt.get("l4_protocol") or "").upper()
            if l4 == "TCP" or pkt.get("ip_protocol") == 6:
                totals["tcp_packets"] += 1
            elif l4 == "UDP" or pkt.get("ip_protocol") == 17:
                totals["udp_packets"] += 1
            ts = pkt.get("timestamp_us")
            if ts is None:
                continue
            try:
                ts_val = int(ts)
            except (TypeError, ValueError):
                continue
            if first_ts is None or ts_val < first_ts:
                first_ts = ts_val
            if last_ts is None or ts_val > last_ts:
                last_ts = ts_val

        if first_ts is not None and last_ts is not None:
            totals["duration_us"] = max(0, last_ts - first_ts)
        return totals

    def _label(self, text):
        label = QtWidgets.QLabel(text)
        label.setStyleSheet("color: %s;" % FG_MUTED)
        return label

    def _value_label(self, text=""):
        label = QtWidgets.QLabel(text)
        label.setStyleSheet("color: %s; font-weight: 600;" % FG_TEXT)
        label.setWordWrap(True)
        return label

    def _stat_block(self, title, value_label, width=None):
        frame = QtWidgets.QFrame()
        frame.setStyleSheet("background-color: %s;" % BG_PANEL)
        if width:
            frame.setFixedWidth(width)
        layout = QtWidgets.QVBoxLayout(frame)
        layout.setContentsMargins(8, 6, 8, 6)
        title_label = QtWidgets.QLabel(title)
        title_label.setStyleSheet("color: %s;" % FG_MUTED)
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        return frame

    def _make_section(self, title):
        box = QtWidgets.QGroupBox(title)
        box.setStyleSheet("""
            QGroupBox {
                color: %s;
                font-weight: 600;
                font-size: 12px;
                text-transform: uppercase;
                border: 1px solid %s;
                margin-top: 6px;
                background-color: %s;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 4px;
                color: %s;
                font-weight: 600;
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
        """ % (FG_TEXT, BORDER_DARK, BG_PANEL, FG_TEXT))
        layout = QtWidgets.QVBoxLayout(box)
        layout.setContentsMargins(10, 10, 10, 10)
        return box, layout

    def _make_scroll_page(self):
        page = QtWidgets.QWidget()
        outer = QtWidgets.QVBoxLayout(page)
        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)
        content = QtWidgets.QWidget()
        scroll.setWidget(content)
        vbox = QtWidgets.QVBoxLayout(content)
        vbox.setContentsMargins(10, 10, 10, 10)
        vbox.setSpacing(10)
        return page, vbox

    def _make_kv_table(self, min_rows=10):
        table = QtWidgets.QTableWidget(0, 2)
        table.setHorizontalHeaderLabels(["Key", "Value"])
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        table.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        table.setMinimumHeight(min_rows * 24 + 32)
        return table

    def _make_table(self, columns, min_rows=10):
        table = QtWidgets.QTableWidget(0, len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        table.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        table.setMinimumHeight(min_rows * 24 + 32)
        return table

    def _set_kv_rows(self, table, rows):
        table.setRowCount(0)
        for row in rows:
            r = table.rowCount()
            table.insertRow(r)
            table.setItem(r, 0, QtWidgets.QTableWidgetItem(str(row[0])))
            table.setItem(r, 1, QtWidgets.QTableWidgetItem(str(row[1])))

    def _set_dynamic_rows(self, table, items, columns=None):
        if columns is None:
            keys = set()
            for item in items:
                if isinstance(item, dict):
                    keys.update(item.keys())
            columns = sorted(keys) if keys else ["value"]
        table.setColumnCount(len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.setRowCount(0)
        for item in items:
            r = table.rowCount()
            table.insertRow(r)
            if isinstance(item, dict):
                for idx, col in enumerate(columns):
                    table.setItem(r, idx, QtWidgets.QTableWidgetItem(str(item.get(col, ""))))
            else:
                table.setItem(r, 0, QtWidgets.QTableWidgetItem(str(item)))

    def _set_json_text(self, editor, obj):
        try:
            editor.setPlainText(json.dumps(obj, indent=2))
        except Exception:
            editor.setPlainText(str(obj))

    def _make_json_panel(self, title):
        box, layout = self._make_section(title)
        editor = QtWidgets.QPlainTextEdit()
        editor.setReadOnly(True)
        editor.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        layout.addWidget(QtWidgets.QLabel("Complete analyzer output for verification and debugging."))
        layout.addWidget(editor)
        return box, editor
    def _build_raw_data_tab(self):
        layout = QtWidgets.QVBoxLayout(self.raw_data_tab)
        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)

        content = QtWidgets.QWidget()
        scroll.setWidget(content)
        vbox = QtWidgets.QVBoxLayout(content)
        vbox.setContentsMargins(10, 10, 10, 10)
        vbox.setSpacing(10)

        self.raw_cards = {}

        # Capture health
        box, box_layout = self._make_section("Capture health and integrity")
        grid = QtWidgets.QGridLayout()
        box_layout.addLayout(grid)
        self.raw_cards["capture_quality"] = self._info_card_var("Capture Quality")
        self.raw_cards["decode_health"] = self._info_card_var("Decode Health")
        self.raw_cards["filtering"] = self._info_card_var("Filtering and Sampling")
        grid.addWidget(self.raw_cards["capture_quality"], 0, 0)
        grid.addWidget(self.raw_cards["decode_health"], 0, 1)
        grid.addWidget(self.raw_cards["filtering"], 0, 2)
        vbox.addWidget(box)

        # Thresholds
        box, box_layout = self._make_section("Thresholds")
        form = QtWidgets.QFormLayout()
        form.setLabelAlignment(QtCore.Qt.AlignLeft)
        form.setFormAlignment(QtCore.Qt.AlignTop)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(6)
        box_layout.addLayout(form)

        self.threshold_inputs = {}
        self.threshold_inputs["drop_warn"] = self._make_threshold_spin(DROP_RATE_WARN, 0, 100, 0.1, 2)
        form.addRow(self._label("Drop rate warn (%)"), self.threshold_inputs["drop_warn"])
        self.threshold_inputs["drop_bad"] = self._make_threshold_spin(DROP_RATE_BAD, 0, 100, 0.1, 2)
        form.addRow(self._label("Drop rate bad (%)"), self.threshold_inputs["drop_bad"])
        self.threshold_inputs["handshake_warn"] = self._make_threshold_spin(HANDSHAKE_WARN_LO, 0, 100, 0.5, 2)
        form.addRow(self._label("Handshake warn >= (%)"), self.threshold_inputs["handshake_warn"])
        self.threshold_inputs["handshake_good"] = self._make_threshold_spin(HANDSHAKE_GOOD_LO, 0, 100, 0.5, 2)
        form.addRow(self._label("Handshake good >= (%)"), self.threshold_inputs["handshake_good"])
        self.threshold_inputs["retrans_warn"] = self._make_threshold_spin(RETX_WARN, 0, 100, 0.1, 2)
        form.addRow(self._label("Retransmission warn (%)"), self.threshold_inputs["retrans_warn"])
        self.threshold_inputs["retrans_bad"] = self._make_threshold_spin(RETX_BAD, 0, 100, 0.1, 2)
        form.addRow(self._label("Retransmission bad (%)"), self.threshold_inputs["retrans_bad"])
        self.threshold_inputs["rst_warn"] = self._make_threshold_spin(RST_WARN, 0, 100, 0.1, 2)
        form.addRow(self._label("RST warn (%)"), self.threshold_inputs["rst_warn"])
        self.threshold_inputs["rst_bad"] = self._make_threshold_spin(RST_BAD, 0, 100, 0.1, 2)
        form.addRow(self._label("RST bad (%)"), self.threshold_inputs["rst_bad"])
        self.threshold_inputs["scan_ports_warn"] = self._make_threshold_int(SCAN_PORTS_WARN, 1, 100000, 1)
        form.addRow(self._label("Scan ports warn (count)"), self.threshold_inputs["scan_ports_warn"])
        self.threshold_inputs["arp_conflict_warn"] = self._make_threshold_int(ARP_CONFLICT_WARN, 0, 100000, 1)
        form.addRow(self._label("ARP conflict warn (count)"), self.threshold_inputs["arp_conflict_warn"])
        self.threshold_inputs["nxdomain_warn"] = QtWidgets.QCheckBox("Enable NXDOMAIN spike warning")
        self.threshold_inputs["nxdomain_warn"].setChecked(bool(NXDOMAIN_SPIKE_WARN))
        form.addRow(self._label("NXDOMAIN spike warn"), self.threshold_inputs["nxdomain_warn"])
        self.threshold_inputs["abnormal_rst_ratio"] = self._make_threshold_spin(ABNORMAL_RST_RATIO_THRESHOLD, 0, 100, 0.5, 2)
        form.addRow(self._label("Abnormal RST ratio threshold (%)"), self.threshold_inputs["abnormal_rst_ratio"])
        vbox.addWidget(box)

        # Traffic overview
        box, box_layout = self._make_section("Traffic overview")
        grid = QtWidgets.QGridLayout()
        box_layout.addLayout(grid)
        self.raw_cards["throughput"] = self._info_card_var("Throughput")
        self.raw_cards["packet_sizes"] = self._info_card_var("Packet Size Stats")
        self.raw_cards["l2l3"] = self._info_card_var("L2/L3 Breakdown")
        grid.addWidget(self.raw_cards["throughput"], 0, 0)
        grid.addWidget(self.raw_cards["packet_sizes"], 0, 1)
        grid.addWidget(self.raw_cards["l2l3"], 0, 2)
        vbox.addWidget(box)

        # Top entities
        box, box_layout = self._make_section("Top entities")
        grid = QtWidgets.QGridLayout()
        box_layout.addLayout(grid)
        self.raw_cards["top_talkers"] = self._info_card_var("Top Talkers")
        self.raw_cards["top_macs"] = self._info_card_var("Top MAC Addresses")
        self.raw_cards["top_ports"] = self._info_card_var("Top Ports and Services")
        grid.addWidget(self.raw_cards["top_talkers"], 0, 0)
        grid.addWidget(self.raw_cards["top_macs"], 0, 1)
        grid.addWidget(self.raw_cards["top_ports"], 0, 2)
        vbox.addWidget(box)

        # Flow analytics
        box, box_layout = self._make_section("Flow analytics")
        grid = QtWidgets.QGridLayout()
        box_layout.addLayout(grid)
        self.raw_cards["flow_summary"] = self._info_card_var("Flow Summary")
        self.raw_cards["flow_heavy"] = self._info_card_var("Heavy Hitters")
        self.raw_cards["flow_states"] = self._info_card_var("Flow States")
        grid.addWidget(self.raw_cards["flow_summary"], 0, 0)
        grid.addWidget(self.raw_cards["flow_heavy"], 0, 1)
        grid.addWidget(self.raw_cards["flow_states"], 0, 2)
        vbox.addWidget(box)

        # TCP health
        box, box_layout = self._make_section("TCP health")
        grid = QtWidgets.QGridLayout()
        box_layout.addLayout(grid)
        self.raw_cards["tcp_handshake"] = self._info_card_var("TCP Handshakes")
        self.raw_cards["tcp_reliability"] = self._info_card_var("TCP Reliability")
        self.raw_cards["tcp_performance"] = self._info_card_var("TCP Performance")
        grid.addWidget(self.raw_cards["tcp_handshake"], 0, 0)
        grid.addWidget(self.raw_cards["tcp_reliability"], 0, 1)
        grid.addWidget(self.raw_cards["tcp_performance"], 0, 2)
        vbox.addWidget(box)

        # Security signals
        box, box_layout = self._make_section("Security signals")
        grid = QtWidgets.QGridLayout()
        box_layout.addLayout(grid)
        self.raw_cards["scan_signals"] = self._info_card_var("Scan Signals")
        self.raw_cards["arp_lan"] = self._info_card_var("ARP / LAN Signals")
        self.raw_cards["dns_anomalies"] = self._info_card_var("DNS Anomalies")
        grid.addWidget(self.raw_cards["scan_signals"], 0, 0)
        grid.addWidget(self.raw_cards["arp_lan"], 0, 1)
        grid.addWidget(self.raw_cards["dns_anomalies"], 0, 2)
        vbox.addWidget(box)

        # Other analyzers (fallback)
        box, box_layout = self._make_section("Other analyzers")
        self.raw_other_table = self._make_kv_table(min_rows=12)
        box_layout.addWidget(self.raw_other_table)
        vbox.addWidget(box)

        vbox.addStretch(1)

    def _info_card_var(self, title):
        frame = QtWidgets.QFrame()
        frame.setStyleSheet("background-color: %s;" % BG_CARD)
        layout = QtWidgets.QVBoxLayout(frame)
        layout.setContentsMargins(8, 8, 8, 8)
        label = QtWidgets.QLabel(title)
        label.setStyleSheet("color: %s; font-weight: 600;" % FG_MUTED)
        value = QtWidgets.QLabel("-")
        value.setWordWrap(True)
        value.setStyleSheet("color: %s;" % FG_TEXT)
        layout.addWidget(label)
        layout.addWidget(value)
        frame.value_label = value
        return frame

    def _make_threshold_spin(self, value, minimum, maximum, step, decimals):
        spin = QtWidgets.QDoubleSpinBox()
        spin.setRange(minimum, maximum)
        spin.setDecimals(decimals)
        spin.setSingleStep(step)
        spin.setValue(float(value))
        spin.setFixedWidth(140)
        return spin

    def _make_threshold_int(self, value, minimum, maximum, step):
        spin = QtWidgets.QSpinBox()
        spin.setRange(minimum, maximum)
        spin.setSingleStep(step)
        spin.setValue(int(value))
        spin.setFixedWidth(140)
        return spin

    def _get_thresholds(self):
        def get_value(key, default):
            widget = getattr(self, "threshold_inputs", {}).get(key)
            if widget is None:
                return default
            if isinstance(widget, QtWidgets.QCheckBox):
                return widget.isChecked()
            try:
                return widget.value()
            except Exception:
                return default

        return {
            "drop_warn": get_value("drop_warn", DROP_RATE_WARN),
            "drop_bad": get_value("drop_bad", DROP_RATE_BAD),
            "handshake_warn": get_value("handshake_warn", HANDSHAKE_WARN_LO),
            "handshake_good": get_value("handshake_good", HANDSHAKE_GOOD_LO),
            "retrans_warn": get_value("retrans_warn", RETX_WARN),
            "retrans_bad": get_value("retrans_bad", RETX_BAD),
            "rst_warn": get_value("rst_warn", RST_WARN),
            "rst_bad": get_value("rst_bad", RST_BAD),
            "scan_ports_warn": get_value("scan_ports_warn", SCAN_PORTS_WARN),
            "arp_conflict_warn": get_value("arp_conflict_warn", ARP_CONFLICT_WARN),
            "nxdomain_warn": get_value("nxdomain_warn", NXDOMAIN_SPIKE_WARN),
            "abnormal_rst_ratio": get_value("abnormal_rst_ratio", ABNORMAL_RST_RATIO_THRESHOLD),
        }

    def _build_technical_info_tab(self):
        layout = QtWidgets.QVBoxLayout(self.tech_info_tab)
        self.ti_tabs = QtWidgets.QTabWidget()
        layout.addWidget(self.ti_tabs)

        self.ti_capture_quality = {}
        self.ti_traffic_overview = {}
        self.ti_protocol_mix = {}
        self.ti_flow_analytics = {}
        self.ti_tcp_health = {}
        self.ti_top_entities = {}
        self.ti_security_signals = {}
        self.ti_time_series = {}

        self._ti_capture_quality_page()
        self._ti_traffic_overview_page()
        self._ti_protocol_mix_page()
        self._ti_flow_analytics_page()
        self._ti_tcp_health_page()
        self._ti_top_entities_page()
        self._ti_security_signals_page()
        self._ti_time_series_page()

    def _ti_capture_quality_page(self):
        page, layout = self._make_scroll_page()
        box, box_layout = self._make_section("Capture Quality")
        self.ti_capture_quality["quality"] = self._make_kv_table()
        box_layout.addWidget(self.ti_capture_quality["quality"])
        layout.addWidget(box)

        box, editor = self._make_json_panel("Full Analyzer JSON")
        self.ti_capture_quality["json"] = editor
        layout.addWidget(box)
        layout.addStretch(1)
        self.ti_tabs.addTab(page, "Capture Quality")

    def _ti_traffic_overview_page(self):
        page, layout = self._make_scroll_page()

        box, box_layout = self._make_section("Throughput and Peaks")
        self.ti_traffic_overview["throughput_kv"] = self._make_kv_table()
        box_layout.addWidget(self.ti_traffic_overview["throughput_kv"])
        layout.addWidget(box)

        box, box_layout = self._make_section("Packet Size Statistics")
        self.ti_traffic_overview["packet_stats"] = self._make_kv_table()
        box_layout.addWidget(self.ti_traffic_overview["packet_stats"])
        self.ti_traffic_overview["hist_table"] = self._make_table(["bucket", "count"])
        box_layout.addWidget(self.ti_traffic_overview["hist_table"])
        layout.addWidget(box)

        box, box_layout = self._make_section("L2/L3 Breakdown")
        self.ti_traffic_overview["l2l3"] = self._make_kv_table()
        box_layout.addWidget(self.ti_traffic_overview["l2l3"])
        layout.addWidget(box)

        box, box_layout = self._make_section("Global Totals (context)")
        self.ti_traffic_overview["totals"] = self._make_kv_table()
        box_layout.addWidget(self.ti_traffic_overview["totals"])
        layout.addWidget(box)

        json_tabs = QtWidgets.QTabWidget()
        self.ti_traffic_overview["json_throughput"] = QtWidgets.QPlainTextEdit()
        self.ti_traffic_overview["json_packet_sizes"] = QtWidgets.QPlainTextEdit()
        self.ti_traffic_overview["json_l2l3"] = QtWidgets.QPlainTextEdit()
        for editor in (self.ti_traffic_overview["json_throughput"], self.ti_traffic_overview["json_packet_sizes"], self.ti_traffic_overview["json_l2l3"]):
            editor.setReadOnly(True)
            editor.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        json_tabs.addTab(self.ti_traffic_overview["json_throughput"], "throughput_peaks")
        json_tabs.addTab(self.ti_traffic_overview["json_packet_sizes"], "packet_size_stats")
        json_tabs.addTab(self.ti_traffic_overview["json_l2l3"], "l2_l3_breakdown")
        layout.addWidget(QtWidgets.QLabel("Complete analyzer output for verification and debugging."))
        layout.addWidget(json_tabs)
        layout.addStretch(1)
        self.ti_tabs.addTab(page, "Traffic Overview")
    def _ti_protocol_mix_page(self):
        page, layout = self._make_scroll_page()

        box, box_layout = self._make_section("Totals")
        self.ti_protocol_mix["totals"] = self._make_kv_table()
        box_layout.addWidget(self.ti_protocol_mix["totals"])
        layout.addWidget(box)

        box, box_layout = self._make_section("Protocol Mix")
        self.ti_protocol_mix["counts"] = self._make_table(["protocol", "count"])
        self.ti_protocol_mix["percents"] = self._make_table(["protocol", "percent"])
        self.ti_protocol_mix["extra"] = self._make_kv_table()
        box_layout.addWidget(self.ti_protocol_mix["counts"])
        box_layout.addWidget(self.ti_protocol_mix["percents"])
        box_layout.addWidget(self.ti_protocol_mix["extra"])
        layout.addWidget(box)

        box, box_layout = self._make_section("Global Distributions")
        self.ti_protocol_mix["ip_versions"] = self._make_table(["key", "count", "percent"])
        self.ti_protocol_mix["l4_protocols"] = self._make_table(["key", "count", "percent"])
        self.ti_protocol_mix["tcp_flags"] = self._make_table(["key", "count", "percent"])
        self.ti_protocol_mix["decode_flags"] = self._make_table(["key", "count", "percent"])
        box_layout.addWidget(QtWidgets.QLabel("ip_versions"))
        box_layout.addWidget(self.ti_protocol_mix["ip_versions"])
        box_layout.addWidget(QtWidgets.QLabel("l4_protocols"))
        box_layout.addWidget(self.ti_protocol_mix["l4_protocols"])
        box_layout.addWidget(QtWidgets.QLabel("tcp_flags"))
        box_layout.addWidget(self.ti_protocol_mix["tcp_flags"])
        box_layout.addWidget(QtWidgets.QLabel("decode_quality_flags"))
        box_layout.addWidget(self.ti_protocol_mix["decode_flags"])
        layout.addWidget(box)

        json_tabs = QtWidgets.QTabWidget()
        self.ti_protocol_mix["json_protocol_mix"] = QtWidgets.QPlainTextEdit()
        self.ti_protocol_mix["json_global_stats"] = QtWidgets.QPlainTextEdit()
        for editor in (self.ti_protocol_mix["json_protocol_mix"], self.ti_protocol_mix["json_global_stats"]):
            editor.setReadOnly(True)
            editor.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        json_tabs.addTab(self.ti_protocol_mix["json_protocol_mix"], "protocol_mix")
        json_tabs.addTab(self.ti_protocol_mix["json_global_stats"], "global_stats")
        layout.addWidget(QtWidgets.QLabel("Complete analyzer output for verification and debugging."))
        layout.addWidget(json_tabs)
        layout.addStretch(1)
        self.ti_tabs.addTab(page, "Protocol Mix")

    def _ti_flow_analytics_page(self):
        page, layout = self._make_scroll_page()

        box, box_layout = self._make_section("Summary KPIs")
        self.ti_flow_analytics["summary"] = self._make_kv_table()
        box_layout.addWidget(self.ti_flow_analytics["summary"])
        layout.addWidget(box)

        box, box_layout = self._make_section("Heavy Hitters")
        self.ti_flow_analytics["heavy_bytes"] = self._make_table(["field", "value"], min_rows=14)
        self.ti_flow_analytics["heavy_packets"] = self._make_table(["field", "value"], min_rows=14)
        box_layout.addWidget(QtWidgets.QLabel("top_by_bytes"))
        box_layout.addWidget(self.ti_flow_analytics["heavy_bytes"])
        box_layout.addWidget(QtWidgets.QLabel("top_by_packets"))
        box_layout.addWidget(self.ti_flow_analytics["heavy_packets"])
        layout.addWidget(box)

        box, box_layout = self._make_section("Flow States")
        self.ti_flow_analytics["states"] = self._make_kv_table(min_rows=14)
        box_layout.addWidget(self.ti_flow_analytics["states"])
        layout.addWidget(box)

        box, box_layout = self._make_section("Flow Summary (raw table aggregates)")
        self.ti_flow_analytics["flow_summary"] = self._make_table(["field", "value"], min_rows=16)
        box_layout.addWidget(self.ti_flow_analytics["flow_summary"])
        layout.addWidget(box)

        json_tabs = QtWidgets.QTabWidget()
        self.ti_flow_analytics["json_flow_analytics"] = QtWidgets.QPlainTextEdit()
        self.ti_flow_analytics["json_flow_summary"] = QtWidgets.QPlainTextEdit()
        for editor in (self.ti_flow_analytics["json_flow_analytics"], self.ti_flow_analytics["json_flow_summary"]):
            editor.setReadOnly(True)
            editor.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        json_tabs.addTab(self.ti_flow_analytics["json_flow_analytics"], "flow_analytics")
        json_tabs.addTab(self.ti_flow_analytics["json_flow_summary"], "flow_summary")
        layout.addWidget(QtWidgets.QLabel("Complete analyzer output for verification and debugging."))
        layout.addWidget(json_tabs)
        layout.addStretch(1)
        self.ti_tabs.addTab(page, "Flow Analytics")

    def _ti_tcp_health_page(self):
        page, layout = self._make_scroll_page()

        box, box_layout = self._make_section("Handshakes")
        self.ti_tcp_health["handshakes"] = self._make_kv_table(min_rows=12)
        box_layout.addWidget(self.ti_tcp_health["handshakes"])
        layout.addWidget(box)

        box, box_layout = self._make_section("Reliability")
        self.ti_tcp_health["reliability"] = self._make_kv_table(min_rows=12)
        box_layout.addWidget(self.ti_tcp_health["reliability"])
        layout.addWidget(box)

        box, box_layout = self._make_section("Performance")
        self.ti_tcp_health["performance"] = self._make_kv_table(min_rows=12)
        self.ti_tcp_health["mss_table"] = self._make_table(["field", "value"], min_rows=10)
        box_layout.addWidget(self.ti_tcp_health["performance"])
        box_layout.addWidget(QtWidgets.QLabel("MSS"))
        box_layout.addWidget(self.ti_tcp_health["mss_table"])
        layout.addWidget(box)

        json_tabs = QtWidgets.QTabWidget()
        self.ti_tcp_health["json_handshakes"] = QtWidgets.QPlainTextEdit()
        self.ti_tcp_health["json_reliability"] = QtWidgets.QPlainTextEdit()
        self.ti_tcp_health["json_performance"] = QtWidgets.QPlainTextEdit()
        for editor in (self.ti_tcp_health["json_handshakes"], self.ti_tcp_health["json_reliability"], self.ti_tcp_health["json_performance"]):
            editor.setReadOnly(True)
            editor.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        json_tabs.addTab(self.ti_tcp_health["json_handshakes"], "tcp_handshakes")
        json_tabs.addTab(self.ti_tcp_health["json_reliability"], "tcp_reliability")
        json_tabs.addTab(self.ti_tcp_health["json_performance"], "tcp_performance")
        layout.addWidget(QtWidgets.QLabel("Complete analyzer output for verification and debugging."))
        layout.addWidget(json_tabs)
        layout.addStretch(1)
        self.ti_tabs.addTab(page, "TCP Health")

    def _ti_top_entities_page(self):
        page, layout = self._make_scroll_page()

        box, box_layout = self._make_section("IP Talkers")
        self.ti_top_entities["ip_src"] = self._make_table(["field", "value"], min_rows=14)
        self.ti_top_entities["ip_dst"] = self._make_table(["field", "value"], min_rows=14)
        self.ti_top_entities["ip_split"] = self._make_kv_table()
        box_layout.addWidget(QtWidgets.QLabel("top_src"))
        box_layout.addWidget(self.ti_top_entities["ip_src"])
        box_layout.addWidget(QtWidgets.QLabel("top_dst"))
        box_layout.addWidget(self.ti_top_entities["ip_dst"])
        box_layout.addWidget(QtWidgets.QLabel("internal_external"))
        box_layout.addWidget(self.ti_top_entities["ip_split"])
        layout.addWidget(box)

        box, box_layout = self._make_section("MAC Talkers")
        self.ti_top_entities["mac_src"] = self._make_table(["field", "value"], min_rows=14)
        self.ti_top_entities["mac_dst"] = self._make_table(["field", "value"], min_rows=14)
        box_layout.addWidget(QtWidgets.QLabel("top_src"))
        box_layout.addWidget(self.ti_top_entities["mac_src"])
        box_layout.addWidget(QtWidgets.QLabel("top_dst"))
        box_layout.addWidget(self.ti_top_entities["mac_dst"])
        layout.addWidget(box)

        box, box_layout = self._make_section("Ports and Services")
        self.ti_top_entities["tcp_ports"] = self._make_table(["field", "value"], min_rows=14)
        self.ti_top_entities["udp_ports"] = self._make_table(["field", "value"], min_rows=14)
        box_layout.addWidget(QtWidgets.QLabel("TCP top_dst_ports"))
        box_layout.addWidget(self.ti_top_entities["tcp_ports"])
        box_layout.addWidget(QtWidgets.QLabel("UDP top_dst_ports"))
        box_layout.addWidget(self.ti_top_entities["udp_ports"])
        layout.addWidget(box)

        json_tabs = QtWidgets.QTabWidget()
        self.ti_top_entities["json_top_entities"] = QtWidgets.QPlainTextEdit()
        self.ti_top_entities["json_ip_talkers"] = QtWidgets.QPlainTextEdit()
        self.ti_top_entities["json_mac_talkers"] = QtWidgets.QPlainTextEdit()
        self.ti_top_entities["json_ports"] = QtWidgets.QPlainTextEdit()
        for editor in (self.ti_top_entities["json_top_entities"], self.ti_top_entities["json_ip_talkers"], self.ti_top_entities["json_mac_talkers"], self.ti_top_entities["json_ports"]):
            editor.setReadOnly(True)
            editor.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        json_tabs.addTab(self.ti_top_entities["json_top_entities"], "top_entities")
        json_tabs.addTab(self.ti_top_entities["json_ip_talkers"], "ip_talkers")
        json_tabs.addTab(self.ti_top_entities["json_mac_talkers"], "mac_talkers")
        json_tabs.addTab(self.ti_top_entities["json_ports"], "ports")
        layout.addWidget(QtWidgets.QLabel("Complete analyzer output for verification and debugging."))
        layout.addWidget(json_tabs)
        layout.addStretch(1)
        self.ti_tabs.addTab(page, "Top Entities")

    def _ti_security_signals_page(self):
        page, layout = self._make_scroll_page()

        box, box_layout = self._make_section("Scan Signals")
        self.ti_security_signals["distinct_ports"] = self._make_kv_table(min_rows=10)
        self.ti_security_signals["distinct_ips"] = self._make_kv_table(min_rows=10)
        self.ti_security_signals["syn_ratio"] = self._make_kv_table(min_rows=10)
        self.ti_security_signals["scan_extra"] = self._make_kv_table(min_rows=10)
        box_layout.addWidget(self.ti_security_signals["distinct_ports"])
        box_layout.addWidget(self.ti_security_signals["distinct_ips"])
        box_layout.addWidget(self.ti_security_signals["syn_ratio"])
        box_layout.addWidget(self.ti_security_signals["scan_extra"])
        layout.addWidget(box)

        box, box_layout = self._make_section("ARP / LAN Signals")
        self.ti_security_signals["multiple_macs"] = self._make_kv_table(min_rows=10)
        self.ti_security_signals["multiple_examples"] = self._make_table(["field", "value"], min_rows=10)
        self.ti_security_signals["arp_changes"] = self._make_kv_table(min_rows=10)
        self.ti_security_signals["arp_changes_table"] = self._make_table(["field", "value"], min_rows=10)
        self.ti_security_signals["arp_extra"] = self._make_kv_table(min_rows=10)
        box_layout.addWidget(self.ti_security_signals["multiple_macs"])
        box_layout.addWidget(self.ti_security_signals["multiple_examples"])
        box_layout.addWidget(self.ti_security_signals["arp_changes"])
        box_layout.addWidget(self.ti_security_signals["arp_changes_table"])
        box_layout.addWidget(self.ti_security_signals["arp_extra"])
        layout.addWidget(box)

        box, box_layout = self._make_section("DNS Anomalies")
        self.ti_security_signals["entropy"] = self._make_kv_table(min_rows=10)
        self.ti_security_signals["entropy_samples"] = self._make_table(["field", "value"], min_rows=10)
        self.ti_security_signals["long_labels"] = self._make_kv_table(min_rows=10)
        self.ti_security_signals["long_samples"] = self._make_table(["field", "value"], min_rows=10)
        self.ti_security_signals["nxdomain"] = self._make_kv_table(min_rows=10)
        self.ti_security_signals["dns_extra"] = self._make_kv_table(min_rows=10)
        box_layout.addWidget(self.ti_security_signals["entropy"])
        box_layout.addWidget(self.ti_security_signals["entropy_samples"])
        box_layout.addWidget(self.ti_security_signals["long_labels"])
        box_layout.addWidget(self.ti_security_signals["long_samples"])
        box_layout.addWidget(self.ti_security_signals["nxdomain"])
        box_layout.addWidget(self.ti_security_signals["dns_extra"])
        layout.addWidget(box)

        json_tabs = QtWidgets.QTabWidget()
        self.ti_security_signals["json_scan"] = QtWidgets.QPlainTextEdit()
        self.ti_security_signals["json_arp"] = QtWidgets.QPlainTextEdit()
        self.ti_security_signals["json_dns"] = QtWidgets.QPlainTextEdit()
        for editor in (self.ti_security_signals["json_scan"], self.ti_security_signals["json_arp"], self.ti_security_signals["json_dns"]):
            editor.setReadOnly(True)
            editor.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        json_tabs.addTab(self.ti_security_signals["json_scan"], "scan_signals")
        json_tabs.addTab(self.ti_security_signals["json_arp"], "arp_lan_signals")
        json_tabs.addTab(self.ti_security_signals["json_dns"], "dns_anomalies")
        layout.addWidget(QtWidgets.QLabel("Complete analyzer output for verification and debugging."))
        layout.addWidget(json_tabs)
        layout.addStretch(1)
        self.ti_tabs.addTab(page, "Security Signals")

    def _ti_time_series_page(self):
        page, layout = self._make_scroll_page()

        box, box_layout = self._make_section("Traffic Over Time")
        self.ti_time_series["series"] = self._make_table(["field", "value"], min_rows=16)
        box_layout.addWidget(self.ti_time_series["series"])
        layout.addWidget(box)

        box, box_layout = self._make_section("Packet Chunks")
        self.ti_time_series["chunks"] = self._make_table(["field", "value"], min_rows=16)
        self.ti_time_series["top_bytes"] = self._make_table(["rank", "chunk", "bytes"], min_rows=8)
        self.ti_time_series["top_packets"] = self._make_table(["rank", "chunk", "packets"], min_rows=8)
        box_layout.addWidget(self.ti_time_series["chunks"])
        box_layout.addWidget(QtWidgets.QLabel("Top 3 chunks by bytes"))
        box_layout.addWidget(self.ti_time_series["top_bytes"])
        box_layout.addWidget(QtWidgets.QLabel("Top 3 chunks by packets"))
        box_layout.addWidget(self.ti_time_series["top_packets"])
        layout.addWidget(box)

        json_tabs = QtWidgets.QTabWidget()
        self.ti_time_series["json_time_series"] = QtWidgets.QPlainTextEdit()
        self.ti_time_series["json_packet_chunks"] = QtWidgets.QPlainTextEdit()
        for editor in (self.ti_time_series["json_time_series"], self.ti_time_series["json_packet_chunks"]):
            editor.setReadOnly(True)
            editor.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        json_tabs.addTab(self.ti_time_series["json_time_series"], "time_series")
        json_tabs.addTab(self.ti_time_series["json_packet_chunks"], "packet_chunks")
        layout.addWidget(QtWidgets.QLabel("Complete analyzer output for verification and debugging."))
        layout.addWidget(json_tabs)
        layout.addStretch(1)
        self.ti_tabs.addTab(page, "Time Series & Chunking")
    def _build_dashboard_tab(self):
        layout = QtWidgets.QVBoxLayout(self.dashboard_tab)
        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)

        content = QtWidgets.QWidget()
        scroll.setWidget(content)
        vbox = QtWidgets.QVBoxLayout(content)
        vbox.setContentsMargins(10, 10, 10, 10)
        vbox.setSpacing(10)

        # KPI cards
        kpi_box, kpi_layout = self._make_section("Simplified Dashboard")
        kpi_grid = QtWidgets.QGridLayout()
        kpi_layout.addLayout(kpi_grid)
        self.kpi_cards = {}
        kpi_defs = [
            "Total packets",
            "Total bytes",
            "Duration",
            "Peak bps",
            "TCP handshake completion",
            "TCP retransmission rate",
            "Drop rate",
            "NXDOMAIN spike",
        ]
        for idx, title in enumerate(kpi_defs):
            card = self._kpi_card(title)
            self.kpi_cards[title] = card
            row = idx // 4
            col = idx % 4
            kpi_grid.addWidget(card, row, col)
        vbox.addWidget(kpi_box)

        # Charts
        charts_box, charts_layout = self._make_section("Key charts")
        self.chart_tabs = QtWidgets.QTabWidget()
        charts_layout.addWidget(self.chart_tabs)
        self.chart_frames = {}
        for name in [
            "Traffic",
            "Protocols",
            "IP Versions",
            "Talkers",
            "Top Flows (Bytes)",
            "Top Flows (Packets)",
            "Flow States",
            "TCP",
            "Packet Sizes",
        ]:
            frame = QtWidgets.QWidget()
            frame.setLayout(QtWidgets.QVBoxLayout())
            frame.layout().setContentsMargins(6, 6, 6, 6)
            self.chart_tabs.addTab(frame, name)
            self.chart_frames[name] = frame
        vbox.addWidget(charts_box)

        # Diagnostics
        diag_box, diag_layout = self._make_section("Diagnostics")
        self.diag_table = self._make_table(["severity", "message"], min_rows=20)
        diag_layout.addWidget(self.diag_table)
        vbox.addWidget(diag_box)

        vbox.addStretch(1)

    def _kpi_card(self, title):
        frame = QtWidgets.QFrame()
        frame.setStyleSheet("background-color: %s;" % BG_CARD)
        layout = QtWidgets.QVBoxLayout(frame)
        layout.setContentsMargins(8, 8, 8, 8)
        title_label = QtWidgets.QLabel(title)
        title_label.setStyleSheet("color: %s; font-weight: 600;" % FG_MUTED)
        value_label = QtWidgets.QLabel("n/a")
        value_label.setStyleSheet("color: %s; font-size: 14px; font-weight: 600;" % FG_TEXT)
        sub_label = QtWidgets.QLabel("")
        sub_label.setStyleSheet("color: %s;" % FG_MUTED)
        badge = QtWidgets.QLabel("INFO")
        badge.setAlignment(QtCore.Qt.AlignCenter)
        badge.setFixedWidth(60)
        badge.setStyleSheet("background-color: %s; color: %s; padding: 2px;" % (INFO_BADGE, FG_TEXT))

        layout.addWidget(title_label)
        layout.addWidget(value_label)
        layout.addWidget(sub_label)
        layout.addWidget(badge, alignment=QtCore.Qt.AlignLeft)

        frame.value_label = value_label
        frame.sub_label = sub_label
        frame.badge_label = badge
        return frame

    def _set_kpi(self, title, value, severity="INFO", sub=""):
        card = self.kpi_cards.get(title)
        if not card:
            return
        card.value_label.setText(value)
        card.sub_label.setText(sub or "")
        card.badge_label.setText(severity)
        color = INFO_BADGE
        if severity == "GOOD":
            color = GOOD
        elif severity == "WARN":
            color = WARN_BADGE
        elif severity == "BAD":
            color = BAD
        card.badge_label.setStyleSheet("background-color: %s; color: %s; padding: 2px;" % (color, FG_TEXT))

    def _sev_from_pct(self, value, good_lt, warn_lt, bad_ge):
        if value is None:
            return "INFO"
        try:
            val = float(value)
        except (TypeError, ValueError):
            return "INFO"
        if val >= bad_ge:
            return "BAD"
        if val >= warn_lt:
            return "WARN"
        return "GOOD"

    def _sev_from_bool(self, flag):
        if flag is None:
            return "INFO"
        return "WARN" if bool(flag) else "GOOD"

    def _mpl_clear_frame(self, frame):
        layout = frame.layout()
        if layout is None:
            layout = QtWidgets.QVBoxLayout(frame)
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def _mpl_pie(self, frame, labels, values, title):
        self._mpl_clear_frame(frame)
        layout = frame.layout()
        if not self.has_mpl:
            table = self._make_table(["label", "value"])
            rows = list(zip(labels, values))
            self._set_dynamic_rows(table, [{"label": r[0], "value": r[1]} for r in rows], ["label", "value"])
            layout.addWidget(table)
            return
        fig = Figure(figsize=(10, 7))
        ax = fig.add_subplot(111)
        ax.pie(values, labels=labels, autopct="%1.1f%%")
        ax.set_title(title)
        canvas = FigureCanvas(fig)
        canvas.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Expanding)

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        scroll.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        scroll.setWidget(canvas)
        scroll.setMinimumHeight(520)
        layout.addWidget(scroll)

    def _mpl_bar(self, frame, labels, values, title, xrot=0, orientation="v", label_fontsize=9, grid=True, xlabel=None):
        self._mpl_clear_frame(frame)
        layout = frame.layout()
        if not self.has_mpl:
            table = self._make_table(["label", "value"])
            rows = list(zip(labels, values))
            self._set_dynamic_rows(table, [{"label": r[0], "value": r[1]} for r in rows], ["label", "value"])
            layout.addWidget(table)
            return
        fig_height = 8
        if orientation == "h":
            fig_height = max(4, min(12, 0.45 * max(1, len(labels)) + 2))
        fig = Figure(figsize=(12, fig_height))
        ax = fig.add_subplot(111)
        if orientation == "h":
            y_pos = list(range(len(labels)))
            ax.barh(y_pos, values)
            ax.set_yticks(y_pos)
            ax.set_yticklabels(labels, fontsize=label_fontsize)
            ax.invert_yaxis()
            ax.tick_params(axis='x', labelsize=label_fontsize)
            fig.subplots_adjust(left=0.28, right=0.98, top=0.92, bottom=0.12)
        else:
            ax.bar(labels, values)
            if xrot:
                ax.tick_params(axis='x', rotation=xrot, labelsize=label_fontsize)
            else:
                ax.tick_params(axis='x', labelsize=label_fontsize)
            fig.subplots_adjust(left=0.08, right=0.98, top=0.92, bottom=0.18)
        ax.set_title(title)
        if xlabel:
            ax.set_xlabel(xlabel)
        if grid:
            ax.grid(axis='x' if orientation == "h" else 'y', linestyle='--', alpha=0.3)
        canvas = FigureCanvas(fig)
        canvas.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Expanding)

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        scroll.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        scroll.setWidget(canvas)
        scroll.setMinimumHeight(520)
        layout.addWidget(scroll)

    def _mpl_line(self, frame, x, series_list, title, xlabel="", ylabel=""):
        self._mpl_clear_frame(frame)
        layout = frame.layout()
        if not self.has_mpl:
            table = self._make_table(["x"] + [s["name"] for s in series_list])
            rows = []
            for idx, label in enumerate(x):
                row = {"x": label}
                for s in series_list:
                    row[s["name"]] = s["y"][idx] if idx < len(s["y"]) else ""
                rows.append(row)
            self._set_dynamic_rows(table, rows, ["x"] + [s["name"] for s in series_list])
            layout.addWidget(table)
            return
        fig = Figure(figsize=(12, 8))
        ax = fig.add_subplot(111)
        for series in series_list:
            ax.plot(x, series["y"], label=series["name"])
        ax.set_title(title)
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        ax.legend()
        canvas = FigureCanvas(fig)
        canvas.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Expanding)

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        scroll.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        scroll.setWidget(canvas)
        scroll.setMinimumHeight(520)
        layout.addWidget(scroll)

    def _short_flow_label(self, text, max_len=28):
        if not isinstance(text, str):
            text = str(text)
        if len(text) <= max_len:
            return text
        head = max(6, (max_len // 2) - 2)
        tail = max_len - head - 3
        return f"{text[:head]}...{text[-tail:]}"

    def _render_top_flows(self, frame, items, title, value_key, xlabel):
        self._mpl_clear_frame(frame)
        layout = frame.layout()
        items = [i for i in items if isinstance(i, dict)]
        if not items:
            layout.addWidget(QtWidgets.QLabel("No flow data available."))
            return

        labels = [self._short_flow_label(i.get("label", i.get("flow_id", "?"))) for i in items]
        values = [i.get(value_key, 0) for i in items]

        if not self.has_mpl:
            table = self._make_table(["flow", value_key])
            rows = [{"flow": i.get("label", i.get("flow_id", "?")), value_key: i.get(value_key, 0)} for i in items]
            self._set_dynamic_rows(table, rows, ["flow", value_key])
            layout.addWidget(table)
            return

        fig_height = max(4, min(10, 0.45 * len(labels) + 2))
        fig = Figure(figsize=(12, fig_height))
        ax = fig.add_subplot(111)
        y_pos = list(range(len(labels)))
        bars = ax.barh(y_pos, values, color="#00d4ff", alpha=0.85)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(labels, fontsize=8)
        ax.invert_yaxis()
        ax.set_xlabel(xlabel)
        ax.set_title(title)
        ax.grid(axis='x', linestyle='--', alpha=0.25)
        for bar, val in zip(bars, values):
            ax.text(
                bar.get_width(),
                bar.get_y() + bar.get_height() / 2,
                f" {val}",
                va="center",
                ha="left",
                fontsize=8,
                color="#e6e9ef",
            )
        fig.subplots_adjust(left=0.28, right=0.98, top=0.92, bottom=0.12)
        canvas = FigureCanvas(fig)
        canvas.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Expanding)

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        scroll.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        scroll.setWidget(canvas)
        scroll.setMinimumHeight(360)
        layout.addWidget(scroll)

        table = self._make_table(["flow", value_key], min_rows=min(10, len(items) + 2))
        rows = [{"flow": i.get("label", i.get("flow_id", "?")), value_key: i.get(value_key, 0)} for i in items]
        self._set_dynamic_rows(table, rows, ["flow", value_key])
        layout.addWidget(table)

    def _mpl_hist(self, frame, bucket_labels, counts, title):
        self._mpl_clear_frame(frame)
        layout = frame.layout()
        if not self.has_mpl:
            table = self._make_table(["bucket", "count", "percent"])
            total = sum(c for c in counts if isinstance(c, (int, float)))
            rows = []
            for b, c in zip(bucket_labels, counts):
                pct = (float(c) / total * 100.0) if total else 0.0
                rows.append({"bucket": b, "count": c, "percent": f"{pct:.1f}%"})
            self._set_dynamic_rows(table, rows, ["bucket", "count", "percent"])
            layout.addWidget(table)
            return
        fig = Figure(figsize=(12, 9))
        ax = fig.add_subplot(111)
        safe_counts = [c if isinstance(c, (int, float)) else 0 for c in counts]
        total = sum(safe_counts)
        bars = ax.bar(bucket_labels, safe_counts, color="#7b6cff", alpha=0.85)
        ax.set_title(title)
        ax.set_xlabel("Packet size buckets (bytes)")
        ax.set_ylabel("Packets")
        ax.tick_params(axis='x', rotation=25, labelsize=9)
        ax.grid(axis='y', linestyle='--', alpha=0.25)
        if total:
            ax.text(0.99, 0.98, f"Total: {int(total):,}", transform=ax.transAxes,
                    ha="right", va="top", fontsize=9, color="#c7c7c7")
        for bar, count in zip(bars, safe_counts):
            if count <= 0:
                continue
            pct = (count / total * 100.0) if total else 0.0
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                f"{int(count)} ({pct:.1f}%)",
                ha="center",
                va="bottom",
                fontsize=8,
                color="#e6e9ef",
            )
        fig.subplots_adjust(bottom=0.22, top=0.92, left=0.08, right=0.98)
        canvas = FigureCanvas(fig)
        canvas.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Expanding)

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        scroll.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        scroll.setWidget(canvas)
        scroll.setMinimumHeight(520)
        layout.addWidget(scroll)

    def _build_packet_tab(self):
        layout = QtWidgets.QVBoxLayout(self.packet_tab)
        self.packet_table = QtWidgets.QTableWidget(0, 1)
        self.packet_table.setHorizontalHeaderLabels(["packet"])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.setStyleSheet("background-color: %s; color: %s;" % (BG_PANEL, FG_TEXT))
        layout.addWidget(self.packet_table)
    def start_capture(self):
        if hasattr(self, "home_status_label"):
            self.home_status_label.setText("CAPTURE BEGUN")
        try:
            duration = int(self.duration_edit.text().strip() or "0")
        except ValueError:
            duration = 0
        try:
            limit = int(self.limit_edit.text().strip() or "0")
        except ValueError:
            limit = 0
        self._start_home_progress(duration, limit)
        # Get backend (default to scapy if combo doesn't exist)
        if hasattr(self, 'backend_combo'):
            backend = self.backend_combo.currentText().strip()
        else:
            backend = "scapy"
        interface = self.interface_edit.text().strip()
        if backend == "scapy" and not interface:
            interface = get_default_scapy_iface()
            if interface:
                self.interface_edit.setText(interface)
            else:
                interface = ""
        if backend == "scapy":
            resolved = self._resolve_scapy_interface(interface)
            if resolved:
                interface = resolved
                self.interface_edit.setText(interface)
            else:
                self.status_label.setText("No valid scapy interface found. Set an NPF interface and try again.")
                return
        try:
            duration = int(self.duration_edit.text().strip() or "0")
        except ValueError:
            duration = 0
        try:
            limit = int(self.limit_edit.text().strip() or "0")
        except ValueError:
            limit = 0
        if duration > 0:
            pass
        if duration <= 0 and limit <= 0:
            limit = 50
            self.limit_edit.setText(str(limit))
        if backend == "scapy" and duration <= 0:
            duration = 5

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._capture_stop_flag.clear()
        self.status_label.setText(f"Capturing... backend={backend} duration={duration}s limit={limit}")
        thread = threading.Thread(target=self._capture_thread, args=(backend, interface, duration, limit), daemon=True)
        thread.start()
    
    def stop_capture(self):
        """Stop the current capture."""
        self._capture_stop_flag.set()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("STOPPED")
        if hasattr(self, "home_status_label"):
            self.home_status_label.setText("CAPTURED ENDED")
        self._stop_home_progress()

    def _capture_thread(self, backend, interface, duration, limit):
        try:
            capture_limit = limit if limit > 0 else 0
            packets = run_capture(backend, interface, duration, capture_limit)
            note = ""
            if limit > 0 and len(packets) >= limit:
                note = f"Capture complete (limit reached: {limit})"
                if hasattr(self, "home_status_label"):
                    self.ui_call.emit(lambda: self.home_status_label.setText("LIMIT REACHED"))
                self.ui_call.emit(self._stop_home_progress)
            elif duration > 0:
                note = f"Capture complete ({duration}s)"
                if hasattr(self, "home_status_label"):
                    self.ui_call.emit(lambda: self.home_status_label.setText("CAPTURED ENDED"))
                self.ui_call.emit(self._stop_home_progress)
            print(f"DEBUG: UI capture returned {len(packets)} packets")
            self.ui_call.emit(lambda: self.status_label.setText(f"Captured {len(packets)} packets. Analyzing..."))
            if backend == "scapy" and not packets:
                # Auto-probe other interfaces once
                for alt_iface in self._list_scapy_interfaces():
                    if alt_iface == interface:
                        continue
                    packets = run_capture("scapy", alt_iface, max(3, duration), max(10, limit))
                    print(f"DEBUG: UI probe {alt_iface} -> {len(packets)} packets")
                    if packets:
                        interface = alt_iface
                        self.ui_call.emit(lambda: self.interface_edit.setText(interface))
                        break
            thresholds = self._get_thresholds()
            analysis = run_analysis(
                packets,
                scan_port_threshold=int(thresholds["scan_ports_warn"]),
                rst_ratio_threshold=float(thresholds["abnormal_rst_ratio"]) / 100.0,
            )
            print(f"DEBUG: Analysis keys: {list(analysis.keys())}")
            self.latest_packets = packets
            self.latest_analysis = analysis
            self._last_capture_note = note
            self._packet_search_cache = self._build_packet_search_cache(packets)
            self._packet_search_cache_id = id(packets)
            self._packet_search_cache_len = len(packets)
            self.ui_call.emit(self.refresh_all)
        except Exception as exc:
            msg = str(exc)
            self.ui_call.emit(lambda: self.status_label.setText(msg))
        finally:
            self.ui_call.emit(lambda: self.start_btn.setEnabled(True))
            self.ui_call.emit(lambda: self.stop_btn.setEnabled(False))
            self.ui_call.emit(self._stop_home_progress)

    def refresh_all(self):
        print("DEBUG: refresh_all called")
        if not self.latest_packets:
            self.status_label.setText(self._last_capture_note or "Capture complete (0 packets)")
        else:
            self.status_label.setText(self._last_capture_note or "Capture complete")
        if hasattr(self, "download_btn"):
            self.download_btn.setEnabled(bool(self.latest_packets))
        if hasattr(self, "export_analysis_btn"):
            self.export_analysis_btn.setEnabled(bool(self.latest_analysis))
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.refresh_summary()
        self.refresh_top_domains()
        self.refresh_raw_data()
        self.refresh_technical_information()
        self.refresh_dashboard()
        self.refresh_packets()
        self.refresh_packet_overview()

    def refresh_summary(self):
        totals = self._get_global_totals(self.latest_analysis)
        if (not totals.get("packets")) and self.latest_packets:
            totals = self._compute_totals_from_packets(self.latest_packets)
        cached = getattr(self, "_cached_quick_counts", None)
        if isinstance(cached, dict) and cached.get("packet_count") == len(self.latest_packets or []):
            self.analysis_eth.setText(_fmt_count(cached.get("eth_count")))
            self.analysis_dns.setText(_fmt_count(cached.get("dns_count")))
            self.analysis_unique_ips.setText(_fmt_count(cached.get("unique_ip_count")))
            cached_valid = True
        else:
            cached_valid = False
        packets = totals.get("packets")
        bytes_total = totals.get("bytes") or totals.get("bytes_captured") or totals.get("bytes_original")
        duration_us = totals.get("duration_us")
        self.stat_packets.setText(_fmt_count(packets))
        if hasattr(self, "stat_packets_panel"):
            self.stat_packets_panel.setText(_fmt_count(packets))
        if hasattr(self, "stat_bytes"):
            self.stat_bytes.setText(_fmt_bytes(bytes_total))
        if hasattr(self, "stat_duration"):
            self.stat_duration.setText(_fmt_duration_us(duration_us))
        ip4 = totals.get("ipv4_packets")
        ip6 = totals.get("ipv6_packets")
        self.stat_ip.setText(f"{_fmt_count(ip4)} / {_fmt_count(ip6)}")
        if hasattr(self, "stat_ip_panel"):
            self.stat_ip_panel.setText(f"{_fmt_count(ip4)} / {_fmt_count(ip6)}")
        tcp = totals.get("tcp_packets")
        udp = totals.get("udp_packets")
        self.stat_l4.setText(f"{_fmt_count(tcp)} / {_fmt_count(udp)}")
        if hasattr(self, "stat_l4_panel"):
            self.stat_l4_panel.setText(f"{_fmt_count(tcp)} / {_fmt_count(udp)}")
        flows = totals.get("flows") or totals.get("flow_count")
        if flows is None:
            flow_analytics = self.latest_analysis.get("global_results", {}).get("flow_analytics", {})
            summary = flow_analytics.get("summary", {}) if isinstance(flow_analytics, dict) else {}
            flows = summary.get("total_flows")
        if flows is None:
            flow_results = self.latest_analysis.get("flow_results", {}) if isinstance(self.latest_analysis, dict) else {}
            flow_summary_block = flow_results.get("flow_summary", {}) if isinstance(flow_results, dict) else {}
            flow_list = flow_summary_block.get("flows", []) if isinstance(flow_summary_block, dict) else []
            if isinstance(flow_list, list) and flow_list:
                flows = len(flow_list)
        self.stat_flows.setText(_fmt_count(flows))
        if hasattr(self, "stat_flows_panel"):
            self.stat_flows_panel.setText(_fmt_count(flows))

        tcp_rel = self.latest_analysis.get("global_results", {}).get("tcp_reliability", {})
        rst_rate = tcp_rel.get("rst_rate") if isinstance(tcp_rel, dict) else None
        self.stat_rst.setText(_fmt_pct(rst_rate))
        if hasattr(self, "stat_rst_panel"):
            self.stat_rst_panel.setText(_fmt_pct(rst_rate))

        capture_health = self.latest_analysis.get("global_results", {}).get("capture_health", {})
        drops = ((capture_health.get("capture_quality", {}) or {}).get("drops", {}) or {}).get("dropped_packets")
        self.stat_drops.setText(_fmt_count(drops))

        protocol_mix = self.latest_analysis.get("global_results", {}).get("protocol_mix", {})
        self.analysis_protocol.setText(f"{len(protocol_mix.get('protocol_counts', {}) or {})} protocols")
        top_proto = "-"
        if isinstance(protocol_mix, dict):
            counts = protocol_mix.get("protocol_counts") or {}
            if isinstance(counts, dict) and counts:
                top_proto = max(counts.items(), key=lambda kv: kv[1])[0]
        if (top_proto == "-" or top_proto is None) and self.latest_packets:
            proto_counts = {}
            for pkt in self.latest_packets or []:
                l4 = pkt.get("l4_protocol")
                if not l4:
                    ip_proto = pkt.get("ip_protocol")
                    if ip_proto == 6:
                        l4 = "TCP"
                    elif ip_proto == 17:
                        l4 = "UDP"
                if l4:
                    proto_counts[l4] = proto_counts.get(l4, 0) + 1
            if proto_counts:
                top_proto = max(proto_counts.items(), key=lambda kv: kv[1])[0]
        self.stat_top_proto.setText(str(top_proto))
        if hasattr(self, "stat_protocols"):
            if isinstance(protocol_mix, dict) and isinstance(protocol_mix.get("protocol_counts"), dict):
                self.stat_protocols.setText(_fmt_count(len(protocol_mix.get("protocol_counts") or {})))
            elif self.latest_packets:
                proto_counts = {}
                for pkt in self.latest_packets or []:
                    l4 = pkt.get("l4_protocol")
                    if not l4:
                        ip_proto = pkt.get("ip_protocol")
                        if ip_proto == 6:
                            l4 = "TCP"
                        elif ip_proto == 17:
                            l4 = "UDP"
                    if l4:
                        proto_counts[l4] = proto_counts.get(l4, 0) + 1
                self.stat_protocols.setText(_fmt_count(len(proto_counts)))
        bytes_captured = totals.get("bytes") or totals.get("bytes_captured")
        self.analysis_bytes.setText(_fmt_bytes(bytes_captured))
        handshake = self.latest_analysis.get("global_results", {}).get("tcp_handshakes", {})
        if handshake:
            total = handshake.get("handshakes_total")
            complete = handshake.get("handshakes_complete")
            incomplete = handshake.get("handshakes_incomplete")
            if total is not None and complete is not None:
                if incomplete is None and total is not None and complete is not None:
                    try:
                        incomplete = int(total) - int(complete)
                    except Exception:
                        incomplete = None
                if incomplete is not None:
                    self.analysis_handshake.setText(f"{_fmt_count(complete)} / {_fmt_count(total)} ({_fmt_count(incomplete)} incomplete)")
                else:
                    self.analysis_handshake.setText(f"{_fmt_count(complete)} / {_fmt_count(total)}")
            else:
                completion = handshake.get("completion_rate")
                self.analysis_handshake.setText(f"{_fmt_pct(completion)}")
        else:
            self.analysis_handshake.setText("-")
        ts_obj = self.latest_analysis.get("time_series", {}) if isinstance(self.latest_analysis, dict) else {}
        packet_chunks = ts_obj.get("packet_chunks") if isinstance(ts_obj, dict) else {}
        packet_chunks = packet_chunks if isinstance(packet_chunks, dict) else {}
        chunks = packet_chunks.get("chunks")
        if chunks is None:
            chunks = packet_chunks if isinstance(packet_chunks, list) else []
        count = len(chunks) if isinstance(chunks, list) else 0
        self.analysis_chunks.setText(_fmt_count(count))
        if not cached_valid:
            eth_count = 0
            dns_count = 0
            unique_ips = set()
            for pkt in self.latest_packets or []:
                if not isinstance(pkt, dict):
                    continue
                if pkt.get("is_arp") or pkt.get("src_mac") or pkt.get("dst_mac") or pkt.get("eth_type"):
                    eth_count += 1
                if pkt.get("dns_qname") or pkt.get("dns_rcode") is not None or pkt.get("dns_is_query") or pkt.get("dns_is_response"):
                    dns_count += 1
                src_ip = pkt.get("src_ip")
                dst_ip = pkt.get("dst_ip")
                if src_ip:
                    unique_ips.add(src_ip)
                if dst_ip:
                    unique_ips.add(dst_ip)
            self.analysis_eth.setText(_fmt_count(eth_count))
            self.analysis_dns.setText(_fmt_count(dns_count))
            self.analysis_unique_ips.setText(_fmt_count(len(unique_ips)))
            self._cached_quick_counts = {
                "eth_count": eth_count,
                "dns_count": dns_count,
                "unique_ip_count": len(unique_ips),
                "packet_count": len(self.latest_packets or []),
            }

    def refresh_top_domains(self):
        if not hasattr(self, "top_domain_labels"):
            return
        if not self.latest_packets:
            for label in self.top_domain_labels:
                label.setText("-")
            return
        counts = {}
        byte_out = 0
        byte_in = 0
        local_candidates = {}
        local_ips = set()
        ext_counts = {}
        try:
            import socket
            host = socket.gethostname()
            for ip in socket.gethostbyname_ex(host)[2]:
                local_ips.add(ip)
        except Exception:
            pass
        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                for ip in iface.get("ips") or []:
                    local_ips.add(ip)
        except Exception:
            pass
        try:
            from scapy.all import conf
            for _dst, _gw, _iface, src in conf.route.routes:
                if src:
                    local_ips.add(src)
        except Exception:
            pass
        local_ips = {ip for ip in local_ips if ip and ip not in ("0.0.0.0", "127.0.0.1")}
        for pkt in self.latest_packets or []:
            if not isinstance(pkt, dict):
                continue
            src_ip = pkt.get("src_ip")
            dst_ip = pkt.get("dst_ip")
            if src_ip:
                local_candidates[src_ip] = local_candidates.get(src_ip, 0) + 1
            qname = pkt.get("dns_qname")
            if qname:
                domain = str(qname).strip().lower().rstrip(".")
                if domain:
                    counts[domain] = counts.get(domain, 0) + 1
        if not local_ips:
            # Infer local IPs as most frequent src_ip values
            local_ips = {ip for ip, _cnt in sorted(local_candidates.items(), key=lambda kv: kv[1], reverse=True)[:2]}
        for pkt in self.latest_packets or []:
            if not isinstance(pkt, dict):
                continue
            src_ip = pkt.get("src_ip")
            dst_ip = pkt.get("dst_ip")
            length = int(pkt.get("original_length") or pkt.get("captured_length") or 0)
            if src_ip in local_ips:
                byte_out += length
            elif dst_ip in local_ips:
                byte_in += length
            # External IPs (inbound only)
            if dst_ip in local_ips and src_ip and src_ip not in local_ips:
                try:
                    import ipaddress
                    ip_obj = ipaddress.ip_address(src_ip)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local:
                        continue
                except Exception:
                    pass
                ext_counts[src_ip] = ext_counts.get(src_ip, 0) + 1
        top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:1]
        if top:
            domain, count = top[0]
            self.top_domain_labels[0].setText(f"{domain} ({count})")
        else:
            self.top_domain_labels[0].setText("-")

        if byte_in or byte_out:
            direction = "DOWNLOAD" if byte_in >= byte_out else "UPLOAD"
            self.top_domain_labels[1].setText(f"{direction} ({_fmt_bytes(byte_in)} / {_fmt_bytes(byte_out)})")
        else:
            self.top_domain_labels[1].setText("-")

        totals = self._get_global_totals(self.latest_analysis)
        if (not totals.get("duration_us")) and self.latest_packets:
            totals = self._compute_totals_from_packets(self.latest_packets)
        duration_s = (float(totals.get("duration_us") or 0) / 1_000_000) if totals.get("duration_us") else 0.0
        if duration_s > 0 and (byte_in or byte_out):
            dl_bps = (byte_in * 8.0) / duration_s
            ul_bps = (byte_out * 8.0) / duration_s
            self.top_domain_labels[2].setText(f"DL {_fmt_bps(dl_bps)} / UL {_fmt_bps(ul_bps)}")
        else:
            self.top_domain_labels[2].setText("-")

        if top:
            self.top_domain_labels[3].setText(f"{top[0][0]} ({top[0][1]})")
        else:
            self.top_domain_labels[3].setText("-")

        # Network quality score (heuristic)
        capture_health = self.latest_analysis.get("global_results", {}).get("capture_health", {})
        capture_quality = capture_health.get("capture_quality", {}) if isinstance(capture_health, dict) else {}
        drops = capture_quality.get("drops", {}) if isinstance(capture_quality, dict) else {}
        drop_rate = drops.get("drop_rate")
        if drop_rate is not None:
            try:
                drop_rate = float(drop_rate)
            except (TypeError, ValueError):
                drop_rate = None
        if drop_rate is not None:
            drop_pct = drop_rate * 100.0 if drop_rate <= 1.0 else drop_rate
        else:
            drop_pct = None

        tcp_rel = self.latest_analysis.get("global_results", {}).get("tcp_reliability", {})
        retrans_rate = tcp_rel.get("retransmission_rate") if isinstance(tcp_rel, dict) else None
        if retrans_rate is not None:
            try:
                retrans_rate = float(retrans_rate)
            except (TypeError, ValueError):
                retrans_rate = None

        tcp_hs = self.latest_analysis.get("global_results", {}).get("tcp_handshakes", {})
        completion = tcp_hs.get("completion_rate") if isinstance(tcp_hs, dict) else None
        if completion is not None:
            try:
                completion = float(completion)
            except (TypeError, ValueError):
                completion = None

        decode_health = capture_health.get("decode_health", {}) if isinstance(capture_health, dict) else {}
        decode_ok = decode_health.get("decode_success_rate") if isinstance(decode_health, dict) else None
        if decode_ok is not None:
            try:
                decode_ok = float(decode_ok)
            except (TypeError, ValueError):
                decode_ok = None

        if any(v is not None for v in (drop_pct, retrans_rate, completion, decode_ok)):
            score = 100.0
            if drop_pct is not None:
                score -= min(50.0, drop_pct * 0.5)
            if retrans_rate is not None:
                score -= min(40.0, retrans_rate * 100.0 * 0.4)
            if completion is not None:
                score -= min(40.0, (1.0 - completion) * 100.0 * 0.4)
            if decode_ok is not None:
                score -= min(30.0, (1.0 - decode_ok) * 100.0 * 0.3)
            score = max(0.0, min(100.0, score))
            self.top_domain_labels[4].setText(f"{_fmt_number(score, 1)} / 100")
        else:
            self.top_domain_labels[4].setText("-")

        # Unusual ports (dst ports not in common list)
        common_ports = {
            20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 137, 138, 139, 143, 161, 162,
            389, 443, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443,
            9200, 27017,
        }
        port_counts = {}
        for pkt in self.latest_packets or []:
            if not isinstance(pkt, dict):
                continue
            dst_port = pkt.get("dst_port")
            if dst_port is None:
                continue
            try:
                port = int(dst_port)
            except (TypeError, ValueError):
                continue
            if port <= 1024 or port in common_ports:
                continue
            port_counts[port] = port_counts.get(port, 0) + 1
        if port_counts:
            top_ports = sorted(port_counts.items(), key=lambda kv: kv[1], reverse=True)[:3]
            self.top_domain_labels[5].setText(", ".join(f"{p} ({c})" for p, c in top_ports))
        else:
            self.top_domain_labels[5].setText("-")

        if ext_counts:
            ip, count = max(ext_counts.items(), key=lambda kv: kv[1])
            self.top_domain_labels[6].setText(f"{ip} ({count})")
        else:
            self.top_domain_labels[6].setText("-")

        for idx in range(7, len(self.top_domain_labels)):
            self.top_domain_labels[idx].setText("-")

    def refresh_raw_data(self):
        analysis = self.latest_analysis.get("global_results", {})

        capture_health = analysis.get("capture_health", {})
        capture_quality = capture_health.get("capture_quality", {})
        decode_health = capture_health.get("decode_health", {})
        filtering = capture_health.get("filtering", {})
        self.raw_cards["capture_quality"].value_label.setText(json.dumps(capture_quality, indent=2) if capture_quality else "n/a")
        self.raw_cards["decode_health"].value_label.setText(json.dumps(decode_health, indent=2) if decode_health else "n/a")
        self.raw_cards["filtering"].value_label.setText(json.dumps(filtering, indent=2) if filtering else "n/a")

        throughput = analysis.get("throughput_peaks", {})
        if throughput:
            self.raw_cards["throughput"].value_label.setText(f"Peak bps: {_fmt_bps(throughput.get('peak_bps'))}\nPeak pps: {_fmt_pps(throughput.get('peak_pps'))}")
        else:
            self.raw_cards["throughput"].value_label.setText("n/a")

        packet_sizes = analysis.get("packet_size_stats", {})
        if packet_sizes:
            cap = packet_sizes.get("captured_length", {})
            self.raw_cards["packet_sizes"].value_label.setText(f"min {_fmt_bytes(cap.get('min'))} | p95 {_fmt_bytes(cap.get('p95'))}")
        else:
            self.raw_cards["packet_sizes"].value_label.setText("n/a")

        l2l3 = analysis.get("l2_l3_breakdown", {})
        if l2l3:
            self.raw_cards["l2l3"].value_label.setText(f"ethernet {l2l3.get('ethernet_frames', 0)}")
        else:
            self.raw_cards["l2l3"].value_label.setText("n/a")

        top_entities = analysis.get("top_entities", {})
        ip_talkers = top_entities.get("ip_talkers", {})
        mac_talkers = top_entities.get("mac_talkers", {})
        ports = top_entities.get("ports", {})
        self.raw_cards["top_talkers"].value_label.setText(f"src {len(ip_talkers.get('top_src', []) or [])}")
        self.raw_cards["top_macs"].value_label.setText(f"src {len(mac_talkers.get('top_src', []) or [])}")
        self.raw_cards["top_ports"].value_label.setText(f"tcp {len((ports.get('tcp', {}) or {}).get('top_dst_ports', []) or [])}")

        flow_analytics = analysis.get("flow_analytics", {})
        summary = flow_analytics.get("summary", {})
        flow_results = self.latest_analysis.get("flow_results", {}) if isinstance(self.latest_analysis, dict) else {}
        flow_summary_block = flow_results.get("flow_summary", {}) if isinstance(flow_results, dict) else {}
        flow_list = flow_summary_block.get("flows", []) if isinstance(flow_summary_block, dict) else []
        total_flows = summary.get("total_flows", "n/a")
        if isinstance(flow_list, list) and flow_list:
            total_flows = len(flow_list)
        self.raw_cards["flow_summary"].value_label.setText(f"total_flows {total_flows}")
        self.raw_cards["flow_heavy"].value_label.setText(f"by_bytes {len((flow_analytics.get('heavy_hitters', {}) or {}).get('top_by_bytes', []) or [])}")
        self.raw_cards["flow_states"].value_label.setText(json.dumps(flow_analytics.get("states", {})) if flow_analytics.get("states") else "n/a")

        tcp_handshakes = analysis.get("tcp_handshakes", {})
        tcp_reliability = analysis.get("tcp_reliability", {})
        tcp_performance = analysis.get("tcp_performance", {})
        if isinstance(tcp_handshakes, dict):
            total = tcp_handshakes.get("handshakes_total")
            complete = tcp_handshakes.get("handshakes_complete")
            incomplete = tcp_handshakes.get("handshakes_incomplete")
            if total is not None and complete is not None:
                if incomplete is None and total is not None and complete is not None:
                    try:
                        incomplete = int(total) - int(complete)
                    except Exception:
                        incomplete = None
                if incomplete is not None:
                    text = f"{_fmt_count(complete)} / {_fmt_count(total)} ({_fmt_count(incomplete)} incomplete)"
                else:
                    text = f"{_fmt_count(complete)} / {_fmt_count(total)}"
                self.raw_cards["tcp_handshake"].value_label.setText(text)
            else:
                self.raw_cards["tcp_handshake"].value_label.setText(_fmt_pct(tcp_handshakes.get("completion_rate")))
        else:
            self.raw_cards["tcp_handshake"].value_label.setText("n/a")
        self.raw_cards["tcp_reliability"].value_label.setText(_fmt_pct(tcp_reliability.get("retransmission_rate")))
        self.raw_cards["tcp_performance"].value_label.setText(_fmt_count(tcp_performance.get("zero_window")))

        scan = analysis.get("scan_signals", {})
        arp = analysis.get("arp_lan_signals", {})
        dns = analysis.get("dns_anomalies", {})
        self.raw_cards["scan_signals"].value_label.setText(json.dumps(scan.get("distinct_ports", {})) if scan else "n/a")
        self.raw_cards["arp_lan"].value_label.setText(json.dumps(arp.get("multiple_macs", {})) if arp else "n/a")
        self.raw_cards["dns_anomalies"].value_label.setText(json.dumps(dns.get("nxdomain", {})) if dns else "n/a")

        # Render any remaining analyzers not shown above
        handled = {
            "capture_health", "throughput_peaks", "packet_size_stats", "l2_l3_breakdown",
            "top_entities", "flow_analytics", "tcp_handshakes", "tcp_reliability", "tcp_performance",
            "scan_signals", "arp_lan_signals", "dns_anomalies", "protocol_mix", "flow_summary",
            "abnormal_activity",
        }
        other_rows = []
        if isinstance(analysis, dict):
            for key in sorted(analysis.keys()):
                if key in handled:
                    continue
                value = analysis.get(key)
                try:
                    value_text = json.dumps(value)
                except Exception:
                    value_text = str(value)
                other_rows.append((key, value_text))
        # include top-level analysis keys not in global_results
        top_level = self.latest_analysis
        for key in sorted(top_level.keys()):
            if key in ("global_results",):
                continue
            if key in handled:
                continue
            value = top_level.get(key)
            try:
                value_text = json.dumps(value)
            except Exception:
                value_text = str(value)
            other_rows.append((key, value_text))
        self._set_kv_rows(self.raw_other_table, other_rows)

    def refresh_technical_information(self):
        analysis = self.latest_analysis
        self._refresh_ti_capture_quality(analysis)
        self._refresh_ti_traffic_overview(analysis)
        self._refresh_ti_protocol_mix(analysis)
        self._refresh_ti_flow_analytics(analysis)
        self._refresh_ti_tcp_health(analysis)
        self._refresh_ti_top_entities(analysis)
        self._refresh_ti_security_signals(analysis)
        self._refresh_ti_time_series(analysis)

    def refresh_dashboard(self):
        analysis = self.latest_analysis
        thresholds = self._get_thresholds()
        totals = self._get_global_totals(analysis)
        throughput = analysis.get("global_results", {}).get("throughput_peaks", {})
        tcp_handshakes = analysis.get("global_results", {}).get("tcp_handshakes", {})
        tcp_reliability = analysis.get("global_results", {}).get("tcp_reliability", {})
        capture_health = analysis.get("global_results", {}).get("capture_health", {})
        drops = (((capture_health.get("capture_quality", {}) or {}).get("drops", {}) or {}).get("drop_rate"))
        dns = analysis.get("global_results", {}).get("dns_anomalies", {}).get("nxdomain", {})
        nxdomain_spike = dns.get("spike_detected") if isinstance(dns, dict) else None

        self._set_kpi("Total packets", _fmt_count(totals.get("packets")), "INFO")
        self._set_kpi("Total bytes", _fmt_bytes(totals.get("bytes") or totals.get("bytes_captured") or totals.get("bytes_original")), "INFO")
        self._set_kpi("Duration", _fmt_duration_us(totals.get("duration_us")), "INFO")
        self._set_kpi("Peak bps", _fmt_bps(throughput.get("peak_bps")), "INFO")

        completion = _safe_float(tcp_handshakes.get("completion_rate"))
        total_hs = tcp_handshakes.get("handshakes_total")
        complete_hs = tcp_handshakes.get("handshakes_complete")
        incomplete_hs = tcp_handshakes.get("handshakes_incomplete")
        completion_sev = self._sev_from_pct(
            completion,
            thresholds["handshake_good"],
            thresholds["handshake_warn"],
            100.0,
        )
        if total_hs is not None and complete_hs is not None:
            if incomplete_hs is None:
                try:
                    incomplete_hs = int(total_hs) - int(complete_hs)
                except Exception:
                    incomplete_hs = None
            if incomplete_hs is not None:
                display = f"{_fmt_count(complete_hs)} / {_fmt_count(total_hs)} ({_fmt_count(incomplete_hs)} incomplete)"
            else:
                display = f"{_fmt_count(complete_hs)} / {_fmt_count(total_hs)}"
        else:
            display = _fmt_pct(completion)
        self._set_kpi("TCP handshakes", display, completion_sev)

        retrans = _safe_float(tcp_reliability.get("retransmission_rate"))
        retrans_sev = self._sev_from_pct(
            retrans,
            thresholds["retrans_warn"],
            thresholds["retrans_warn"],
            thresholds["retrans_bad"],
        )
        self._set_kpi("TCP retransmission rate", _fmt_pct(retrans), retrans_sev)

        drop_rate = _safe_float(drops)
        drop_sev = self._sev_from_pct(
            drop_rate,
            thresholds["drop_warn"],
            thresholds["drop_warn"],
            thresholds["drop_bad"],
        )
        self._set_kpi("Drop rate", _fmt_pct(drop_rate), drop_sev)

        if thresholds["nxdomain_warn"]:
            nx_sev = self._sev_from_bool(nxdomain_spike)
        else:
            nx_sev = "INFO"
        self._set_kpi("NXDOMAIN spike", "yes" if nxdomain_spike else "no", nx_sev)

        self._refresh_dashboard_charts(analysis)
        self._refresh_dashboard_diagnostics(analysis)

    def refresh_packets(self, packets=None):
        packets = packets if packets is not None else (self.latest_packets or [])
        preferred = [
            "packet_id", "timestamp_us", "stack_summary",
            "src_ip", "dst_ip", "src_port", "dst_port",
            "l4_protocol", "ip_version",
            "captured_length", "original_length",
            "src_mac", "dst_mac", "eth_type",
            "tcp_flags_names", "quality_names",
        ]
        keys = set()
        for pkt in packets:
            if isinstance(pkt, dict):
                keys.update(pkt.keys())
        columns = [k for k in preferred if k in keys]
        for k in sorted(keys):
            if k not in columns:
                columns.append(k)
        if not columns:
            columns = ["packet"]

        self.packet_table.setRowCount(0)
        self.packet_table.setColumnCount(len(columns))
        self.packet_table.setHorizontalHeaderLabels(columns)

        for pkt in packets:
            r = self.packet_table.rowCount()
            self.packet_table.insertRow(r)
            if isinstance(pkt, dict):
                for c, key in enumerate(columns):
                    val = pkt.get(key)
                    if isinstance(val, list):
                        val = ", ".join(str(x) for x in val)
                    self.packet_table.setItem(r, c, QtWidgets.QTableWidgetItem(str(val)))
            else:
                self.packet_table.setItem(r, 0, QtWidgets.QTableWidgetItem(str(pkt)))

    def apply_filter(self):
        term = self.filter_edit.text().strip().lower()
        if not term:
            self.refresh_packets()
            self.refresh_packet_overview()
            return
        if (
            len(self._packet_search_cache) != len(self.latest_packets)
            or getattr(self, "_packet_search_cache_id", None) != id(self.latest_packets)
            or getattr(self, "_packet_search_cache_len", None) != len(self.latest_packets)
        ):
            self._packet_search_cache = self._build_packet_search_cache(self.latest_packets)
            self._packet_search_cache_id = id(self.latest_packets)
            self._packet_search_cache_len = len(self.latest_packets)
        filtered = []
        for packet, hay in zip(self.latest_packets, self._packet_search_cache):
            if term in hay:
                filtered.append(packet)
        packets = filtered
        preferred = [
            "packet_id", "timestamp_us", "stack_summary",
            "src_ip", "dst_ip", "src_port", "dst_port",
            "l4_protocol", "ip_version",
            "captured_length", "original_length",
            "src_mac", "dst_mac", "eth_type",
            "tcp_flags_names", "quality_names",
        ]
        keys = set()
        for pkt in packets:
            if isinstance(pkt, dict):
                keys.update(pkt.keys())
        columns = [k for k in preferred if k in keys]
        for k in sorted(keys):
            if k not in columns:
                columns.append(k)
        if not columns:
            columns = ["packet"]

        self.packet_table.setRowCount(0)
        self.packet_table.setColumnCount(len(columns))
        self.packet_table.setHorizontalHeaderLabels(columns)

        for pkt in packets:
            r = self.packet_table.rowCount()
            self.packet_table.insertRow(r)
            if isinstance(pkt, dict):
                for c, key in enumerate(columns):
                    val = pkt.get(key)
                    if isinstance(val, list):
                        val = ", ".join(str(x) for x in val)
                    self.packet_table.setItem(r, c, QtWidgets.QTableWidgetItem(str(val)))
            else:
                self.packet_table.setItem(r, 0, QtWidgets.QTableWidgetItem(str(pkt)))
        self.refresh_packet_overview(packets)

    def _build_packet_search_cache(self, packets):
        cache = []
        for packet in packets or []:
            try:
                cache.append(json.dumps(packet).lower())
            except Exception:
                cache.append(str(packet).lower())
        return cache

    def refresh_packet_overview(self, packets=None):
        if isinstance(packets, bool):
            packets = None
        packets = packets if packets is not None else (self.latest_packets or [])
        if not isinstance(packets, (list, tuple)):
            packets = self.latest_packets or []
        grouping = "ip" if self.group_ip_btn.isChecked() else "l4"
        filters = self._get_selected_osi_filters()
        can_skip = packets is self.latest_packets
        if can_skip:
            sig = (
                id(self.latest_packets),
                len(self.latest_packets),
                grouping,
                tuple(sorted(filters["l2"])),
                tuple(sorted(filters["l3"])),
                tuple(sorted(filters["l4"])),
                tuple(sorted(filters["app"])),
            )
            if getattr(self, "_packet_overview_sig", None) == sig:
                return
            self._packet_overview_sig = sig
        packets = self._filter_packets_by_osi(packets)
        self.packet_overview.clear()
        self._packet_overview_loaded_ids = set()
        can_cache = (
            packets is self.latest_packets
            and not any(filters.values())
        )
        cache_entry = self._packet_group_cache.get(grouping)
        if can_cache and cache_entry and cache_entry.get("packets_id") == id(self.latest_packets) and cache_entry.get("count") == len(self.latest_packets):
            groups = cache_entry.get("groups", [])
        else:
            groups = self._group_packets(packets, grouping)
            if can_cache:
                self._packet_group_cache[grouping] = {
                    "packets_id": id(self.latest_packets),
                    "count": len(self.latest_packets),
                    "groups": groups,
                }
        for group_name, group_packets in groups:
            group_item = QtWidgets.QTreeWidgetItem([group_name])
            group_item.setFirstColumnSpanned(True)
            group_item.setFlags(group_item.flags() & ~QtCore.Qt.ItemIsSelectable)
            group_item.setExpanded(True)
            self.packet_overview.addTopLevelItem(group_item)

            for pkt in group_packets:
                row = self._packet_row(pkt)
                item = QtWidgets.QTreeWidgetItem(row)
                item.setChildIndicatorPolicy(QtWidgets.QTreeWidgetItem.ShowIndicator)
                if isinstance(pkt, dict) and "packet_id" in pkt:
                    item.setData(0, QtCore.Qt.UserRole, pkt.get("packet_id"))
                item.setData(1, QtCore.Qt.UserRole, pkt)
                group_item.addChild(item)

        if not self._packet_overview_resized and self.packet_overview.topLevelItemCount() > 0:
            for col in range(7):
                self.packet_overview.resizeColumnToContents(col)
            self._packet_overview_resized = True

    def _filter_packets_by_osi(self, packets):
        if not isinstance(packets, (list, tuple)):
            return list(self.latest_packets or [])
        filters = self._get_selected_osi_filters()
        if not any(filters.values()):
            return list(packets)
        filtered = []
        for pkt in packets:
            lens_tags = self._derive_osi_tags_ui(pkt)
            if not self._packet_matches_osi_filters(lens_tags, filters):
                continue
            filtered.append(pkt)
        return filtered

    def _packet_matches_osi_filters(self, lens_tags, filters):
        for lens, wanted in filters.items():
            if not wanted:
                continue
            if not (lens_tags.get(lens) or set()):
                return False
            if not (lens_tags.get(lens, set()) & wanted):
                return False
        return True

    def _get_selected_osi_filters(self):
        filters = {
            "l2": set(),
            "l3": set(),
            "l4": set(),
            "app": set(),
        }
        if self.osi_l2_eth.isChecked():
            filters["l2"].add("ethernet")
        if self.osi_l2_arp.isChecked():
            filters["l2"].add("arp")
        if self.osi_l3_ipv4.isChecked():
            filters["l3"].add("ipv4")
        if self.osi_l3_ipv6.isChecked():
            filters["l3"].add("ipv6")
        if self.osi_l4_tcp.isChecked():
            filters["l4"].add("tcp")
        if self.osi_l4_udp.isChecked():
            filters["l4"].add("udp")
        if self.osi_app_dns.isChecked():
            filters["app"].add("dns")
        return filters

    def _group_packets(self, packets, mode):
        groups = {}
        if mode == "ip":
            for pkt in packets:
                ip_version = pkt.get("ip_version") if isinstance(pkt, dict) else None
                if ip_version == 4:
                    key = "IPv4"
                elif ip_version == 6:
                    key = "IPv6"
                elif pkt.get("is_arp") if isinstance(pkt, dict) else False:
                    key = "ARP"
                else:
                    key = "Other"
                groups.setdefault(key, []).append(pkt)
        else:
            for pkt in packets:
                proto = pkt.get("l4_protocol") if isinstance(pkt, dict) else None
                if not proto:
                    if pkt.get("is_arp") if isinstance(pkt, dict) else False:
                        proto = "ARP"
                    elif pkt.get("ip_protocol") == 1:
                        proto = "ICMP"
                    elif pkt.get("ip_protocol") == 2:
                        proto = "IGMP"
                    else:
                        proto = "Other"
                groups.setdefault(proto, []).append(pkt)
        order = sorted(groups.keys(), key=lambda k: ("Other" in k, k))
        return [(k, groups[k]) for k in order]

    def _packet_row(self, pkt):
        if not isinstance(pkt, dict):
            return ["-", "-", "-", "-", "-", "-", "-", str(pkt)]
        ts = pkt.get("timestamp_us")
        time_str = _fmt_ts_utc(ts) if ts else "-"
        src = pkt.get("src_ip") or pkt.get("src_mac") or "-"
        dst = pkt.get("dst_ip") or pkt.get("dst_mac") or "-"
        proto = pkt.get("l4_protocol") or ("ARP" if pkt.get("is_arp") else pkt.get("stack_summary")) or "-"
        length = pkt.get("captured_length") or pkt.get("original_length") or "-"
        info = pkt.get("stack_summary") or "-"
        osi_text = self._fmt_osi_tags(pkt)
        if pkt.get("dns_qname"):
            info = f"DNS {pkt.get('dns_qname')}"
        elif pkt.get("tcp_flags_names"):
            info = f"TCP {','.join(pkt.get('tcp_flags_names') or [])}"
        return [
            str(pkt.get("packet_id", "-")),
            time_str,
            str(src),
            str(dst),
            str(proto),
            str(length),
            osi_text,
            str(info),
        ]

    def _add_packet_details(self, parent_item, pkt):
        if not isinstance(pkt, dict):
            return
        self._add_detail_section(parent_item, "Ethernet", [
            ("src_mac", pkt.get("src_mac")),
            ("dst_mac", pkt.get("dst_mac")),
            ("eth_type", pkt.get("eth_type")),
        ])
        self._add_detail_section(parent_item, "IP", [
            ("ip_version", pkt.get("ip_version")),
            ("src_ip", pkt.get("src_ip")),
            ("dst_ip", pkt.get("dst_ip")),
            ("ttl", pkt.get("ttl")),
        ])
        self._add_detail_section(parent_item, "Transport", [
            ("l4_protocol", pkt.get("l4_protocol")),
            ("src_port", pkt.get("src_port")),
            ("dst_port", pkt.get("dst_port")),
            ("tcp_flags", ",".join(pkt.get("tcp_flags_names") or []) if pkt.get("tcp_flags_names") else None),
            ("tcp_seq", pkt.get("tcp_seq")),
            ("tcp_ack", pkt.get("tcp_ack")),
            ("tcp_window", pkt.get("tcp_window")),
            ("tcp_mss", pkt.get("tcp_mss")),
        ])
        self._add_detail_section(parent_item, "DNS", [
            ("qname", pkt.get("dns_qname")),
            ("is_query", pkt.get("dns_is_query")),
            ("is_response", pkt.get("dns_is_response")),
            ("rcode", pkt.get("dns_rcode")),
        ])
        osi_text = self._fmt_osi_tags(pkt)
        if osi_text and osi_text != "-":
            self._add_detail_section(parent_item, "OSI Tags", [
                ("tags", osi_text),
            ])

    def _add_detail_section(self, parent_item, title, rows):
        section = QtWidgets.QTreeWidgetItem([title])
        section.setFirstColumnSpanned(True)
        section.setFlags(section.flags() & ~QtCore.Qt.ItemIsSelectable)
        parent_item.addChild(section)
        for key, value in rows:
            if value is None or value == "":
                continue
            cols = max(1, self.packet_overview.columnCount())
            row = [""] * cols
            row[0] = str(key)
            row[-1] = str(value)
            item = QtWidgets.QTreeWidgetItem(row)
            section.addChild(item)

    def _fmt_osi_tags(self, pkt):
        tags = self._derive_osi_tags_ui(pkt)
        parts = []
        if tags.get("l2"):
            parts.append("L2 " + "/".join(sorted(tags["l2"])))
        if tags.get("l3"):
            parts.append("L3 " + "/".join(sorted(tags["l3"])))
        if tags.get("l4"):
            parts.append("L4 " + "/".join(sorted(tags["l4"])))
        if tags.get("app"):
            parts.append("APP " + "/".join(sorted(tags["app"])))
        return " | ".join(parts) if parts else "-"

    def _derive_osi_tags_ui(self, pkt):
        tags = {"l2": set(), "l3": set(), "l4": set(), "app": set()}
        if not isinstance(pkt, dict):
            return tags

        cached = pkt.get("_osi_tags_ui")
        if isinstance(cached, dict):
            try:
                return {
                    "l2": set(cached.get("l2") or []),
                    "l3": set(cached.get("l3") or []),
                    "l4": set(cached.get("l4") or []),
                    "app": set(cached.get("app") or []),
                }
            except Exception:
                pass

        raw_tags = pkt.get("osi_tags") or []
        if isinstance(raw_tags, str):
            raw_tags = [raw_tags]
        for tag in raw_tags:
            if not isinstance(tag, str):
                continue
            raw = tag.strip().lower()
            if raw.startswith("l2:"):
                tags["l2"].add(raw.split(":", 1)[1])
            elif raw.startswith("l3:"):
                tags["l3"].add(raw.split(":", 1)[1])
            elif raw.startswith("l4:"):
                tags["l4"].add(raw.split(":", 1)[1])
            elif raw.startswith("app:"):
                tags["app"].add(raw.split(":", 1)[1])
            else:
                if raw in ("ethernet", "arp"):
                    tags["l2"].add(raw)
                elif raw in ("ipv4", "ipv6"):
                    tags["l3"].add(raw)
                elif raw in ("tcp", "udp"):
                    tags["l4"].add(raw)
                elif raw in ("dns",):
                    tags["app"].add(raw)

        if not any(tags.values()):
            if pkt.get("is_arp"):
                tags["l2"].add("arp")
            elif pkt.get("src_mac") or pkt.get("dst_mac") or pkt.get("eth_type"):
                tags["l2"].add("ethernet")

            ip_version = pkt.get("ip_version")
            if ip_version == 4:
                tags["l3"].add("ipv4")
            elif ip_version == 6:
                tags["l3"].add("ipv6")

            l4 = (pkt.get("l4_protocol") or "").lower()
            if l4 in ("tcp", "udp"):
                tags["l4"].add(l4)
            else:
                ip_proto = pkt.get("ip_protocol")
                if ip_proto == 6:
                    tags["l4"].add("tcp")
                elif ip_proto == 17:
                    tags["l4"].add("udp")

            if pkt.get("dns_qname") or pkt.get("dns_rcode") is not None or pkt.get("dns_is_query") or pkt.get("dns_is_response"):
                tags["app"].add("dns")

        pkt["_osi_tags_ui"] = {
            "l2": sorted(tags["l2"]),
            "l3": sorted(tags["l3"]),
            "l4": sorted(tags["l4"]),
            "app": sorted(tags["app"]),
        }
        return tags

    def _clear_packet_overview_settings(self):
        # Reset all Packet Overview controls to defaults.
        blockers = [
            QtCore.QSignalBlocker(self.group_ip_btn),
            QtCore.QSignalBlocker(self.group_l4_btn),
            QtCore.QSignalBlocker(self.osi_l2_eth),
            QtCore.QSignalBlocker(self.osi_l2_arp),
            QtCore.QSignalBlocker(self.osi_l3_ipv4),
            QtCore.QSignalBlocker(self.osi_l3_ipv6),
            QtCore.QSignalBlocker(self.osi_l4_tcp),
            QtCore.QSignalBlocker(self.osi_l4_udp),
            QtCore.QSignalBlocker(self.osi_app_dns),
        ]
        try:
            self.group_ip_btn.setChecked(True)
            self.group_l4_btn.setChecked(False)
            for cb in (
                self.osi_l2_eth, self.osi_l2_arp,
                self.osi_l3_ipv4, self.osi_l3_ipv6,
                self.osi_l4_tcp, self.osi_l4_udp,
                self.osi_app_dns,
            ):
                cb.setChecked(False)
        finally:
            blockers.clear()

        self.packet_overview.clearSelection()
        self.packet_overview.collapseAll()
        self._packet_overview_loaded_ids = set()
        self._packet_overview_sig = None
        self.refresh_packet_overview()

    def _on_packet_overview_click(self, item, _column):
        # Toggle packet rows (depth=1 under group)
        parent = item.parent()
        if parent is None:
            return
        if parent.parent() is None:
            item.setExpanded(not item.isExpanded())
            if item.isExpanded():
                self._ensure_packet_details(item)

    def _on_packet_overview_expand(self, item):
        parent = item.parent()
        if parent is None:
            return
        if parent.parent() is None:
            self._ensure_packet_details(item)

    def _ensure_packet_details(self, item):
        pkt = item.data(1, QtCore.Qt.UserRole)
        if not isinstance(pkt, dict):
            return
        pkt_id = item.data(0, QtCore.Qt.UserRole)
        if pkt_id in self._packet_overview_loaded_ids:
            return
        if pkt_id is not None:
            self._packet_overview_loaded_ids.add(pkt_id)
        self._add_packet_details(item, pkt)

    def download_capture(self):
        if not self.latest_packets:
            QtWidgets.QMessageBox.information(self, "No capture", "No packets available to download.")
            return
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save capture data",
            "",
            "JSON files (*.json);;All files (*.*)",
        )
        if not filename:
            return
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.latest_packets, f, indent=2)
        except Exception as exc:
            QtWidgets.QMessageBox.critical(self, "Save failed", str(exc))

    def export_analysis(self):
        if not self.latest_analysis:
            QtWidgets.QMessageBox.information(self, "No analysis", "No analysis available to export.")
            return
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save analysis report",
            "",
            "JSON files (*.json);;All files (*.*)",
        )
        if not filename:
            return
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.latest_analysis, f, indent=2)
        except Exception as exc:
            QtWidgets.QMessageBox.critical(self, "Save failed", str(exc))
    def _refresh_ti_capture_quality(self, analysis):
        capture_health = analysis.get("global_results", {}).get("capture_health", {})
        capture_health = capture_health if isinstance(capture_health, dict) else {}
        rows = []
        for key in sorted(capture_health.keys()):
            value = capture_health.get(key)
            if isinstance(value, (dict, list)):
                value_text = json.dumps(value)
            else:
                value_text = str(value)
            rows.append((key, value_text))
        self._set_kv_rows(self.ti_capture_quality["quality"], rows)
        self._set_json_text(self.ti_capture_quality["json"], capture_health if capture_health else {})

    def _refresh_ti_traffic_overview(self, analysis):
        throughput = analysis.get("global_results", {}).get("throughput_peaks", {})
        packet_stats = analysis.get("global_results", {}).get("packet_size_stats", {})
        l2l3 = analysis.get("global_results", {}).get("l2_l3_breakdown", {})
        totals = self._get_global_totals(analysis)

        throughput_rows = []
        if isinstance(throughput, dict):
            for key in sorted(throughput.keys()):
                value = throughput.get(key)
                if key in ("bps_now", "bps_avg", "peak_bps"):
                    value_text = _fmt_bps(value)
                elif key in ("pps_now", "pps_avg", "peak_pps"):
                    value_text = _fmt_pps(value)
                elif key.endswith("timestamp"):
                    value_text = _fmt_ts_utc(value)
                else:
                    value_text = str(value)
                throughput_rows.append((key, value_text))
        self._set_kv_rows(self.ti_traffic_overview["throughput_kv"], throughput_rows)

        packet_rows = []
        if isinstance(packet_stats, dict):
            cap = packet_stats.get("captured_length", {})
            orig = packet_stats.get("original_length", {})
            if isinstance(cap, dict):
                for key in ["min", "median", "p95", "max"]:
                    packet_rows.append((f"captured_{key}", _fmt_bytes(cap.get(key))))
            if isinstance(orig, dict):
                for key in ["min", "median", "p95", "max"]:
                    packet_rows.append((f"original_{key}", _fmt_bytes(orig.get(key))))
            fragments = packet_stats.get("fragments", {})
            if isinstance(fragments, dict):
                for key in sorted(fragments.keys()):
                    packet_rows.append((key, _fmt_count(fragments.get(key))))
        self._set_kv_rows(self.ti_traffic_overview["packet_stats"], packet_rows)

        hist = {}
        if isinstance(packet_stats, dict):
            hist = packet_stats.get("histogram", {})
        hist_rows = []
        if isinstance(hist, dict):
            for key in hist.keys():
                hist_rows.append({"bucket": key, "count": hist.get(key)})
        self._set_dynamic_rows(self.ti_traffic_overview["hist_table"], hist_rows, ["bucket", "count"])

        l2_rows = []
        if isinstance(l2l3, dict):
            for key in sorted(l2l3.keys()):
                l2_rows.append((key, _fmt_count(l2l3.get(key))))
        self._set_kv_rows(self.ti_traffic_overview["l2l3"], l2_rows)

        totals_rows = []
        if isinstance(totals, dict):
            for key in sorted(totals.keys()):
                value = totals.get(key)
                if key in ("bytes", "bytes_captured", "bytes_original"):
                    value_text = _fmt_bytes(value)
                elif key in ("duration_us", "duration"):
                    value_text = _fmt_duration_us(value)
                else:
                    value_text = str(value)
                totals_rows.append((key, value_text))
        self._set_kv_rows(self.ti_traffic_overview["totals"], totals_rows)

        self._set_json_text(self.ti_traffic_overview["json_throughput"], throughput if throughput else {})
        self._set_json_text(self.ti_traffic_overview["json_packet_sizes"], packet_stats if packet_stats else {})
        self._set_json_text(self.ti_traffic_overview["json_l2l3"], l2l3 if l2l3 else {})

    def _refresh_ti_protocol_mix(self, analysis):
        totals = self._get_global_totals(analysis)
        totals_rows = []
        if isinstance(totals, dict):
            for key in sorted(totals.keys()):
                value = totals.get(key)
                if key in ("bytes", "bytes_captured", "bytes_original"):
                    value_text = _fmt_bytes(value)
                elif key in ("duration_us", "duration"):
                    value_text = _fmt_duration_us(value)
                else:
                    value_text = str(value)
                totals_rows.append((key, value_text))
        self._set_kv_rows(self.ti_protocol_mix["totals"], totals_rows)

        protocol = analysis.get("global_results", {}).get("protocol_mix", {})
        protocol_counts = protocol.get("protocol_counts") if isinstance(protocol, dict) else None
        protocol_pcts = protocol.get("protocol_percentages") if isinstance(protocol, dict) else None
        counts_rows = []
        if isinstance(protocol_counts, dict):
            for key in sorted(protocol_counts.keys()):
                counts_rows.append({"protocol": key, "count": protocol_counts.get(key)})
        self._set_dynamic_rows(self.ti_protocol_mix["counts"], counts_rows, ["protocol", "count"])

        pct_rows = []
        if isinstance(protocol_pcts, dict):
            for key in sorted(protocol_pcts.keys()):
                pct_rows.append({"protocol": key, "percent": _fmt_pct(protocol_pcts.get(key))})
        elif isinstance(protocol_counts, dict):
            total = sum(v for v in protocol_counts.values() if isinstance(v, (int, float)))
            for key in sorted(protocol_counts.keys()):
                val = protocol_counts.get(key)
                pct = (float(val) / total * 100.0) if total else 0.0
                pct_rows.append({"protocol": key, "percent": _fmt_pct(pct)})
        self._set_dynamic_rows(self.ti_protocol_mix["percents"], pct_rows, ["protocol", "percent"])

        extra_rows = []
        if isinstance(protocol, dict):
            for key in sorted(protocol.keys()):
                if key in ("protocol_counts", "protocol_percentages"):
                    continue
                value = protocol.get(key)
                if isinstance(value, (dict, list)):
                    value_text = json.dumps(value)
                else:
                    value_text = str(value)
                extra_rows.append((key, value_text))
        self._set_kv_rows(self.ti_protocol_mix["extra"], extra_rows)

        distributions = analysis.get("global_results", {}).get("global_stats", {}).get("distributions", {})
        for key, table_key in (
            ("ip_versions", "ip_versions"),
            ("l4_protocols", "l4_protocols"),
            ("tcp_flags", "tcp_flags"),
            ("decode_quality_flags", "decode_flags"),
        ):
            dist = distributions.get(key, {}) if isinstance(distributions, dict) else {}
            rows = []
            if isinstance(dist, dict):
                total = sum(v for v in dist.values() if isinstance(v, (int, float)))
                for k in sorted(dist.keys()):
                    val = dist.get(k)
                    pct = (float(val) / total * 100.0) if total else 0.0
                    rows.append({"key": k, "count": val, "percent": _fmt_pct(pct)})
            self._set_dynamic_rows(self.ti_protocol_mix[table_key], rows, ["key", "count", "percent"])

        self._set_json_text(self.ti_protocol_mix["json_protocol_mix"], protocol if protocol else {})
        self._set_json_text(self.ti_protocol_mix["json_global_stats"], analysis.get("global_results", {}).get("global_stats", {}))

    def _refresh_ti_flow_analytics(self, analysis):
        flow_analytics = analysis.get("global_results", {}).get("flow_analytics", {})
        summary = flow_analytics.get("summary", {}) if isinstance(flow_analytics, dict) else {}
        rows = []
        if isinstance(summary, dict):
            for key in sorted(summary.keys()):
                value = summary.get(key)
                if key.startswith("duration"):
                    value_text = _fmt_duration_us(value)
                elif key.endswith("bytes"):
                    value_text = _fmt_bytes(value)
                else:
                    value_text = str(value)
                rows.append((key, value_text))
        self._set_kv_rows(self.ti_flow_analytics["summary"], rows)

        heavy = flow_analytics.get("heavy_hitters", {}) if isinstance(flow_analytics, dict) else {}
        top_by_bytes = heavy.get("top_by_bytes", []) if isinstance(heavy, dict) else []
        top_by_packets = heavy.get("top_by_packets", []) if isinstance(heavy, dict) else []
        self._set_dynamic_rows(self.ti_flow_analytics["heavy_bytes"], top_by_bytes)
        self._set_dynamic_rows(self.ti_flow_analytics["heavy_packets"], top_by_packets)

        states = flow_analytics.get("states", {}) if isinstance(flow_analytics, dict) else {}
        state_rows = []
        if isinstance(states, dict):
            for key in sorted(states.keys()):
                state_rows.append((key, str(states.get(key))))
        self._set_kv_rows(self.ti_flow_analytics["states"], state_rows)

        flow_results = analysis.get("flow_results", {}) if isinstance(analysis, dict) else {}
        flow_summary_block = flow_results.get("flow_summary", {}) if isinstance(flow_results, dict) else {}
        flow_list = None
        if isinstance(flow_summary_block, dict):
            if isinstance(flow_summary_block.get("flows"), list):
                flow_list = flow_summary_block.get("flows")
            else:
                list_value = []
                for v in flow_summary_block.values():
                    if isinstance(v, list):
                        list_value.extend(v)
                if list_value:
                    flow_list = list_value
        if isinstance(flow_list, list) and flow_list:
            self._set_dynamic_rows(self.ti_flow_analytics["flow_summary"], flow_list)
        else:
            flow_summary = analysis.get("global_results", {}).get("flow_summary", {})
            if isinstance(flow_summary, dict):
                if any(isinstance(v, list) for v in flow_summary.values()):
                    list_value = None
                    for v in flow_summary.values():
                        if isinstance(v, list):
                            list_value = v
                            break
                    self._set_dynamic_rows(self.ti_flow_analytics["flow_summary"], list_value or [])
                else:
                    rows = [{"field": k, "value": v} for k, v in flow_summary.items()]
                    self._set_dynamic_rows(self.ti_flow_analytics["flow_summary"], rows, ["field", "value"])
            else:
                self._set_dynamic_rows(self.ti_flow_analytics["flow_summary"], [])

        self._set_json_text(self.ti_flow_analytics["json_flow_analytics"], flow_analytics if flow_analytics else {})
        self._set_json_text(self.ti_flow_analytics["json_flow_summary"], flow_summary_block if flow_summary_block else {})

    def _refresh_ti_tcp_health(self, analysis):
        hand = analysis.get("global_results", {}).get("tcp_handshakes", {})
        rel = analysis.get("global_results", {}).get("tcp_reliability", {})
        perf = analysis.get("global_results", {}).get("tcp_performance", {})

        hand_rows = []
        if isinstance(hand, dict):
            for key in sorted(hand.keys()):
                value = hand.get(key)
                if key.endswith("_rate") or key.endswith("_pct"):
                    value_text = _fmt_pct(value)
                else:
                    value_text = str(value)
                hand_rows.append((key, value_text))
        self._set_kv_rows(self.ti_tcp_health["handshakes"], hand_rows)

        rel_rows = []
        if isinstance(rel, dict):
            for key in sorted(rel.keys()):
                value = rel.get(key)
                if key.endswith("_rate") or key.endswith("_pct"):
                    value_text = _fmt_pct(value)
                else:
                    value_text = str(value)
                rel_rows.append((key, value_text))
        self._set_kv_rows(self.ti_tcp_health["reliability"], rel_rows)

        perf_rows = []
        mss_list = None
        if isinstance(perf, dict):
            mss_list = perf.get("mss_distribution") or perf.get("mss_top_k")
            for key in sorted(perf.keys()):
                value = perf.get(key)
                if isinstance(value, list):
                    continue
                if key.startswith("window"):
                    value_text = _fmt_count(value)
                else:
                    value_text = str(value)
                perf_rows.append((key, value_text))
        self._set_kv_rows(self.ti_tcp_health["performance"], perf_rows)

        if isinstance(mss_list, list):
            self._set_dynamic_rows(self.ti_tcp_health["mss_table"], mss_list)
        else:
            mss_rows = []
            if isinstance(perf, dict):
                for key in ("mss_top_value", "mss_top_pct"):
                    if key in perf:
                        value = perf.get(key)
                        mss_rows.append({"field": key, "value": value})
            self._set_dynamic_rows(self.ti_tcp_health["mss_table"], mss_rows, ["field", "value"])

        self._set_json_text(self.ti_tcp_health["json_handshakes"], hand if hand else {})
        self._set_json_text(self.ti_tcp_health["json_reliability"], rel if rel else {})
        self._set_json_text(self.ti_tcp_health["json_performance"], perf if perf else {})

    def _refresh_ti_top_entities(self, analysis):
        top = analysis.get("global_results", {}).get("top_entities", {})
        ip = top.get("ip_talkers", {}) if isinstance(top, dict) else {}
        mac = top.get("mac_talkers", {}) if isinstance(top, dict) else {}
        ports = top.get("ports", {}) if isinstance(top, dict) else {}

        self._set_dynamic_rows(self.ti_top_entities["ip_src"], ip.get("top_src", []) if isinstance(ip, dict) else [])
        self._set_dynamic_rows(self.ti_top_entities["ip_dst"], ip.get("top_dst", []) if isinstance(ip, dict) else [])
        split = ip.get("internal_external", {}) if isinstance(ip, dict) else {}
        split_rows = [(k, str(split.get(k))) for k in sorted(split.keys())] if isinstance(split, dict) else []
        self._set_kv_rows(self.ti_top_entities["ip_split"], split_rows)

        self._set_dynamic_rows(self.ti_top_entities["mac_src"], mac.get("top_src", []) if isinstance(mac, dict) else [])
        self._set_dynamic_rows(self.ti_top_entities["mac_dst"], mac.get("top_dst", []) if isinstance(mac, dict) else [])

        tcp = ports.get("tcp", {}) if isinstance(ports, dict) else {}
        udp = ports.get("udp", {}) if isinstance(ports, dict) else {}
        self._set_dynamic_rows(self.ti_top_entities["tcp_ports"], tcp.get("top_dst_ports", []) if isinstance(tcp, dict) else [])
        self._set_dynamic_rows(self.ti_top_entities["udp_ports"], udp.get("top_dst_ports", []) if isinstance(udp, dict) else [])

        self._set_json_text(self.ti_top_entities["json_top_entities"], top if top else {})
        self._set_json_text(self.ti_top_entities["json_ip_talkers"], ip if ip else {})
        self._set_json_text(self.ti_top_entities["json_mac_talkers"], mac if mac else {})
        self._set_json_text(self.ti_top_entities["json_ports"], ports if ports else {})

    def _refresh_ti_security_signals(self, analysis):
        scan = analysis.get("global_results", {}).get("scan_signals", {})
        arp = analysis.get("global_results", {}).get("arp_lan_signals", {})
        dns = analysis.get("global_results", {}).get("dns_anomalies", {})

        def _kv_rows(obj, keys=None):
            rows = []
            if isinstance(obj, dict):
                iterable = keys if keys is not None else sorted(obj.keys())
                for key in iterable:
                    if key not in obj:
                        continue
                    value = obj.get(key)
                    if key.endswith("_pct") or key.endswith("_percent") or key.endswith("_rate"):
                        value_text = _fmt_pct(value)
                    else:
                        value_text = str(value)
                    rows.append((key, value_text))
            return rows

        distinct_ports = scan.get("distinct_ports", {}) if isinstance(scan, dict) else {}
        ports_keys = ["src_ip", "max_count"]
        self._set_kv_rows(self.ti_security_signals["distinct_ports"], _kv_rows(distinct_ports, ports_keys + [k for k in sorted(distinct_ports.keys()) if k not in ports_keys]))

        distinct_ips = scan.get("distinct_ips", {}) if isinstance(scan, dict) else {}
        self._set_kv_rows(self.ti_security_signals["distinct_ips"], _kv_rows(distinct_ips))

        syn_ratio = scan.get("tcp_syn_ratio", {}) if isinstance(scan, dict) else {}
        syn_keys = ["syn_count", "synack_count", "ratio", "ratio_note"]
        self._set_kv_rows(self.ti_security_signals["syn_ratio"], _kv_rows(syn_ratio, syn_keys + [k for k in sorted(syn_ratio.keys()) if k not in syn_keys]))

        scan_extra = []
        if isinstance(scan, dict):
            for key in sorted(scan.keys()):
                if key in ("distinct_ports", "distinct_ips", "tcp_syn_ratio"):
                    continue
                value = scan.get(key)
                if isinstance(value, (dict, list)):
                    value_text = json.dumps(value)
                else:
                    value_text = str(value)
                scan_extra.append((key, value_text))
        self._set_kv_rows(self.ti_security_signals["scan_extra"], scan_extra)

        multiple_macs = arp.get("multiple_macs", {}) if isinstance(arp, dict) else {}
        self._set_kv_rows(self.ti_security_signals["multiple_macs"], _kv_rows(multiple_macs, ["count"] + [k for k in sorted(multiple_macs.keys()) if k != "examples"]))
        self._set_dynamic_rows(self.ti_security_signals["multiple_examples"], (multiple_macs.get("examples") or [])[:200])

        arp_changes = arp.get("arp_changes", {}) if isinstance(arp, dict) else {}
        self._set_kv_rows(self.ti_security_signals["arp_changes"], _kv_rows(arp_changes, ["count", "threshold"] + [k for k in sorted(arp_changes.keys()) if k not in ("top_changes",)]))
        self._set_dynamic_rows(self.ti_security_signals["arp_changes_table"], (arp_changes.get("top_changes") or [])[:200])

        arp_extra = []
        if isinstance(arp, dict):
            for key in sorted(arp.keys()):
                if key in ("multiple_macs", "arp_changes"):
                    continue
                value = arp.get(key)
                if isinstance(value, (dict, list)):
                    value_text = json.dumps(value)
                else:
                    value_text = str(value)
                arp_extra.append((key, value_text))
        self._set_kv_rows(self.ti_security_signals["arp_extra"], arp_extra)

        entropy = dns.get("entropy", {}) if isinstance(dns, dict) else {}
        self._set_kv_rows(self.ti_security_signals["entropy"], _kv_rows(entropy, ["count"] + [k for k in sorted(entropy.keys()) if k != "samples"]))
        self._set_dynamic_rows(self.ti_security_signals["entropy_samples"], (entropy.get("samples") or [])[:200])

        long_labels = dns.get("long_labels", {}) if isinstance(dns, dict) else {}
        self._set_kv_rows(self.ti_security_signals["long_labels"], _kv_rows(long_labels, ["count"] + [k for k in sorted(long_labels.keys()) if k != "samples"]))
        self._set_dynamic_rows(self.ti_security_signals["long_samples"], (long_labels.get("samples") or [])[:200])

        nxdomain = dns.get("nxdomain", {}) if isinstance(dns, dict) else {}
        self._set_kv_rows(self.ti_security_signals["nxdomain"], _kv_rows(nxdomain))

        dns_extra = []
        if isinstance(dns, dict):
            for key in sorted(dns.keys()):
                if key in ("entropy", "long_labels", "nxdomain"):
                    continue
                value = dns.get(key)
                if isinstance(value, (dict, list)):
                    value_text = json.dumps(value)
                else:
                    value_text = str(value)
                dns_extra.append((key, value_text))
        self._set_kv_rows(self.ti_security_signals["dns_extra"], dns_extra)

        self._set_json_text(self.ti_security_signals["json_scan"], scan if scan else {})
        self._set_json_text(self.ti_security_signals["json_arp"], arp if arp else {})
        self._set_json_text(self.ti_security_signals["json_dns"], dns if dns else {})

    def _refresh_ti_time_series(self, analysis):
        raw_time_series = analysis.get("time_series", {})
        ts_obj = raw_time_series if isinstance(raw_time_series, dict) else {}

        packet_chunks = ts_obj.get("packet_chunks")
        if packet_chunks is None:
            packet_chunks = analysis.get("packet_chunks", {})
        packet_chunks = packet_chunks if isinstance(packet_chunks, dict) else {}
        chunks = packet_chunks.get("chunks")
        if chunks is None:
            chunks = packet_chunks if isinstance(packet_chunks, list) else []
        chunks = chunks if isinstance(chunks, list) else []

        series = ts_obj.get("time_series") or ts_obj.get("series") or ts_obj.get("buckets") or ts_obj.get("traffic")
        if series is None and isinstance(raw_time_series, list):
            series = raw_time_series
        if series is None:
            series = ts_obj.get("time_series", {}) or ts_obj

        points = []
        if isinstance(series, dict):
            if isinstance(series.get("buckets"), list):
                points = series.get("buckets")
            elif isinstance(series.get("series"), list):
                points = series.get("series")
            elif isinstance(series.get("time_series"), list):
                points = series.get("time_series")
            elif isinstance(series.get("points"), list):
                points = series.get("points")
            elif isinstance(series.get("data"), list):
                points = series.get("data")
            else:
                points = [{"bucket": key, "value": value} for key, value in series.items()]
        elif isinstance(series, list):
            points = series

        self._set_dynamic_rows(self.ti_time_series["series"], points)
        self._set_dynamic_rows(self.ti_time_series["chunks"], chunks)

        def _get_numeric(item, keys):
            for key in keys:
                value = item.get(key)
                if isinstance(value, (int, float)):
                    return value
            return 0

        def _top_chunks(items, metric_keys, top_n=3):
            indexed = []
            for idx, item in enumerate(items):
                if isinstance(item, dict):
                    metric = _get_numeric(item, metric_keys)
                    indexed.append((idx, metric, item))
            ranked = sorted(indexed, key=lambda x: (-x[1], x[0]))[:top_n]
            rows = []
            for rank, (idx, metric, item) in enumerate(ranked, start=1):
                label = item.get("start_us") or item.get("start") or item.get("bucket") or idx
                rows.append({"rank": rank, "chunk": label, "bytes": metric})
            return rows

        top_bytes_rows = _top_chunks(chunks, ["bytes", "bytes_captured", "bytes_total", "bytes_captured_total"])
        top_packets_rows = _top_chunks(chunks, ["packets", "packets_total"])
        self._set_dynamic_rows(self.ti_time_series["top_bytes"], top_bytes_rows, ["rank", "chunk", "bytes"])
        self._set_dynamic_rows(self.ti_time_series["top_packets"], top_packets_rows, ["rank", "chunk", "packets"])

        self._set_json_text(self.ti_time_series["json_time_series"], raw_time_series if raw_time_series else {})
        self._set_json_text(self.ti_time_series["json_packet_chunks"], packet_chunks if packet_chunks else {})

    def _refresh_dashboard_charts(self, analysis):
        protocol = analysis.get("global_results", {}).get("protocol_mix", {})
        counts = protocol.get("protocol_counts") if isinstance(protocol, dict) else None
        percents = protocol.get("protocol_percentages") if isinstance(protocol, dict) else None
        labels = []
        values = []
        if isinstance(percents, dict) and percents:
            labels = list(percents.keys())
            values = [percents[k] for k in labels]
        elif isinstance(counts, dict) and counts:
            labels = list(counts.keys())
            total = sum(v for v in counts.values() if isinstance(v, (int, float)))
            values = [(float(counts[k]) / total * 100.0) if total else 0.0 for k in labels]
        self._mpl_pie(self.chart_frames["Protocols"], labels, values, "Protocol Mix")

        gs = analysis.get("global_results", {}).get("global_stats", {})
        ip_versions = {}
        if isinstance(gs, dict):
            ip_versions = gs.get("ip_versions") or (gs.get("distributions", {}) or {}).get("ip_versions") or {}
        if isinstance(ip_versions, dict) and ip_versions:
            v4 = ip_versions.get("4") or ip_versions.get(4) or 0
            v6 = ip_versions.get("6") or ip_versions.get(6) or 0
            ip_labels = ["IPv4", "IPv6"]
            ip_values = [v4, v6]
        else:
            ip_labels, ip_values = [], []
        self._mpl_pie(self.chart_frames["IP Versions"], ip_labels, ip_values, "IP Version Mix")

        talkers = analysis.get("global_results", {}).get("top_entities", {}).get("ip_talkers", {}).get("top_src", [])
        if isinstance(talkers, list):
            sorted_talkers = sorted([t for t in talkers if isinstance(t, dict)], key=lambda x: x.get("bytes", 0), reverse=True)[:10]
            labels = [t.get("ip", "?") for t in sorted_talkers]
            values = [t.get("bytes", 0) for t in sorted_talkers]
        else:
            labels, values = [], []
        self._mpl_bar(
            self.chart_frames["Talkers"],
            labels,
            values,
            "Top Source IPs by Bytes",
            orientation="h",
            label_fontsize=8,
            xlabel="Bytes",
        )

        flow_analytics = analysis.get("global_results", {}).get("flow_analytics", {})
        heavy = flow_analytics.get("heavy_hitters", {}) if isinstance(flow_analytics, dict) else {}
        top_by_bytes = heavy.get("top_by_bytes", []) if isinstance(heavy, dict) else []
        top_by_packets = heavy.get("top_by_packets", []) if isinstance(heavy, dict) else []
        if isinstance(top_by_bytes, list):
            top_by_bytes = top_by_bytes[:8]
        if isinstance(top_by_packets, list):
            top_by_packets = top_by_packets[:8]
        self._render_top_flows(
            self.chart_frames["Top Flows (Bytes)"],
            top_by_bytes if isinstance(top_by_bytes, list) else [],
            "Top Flows by Bytes",
            "bytes",
            "Bytes",
        )
        self._render_top_flows(
            self.chart_frames["Top Flows (Packets)"],
            top_by_packets if isinstance(top_by_packets, list) else [],
            "Top Flows by Packets",
            "packets",
            "Packets",
        )

        states = flow_analytics.get("states", {}) if isinstance(flow_analytics, dict) else {}
        if isinstance(states, dict) and states:
            state_labels = list(states.keys())
            state_values = [states[k] for k in state_labels]
        else:
            state_labels, state_values = [], []
        self._mpl_bar(
            self.chart_frames["Flow States"],
            state_labels,
            state_values,
            "Flow State Breakdown",
            xrot=30,
        )

        tcp = analysis.get("global_results", {}).get("tcp_reliability", {})
        if isinstance(tcp, dict):
            labels = ["Retrans", "Out-of-order", "Dup ACK", "RST"]
            values = [tcp.get("retransmission_rate"), tcp.get("out_of_order_rate"), tcp.get("dup_ack_rate"), tcp.get("rst_rate")]
            values = [v if v is not None else 0 for v in values]
        else:
            labels, values = [], []
        self._mpl_bar(self.chart_frames["TCP"], labels, values, "TCP Reliability Rates", xrot=30)

        packet_stats = analysis.get("global_results", {}).get("packet_size_stats", {})
        hist = packet_stats.get("histogram", {}) if isinstance(packet_stats, dict) else {}
        bucket_order = ["0-63", "64-127", "128-511", "512-1023", "1024-1514", "jumbo"]
        labels = [b for b in bucket_order if b in hist]
        values = [hist.get(b) for b in labels]
        self._mpl_hist(self.chart_frames["Packet Sizes"], labels, values, "Packet Size Histogram")

        # Traffic time series
        ts_obj = analysis.get("time_series", {})
        series = None
        if isinstance(ts_obj, dict):
            series = ts_obj.get("time_series") or ts_obj.get("buckets") or ts_obj.get("series") or ts_obj.get("traffic")
        if series is None and isinstance(ts_obj, list):
            series = ts_obj
        points = []
        if isinstance(series, list):
            points = series
        elif isinstance(series, dict):
            if isinstance(series.get("buckets"), list):
                points = series.get("buckets")
            elif isinstance(series.get("series"), list):
                points = series.get("series")
            elif isinstance(series.get("time_series"), list):
                points = series.get("time_series")
            elif isinstance(series.get("traffic"), list):
                points = series.get("traffic")

        x = []
        packets = []
        bytes_ = []
        for idx, p in enumerate(points or []):
            if not isinstance(p, dict):
                continue
            ts = p.get("start_us") or p.get("timestamp_us") or p.get("start") or p.get("bucket_start_us")
            label = _fmt_ts_utc(ts) if ts else str(idx)
            x.append(label)
            packets.append(p.get("packets") or p.get("packet_count") or 0)
            bytes_.append(p.get("bytes") or p.get("bytes_captured") or p.get("bytes_original") or 0)

        if len(x) > 200:
            step = max(1, len(x) // 200)
            x = x[::step]
            packets = packets[::step]
            bytes_ = bytes_[::step]

        self._mpl_line(self.chart_frames["Traffic"], x, [{"name": "Packets", "y": packets}, {"name": "Bytes", "y": bytes_}], "Traffic Over Time")

    def _refresh_dashboard_diagnostics(self, analysis):
        findings = []
        thresholds = self._get_thresholds()

        def add_line(sev, title, detail):
            findings.append({"severity": sev, "message": f"[{sev}] {title}  {detail}"})

        capture_quality = analysis.get("global_results", {}).get("capture_health", {}).get("capture_quality", {})
        drops = None
        if isinstance(capture_quality, dict):
            drops = capture_quality.get("drops", {}).get("drop_rate")
        if drops is None:
            add_line("INFO", "Drop rate", "not available in this capture.")
        else:
            sev = self._sev_from_pct(
                drops,
                thresholds["drop_warn"],
                thresholds["drop_warn"],
                thresholds["drop_bad"],
            )
            add_line(sev, "Drop rate", f"{_fmt_pct(drops)}")

        hand = analysis.get("global_results", {}).get("tcp_handshakes", {})
        completion = hand.get("completion_rate") if isinstance(hand, dict) else None
        if completion is None:
            add_line("INFO", "Handshake completion", "not available in this capture.")
        else:
            sev = self._sev_from_pct(
                completion,
                thresholds["handshake_good"],
                thresholds["handshake_warn"],
                100.0,
            )
            total_hs = hand.get("handshakes_total") if isinstance(hand, dict) else None
            complete_hs = hand.get("handshakes_complete") if isinstance(hand, dict) else None
            if total_hs is not None and complete_hs is not None:
                incomplete_hs = hand.get("handshakes_incomplete") if isinstance(hand, dict) else None
                if incomplete_hs is None:
                    try:
                        incomplete_hs = int(total_hs) - int(complete_hs)
                    except Exception:
                        incomplete_hs = None
                if incomplete_hs is not None:
                    detail = f"{_fmt_count(complete_hs)} / {_fmt_count(total_hs)} ({_fmt_count(incomplete_hs)} incomplete)"
                else:
                    detail = f"{_fmt_count(complete_hs)} / {_fmt_count(total_hs)} complete"
            else:
                detail = f"{_fmt_pct(completion)}"
            add_line(sev, "Handshakes", detail)

        tcp_rel = analysis.get("global_results", {}).get("tcp_reliability", {})
        retr = tcp_rel.get("retransmission_rate") if isinstance(tcp_rel, dict) else None
        if retr is None:
            add_line("INFO", "Retransmission rate", "not available in this capture.")
        else:
            sev = self._sev_from_pct(
                retr,
                thresholds["retrans_warn"],
                thresholds["retrans_warn"],
                thresholds["retrans_bad"],
            )
            add_line(sev, "Retransmission rate", f"{_fmt_pct(retr)}")

        rst = tcp_rel.get("rst_rate") if isinstance(tcp_rel, dict) else None
        if rst is None:
            add_line("INFO", "RST rate", "not available in this capture.")
        else:
            sev = self._sev_from_pct(
                rst,
                thresholds["rst_warn"],
                thresholds["rst_warn"],
                thresholds["rst_bad"],
            )
            add_line(sev, "RST rate", f"{_fmt_pct(rst)}")

        scan = analysis.get("global_results", {}).get("scan_signals", {})
        distinct_ports = scan.get("distinct_ports", {}) if isinstance(scan, dict) else {}
        max_count = distinct_ports.get("max_count") if isinstance(distinct_ports, dict) else None
        if max_count is None:
            add_line("INFO", "Scan signals", "not available in this capture.")
        else:
            sev = "WARN" if max_count >= thresholds["scan_ports_warn"] else "GOOD"
            add_line(sev, "Scan signals", f"max distinct ports {max_count}")

        arp = analysis.get("global_results", {}).get("arp_lan_signals", {})
        multiple_macs = arp.get("multiple_macs", {}) if isinstance(arp, dict) else {}
        mac_count = multiple_macs.get("count") if isinstance(multiple_macs, dict) else None
        if mac_count is None:
            add_line("INFO", "ARP conflicts", "not available in this capture.")
        else:
            sev = "WARN" if mac_count >= thresholds["arp_conflict_warn"] else "GOOD"
            add_line(sev, "ARP conflicts", f"multiple MACs {mac_count}")

        dns = analysis.get("global_results", {}).get("dns_anomalies", {})
        nxdomain = dns.get("nxdomain", {}) if isinstance(dns, dict) else {}
        spike = nxdomain.get("spike_detected") if isinstance(nxdomain, dict) else None
        if spike is None:
            add_line("INFO", "NXDOMAIN spike", "not available in this capture.")
        else:
            if thresholds["nxdomain_warn"]:
                sev = "WARN" if spike else "GOOD"
                detail = "spike detected" if spike else "no spike"
            else:
                sev = "INFO"
                detail = "disabled"
            add_line(sev, "NXDOMAIN spike", detail)

        self._set_dynamic_rows(self.diag_table, findings, ["severity", "message"])

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    win = AsphaltApp()
    win.show()
    sys.exit(app.exec())
