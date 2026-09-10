"""
Packet sniffer / analyzer panel - a thin Qt UI over the EXISTING Asphalt
engine in ../Asphalt/src. It reuses that project's pieces verbatim (the
ScapyBackend live capture, PacketDecoder, the AnalysisEngine and its analyzer
registry, and the packet-filter expression compiler); nothing is decoded or
analyzed twice here.

Asphalt's `capture-decode` CLI drains the capture queue and prints one line
per packet. A HUD cannot do that at ten thousand packets a second, so the
worker drains the same queue, decodes with the same decoder, feeds every
packet to the same AnalysisEngine, and emits one batched signal every
_BATCH_MS - the GUI thread only ever receives finished rows.

The analyzers accumulate in on_packet() and only read in on_end(), so
finalize() is a pure snapshot: SIGNALS polls it live while the capture runs,
and only while that view is on screen, so an idle sniffer costs nothing.
"""
import time

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
                               QPushButton, QComboBox, QLabel, QTableWidget,
                               QTableWidgetItem, QHeaderView, QAbstractItemView,
                               QStackedWidget)

from ..core import bridge as eng
from ..widgets import Sparkline
from .. import theme as T

_BATCH_MS = 200            # how often finished rows reach the GUI thread
_REPORT_MS = 1500          # how often SIGNALS re-reads the analyzers
_MAX_ROWS = 600            # rows kept in the live table
_ANALYZERS = ("protocol_mix", "top_entities", "abnormal_activity",
              "scan_signals", "arp_lan_signals", "dns_anomalies")


def _endpoint(ip, port, mac):
    """Best available address for a packet end: ip[:port], else MAC."""
    if ip:
        return f"{ip}:{port}" if port is not None else ip
    return mac or "-"


def _format_row(decoded, raw):
    """One display row (all strings) built off the decoded packet."""
    secs, us = divmod(raw.timestamp_us, 1_000_000)
    stamp = time.strftime("%H:%M:%S", time.localtime(secs)) + f".{us // 1000:03d}"

    src = _endpoint(decoded.src_ip or decoded.arp_sender_ip,
                    decoded.src_port, decoded.src_mac)
    dst = _endpoint(decoded.dst_ip, decoded.dst_port, decoded.dst_mac)

    proto = decoded.l4_protocol
    if not proto:
        stack = decoded.protocol_stack
        proto = stack[-1] if stack else "?"

    bits = [decoded.stack_summary]
    if decoded.tcp_flags:
        bits.append("[" + " ".join(decoded.tcp_flag_names) + "]")
    if decoded.dns_qname:
        kind = "?" if decoded.dns_is_query else "="
        bits.append(f"dns{kind} {decoded.dns_qname}")
    if decoded.is_vlan:
        bits.append("vlan")
    if decoded.is_ipv4_fragment or decoded.is_ipv6_fragment:
        bits.append("frag")
    if decoded.quality_flags:
        bits.append(" ".join(n.lower() for n in decoded.quality_names))

    return (stamp, src, dst, proto, str(raw.original_length), "  ".join(bits))


def _friendly(msg):
    """Turn the engine's raw failure into something actionable in a HUD."""
    low = msg.lower()
    if "npcap" in low or "cannot find the file" in low or "no such device" in low:
        return msg + "  -  install Npcap in WinPcap-compatible mode"
    if "permission" in low or "access is denied" in low or "operation not permitted" in low:
        return msg + "  -  live capture needs an elevated session"
    return msg


# ------------------------------------------------------------------ workers --
class InterfaceWorker(QThread):
    """list_interfaces() touches Npcap, so it never runs on the GUI thread."""
    ready = Signal(list)
    failed = Signal(str)

    def run(self):
        api = eng.load_sniffer()
        if api is None:
            self.failed.emit(eng.SNIFF_ERROR or "Asphalt engine unavailable")
            return
        if not eng.SNIFF_HAS_SCAPY:
            self.failed.emit("scapy is not installed  -  pip install scapy")
            return
        try:
            self.ready.emit(api.ScapyBackend().list_interfaces())
        except Exception as exc:
            self.failed.emit(_friendly(f"{type(exc).__name__}: {exc}"))


class SniffWorker(QThread):
    batch = Signal(list, dict)     # display rows, capture stats
    report = Signal(dict)          # analysis snapshot
    running = Signal(str)          # capture is live on this interface
    failed = Signal(str)

    def __init__(self, iface, bpf, expr, parent=None):
        super().__init__(parent)
        self.iface = iface
        self.bpf = bpf
        self.expr = expr
        self._cancel = False
        self._want_report = False

    def cancel(self):
        self._cancel = True

    def set_report_enabled(self, on):
        self._want_report = bool(on)

    def run(self):
        api = eng.load_sniffer()
        if api is None:
            self.failed.emit(eng.SNIFF_ERROR or "Asphalt engine unavailable")
            return
        try:
            predicate = api.compile_packet_filter(self.expr) if self.expr else None
        except Exception as exc:
            self.failed.emit(f"display filter: {exc}")
            return
        try:
            backend = api.ScapyBackend()
        except Exception as exc:
            self.failed.emit(_friendly(str(exc)))
            return

        analysis = api.AnalysisEngine(
            [api.create_analyzer(name) for name in _ANALYZERS],
            capture_info={"interface": self.iface, "capture_filter": self.bpf or None},
        )
        decoder = api.PacketDecoder()
        config = api.CaptureConfig(interface=self.iface,
                                   filter=self.bpf or None,
                                   buffer_size=20000)
        try:
            session = backend.start(config)
        except Exception as exc:
            self.failed.emit(_friendly(str(exc)))
            return

        self.running.emit(self.iface)
        packet_id = 0
        pending = []
        last_batch = last_report = time.monotonic()
        try:
            while not self._cancel:
                packets = backend.get_packets(session, count=256)
                if not packets:
                    time.sleep(0.02)

                for pkt in packets:
                    packet_id += 1
                    data = pkt["data"]
                    raw = api.RawPacket(
                        packet_id=packet_id,
                        timestamp_us=int(pkt["ts"] * 1_000_000),
                        captured_length=len(data),
                        original_length=pkt.get("wirelen", len(data)),
                        link_type=1,               # DLT_EN10MB, as the CLI does
                        data=data,
                        pcap_ref="live:0:0",
                    )
                    try:
                        decoded = decoder.decode(raw)
                    except Exception:
                        continue
                    analysis.process_packet(decoded)
                    # the display filter is exactly that: the analyzers still
                    # see every captured packet.
                    if predicate and not predicate(decoded.to_dict()):
                        continue
                    pending.append(_format_row(decoded, raw))

                now = time.monotonic()
                if now - last_batch >= _BATCH_MS / 1000:
                    try:
                        stats = backend.get_stats(session)
                    except Exception:
                        stats = {}
                    self.batch.emit(pending[-_MAX_ROWS:], stats)
                    pending = []
                    last_batch = now

                if self._want_report and now - last_report >= _REPORT_MS / 1000:
                    self._emit_report(analysis)
                    last_report = now
        finally:
            try:
                backend.stop(session)
            except Exception:
                pass
            self._emit_report(analysis)

    def _emit_report(self, analysis):
        try:
            self.report.emit(analysis.finalize().to_dict())
        except Exception:
            pass


# ------------------------------------------------------- report -> signals --
def _signal_rows(report):
    """Fold the analyzers' output into (severity, signal, detail) lines."""
    results = report.get("global_results", {})
    rows = []

    for finding in results.get("abnormal_activity", {}).get("findings", []):
        kind = finding.get("type")
        sev = finding.get("severity", "low")
        if kind == "possible_port_scan":
            for source in finding.get("sources", [])[:3]:
                rows.append((sev, "port scan",
                             f"{source['src_ip']} touched "
                             f"{source['unique_dst_ports']} ports"))
        elif kind == "high_tcp_rst_ratio":
            rows.append((sev, "TCP resets",
                         f"{finding.get('ratio', 0) * 100:.0f}% of TCP "
                         f"({finding.get('count', 0)} packets)"))
        elif kind == "malformed_packets":
            rows.append((sev, "malformed packets", str(finding.get("count", 0))))
        elif kind == "syn_without_reply":
            rows.append((sev, "SYN, no reply", f"{finding.get('flows', 0)} flows"))
        elif kind == "synack_without_ack":
            rows.append((sev, "half-open handshakes",
                         f"{finding.get('flows', 0)} flows"))

    arp = results.get("arp_lan_signals", {})
    for example in arp.get("multiple_macs", {}).get("examples", [])[:3]:
        rows.append(("high", "ARP conflict",
                     f"{example['ip']} claimed by {len(example['macs'])} MACs"))
    churn = arp.get("arp_changes", {})
    if churn.get("count"):
        top = churn.get("top_changes", [{}])[0]
        rows.append(("medium", "ARP churn",
                     f"{top.get('ip', '?')} rebound {top.get('changes', 0)}x"))

    dns = results.get("dns_anomalies", {})
    nx = dns.get("nxdomain", {})
    if nx.get("spike_detected"):
        rows.append(("medium", "NXDOMAIN spike",
                     f"{nx.get('nxdomain_pct', 0)}% of "
                     f"{nx.get('total_responses', 0)} responses"))
    if dns.get("entropy", {}).get("count"):
        rows.append(("medium", "high-entropy DNS",
                     f"{dns['entropy']['count']} names - tunnelling or DGA"))
    if dns.get("long_labels", {}).get("count"):
        rows.append(("low", "long DNS labels",
                     f"{dns['long_labels']['count']} names"))

    ratio = results.get("scan_signals", {}).get("tcp_syn_ratio", {})
    if ratio.get("ratio") and ratio["ratio"] >= 3:
        rows.append(("medium", "SYN / SYN-ACK",
                     f"{ratio['ratio']:.1f}:1 ({ratio.get('syn_count', 0)} SYNs)"))

    order = {"high": 0, "medium": 1, "low": 2}
    rows.sort(key=lambda r: order.get(r[0], 3))
    return rows


def _summary_rows(report):
    """Fold the same report into (metric, value) lines."""
    results = report.get("global_results", {})
    stats = report.get("stats", {})
    rows = [("packets analyzed", f"{stats.get('packets_total', 0):,}")]

    duration = stats.get("duration_us", 0) / 1_000_000
    if duration:
        rows.append(("capture window", f"{duration:.1f}s"))
    total_bytes = stats.get("bytes_captured_total", 0)
    if total_bytes:
        rows.append(("captured", _si_bytes(total_bytes)))

    mix = results.get("protocol_mix", {}).get("protocol_percentages", {})
    for name, pct in sorted(mix.items(), key=lambda kv: -kv[1])[:4]:
        rows.append((name.lower(), f"{pct:.0f}%"))

    talkers = results.get("top_entities", {}).get("ip_talkers", {})
    for entry in talkers.get("top_src", [])[:3]:
        rows.append(("talker " + entry["ip"], f"{entry['bytes_pct']:.0f}% of bytes"))
    split = talkers.get("internal_external", {})
    if split.get("external_bytes_pct") is not None:
        rows.append(("leaving the LAN", f"{split['external_bytes_pct']:.0f}% of bytes"))

    ports = results.get("top_entities", {}).get("ports", {})
    for proto in ("tcp", "udp"):
        for entry in ports.get(proto, {}).get("top_dst_ports", [])[:2]:
            # a scan leaves hundreds of ports tied at one packet each; those
            # belong in SIGNALS, not in a "top ports" readout
            if entry["packets_pct"] < 5:
                continue
            service = entry["service"]
            label = f"{proto} {entry['port']}"
            if service != "unknown":
                label += f" {service.lower()}"
            rows.append((label, f"{entry['packets_pct']:.0f}% of {proto}"))
    return rows


def _si_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0


# ------------------------------------------------------------------- panel --
class ModeButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet(
            f"QPushButton{{background:{T.hexs(T.SURFACE_2)};color:{T.hexs(T.TEXT_MUTED)};"
            f"border:1px solid {T.hexs(T.BORDER)};border-radius:{T.R_CTRL}px;"
            f"padding:3px 14px;font:700 8pt '{T.UI}';}}"
            f"QPushButton:checked{{background:{T.hexs(T.ACCENT)};color:{T.hexs(T.ACCENT_INK)};"
            f"border:1px solid {T.hexs(T.ACCENT)};}}")


def _table(headers, stretch):
    """A themed read-only table. `stretch` columns share the leftover width;
    the rest size to their contents. The HUD is only ~820px wide by default,
    so nothing is allowed to scroll sideways - long cells elide instead."""
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setShowGrid(False)
    t.setAlternatingRowColors(True)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setSelectionMode(QAbstractItemView.SingleSelection)
    t.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    t.setTextElideMode(Qt.ElideRight)
    t.setWordWrap(False)
    t.verticalHeader().setDefaultSectionSize(22)
    head = t.horizontalHeader()
    for col in range(len(headers)):
        head.setSectionResizeMode(
            col, QHeaderView.Stretch if col in stretch
            else QHeaderView.ResizeToContents)
    t.setStyleSheet(T.table_qss())
    return t


class SnifferPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.ifaces = None
        self._view = "live"
        self._tally = ""
        self._build()
        self._load_interfaces()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 6, 12, 10)
        root.setSpacing(7)
        input_qss = T.input_qss(height=24)

        r1 = QHBoxLayout()
        r1.setSpacing(7)
        self.iface = QComboBox()
        self.iface.setStyleSheet(input_qss)
        self.iface.setMinimumWidth(150)
        self.iface.addItem("loading interfaces...", None)
        self.bpf = QLineEdit()
        self.bpf.setPlaceholderText("capture filter (BPF) - tcp port 443")
        self.bpf.setToolTip("Berkeley Packet Filter, applied by the capture "
                            "driver: only matching traffic is ever read.")
        self.expr = QLineEdit()
        self.expr.setPlaceholderText("display filter - l4=tcp and not dst_port=443")
        self.expr.setToolTip("Asphalt filter expression, applied to the table "
                            "only. The analyzers still see every packet.")
        for w in (self.bpf, self.expr):
            w.setStyleSheet(input_qss)
        r1.addWidget(self.iface, 3)
        r1.addWidget(self.bpf, 3)
        r1.addWidget(self.expr, 4)
        root.addLayout(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(9)
        self.start_btn = QPushButton("SNIFF")
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.setStyleSheet(T.primary_btn_qss())
        self.start_btn.clicked.connect(self._toggle)
        self.spark = Sparkline(capacity=120, color=T.G_NET, floor=10.0)
        self.spark.setMinimumHeight(34)
        self.spark.setMaximumHeight(38)
        self.spark.set_label("packets/sec", "0")
        r2.addWidget(self.start_btn)
        r2.addWidget(self.spark, 1)
        root.addLayout(r2)

        r3 = QHBoxLayout()
        r3.setSpacing(6)
        self.btn_live = ModeButton("LIVE")
        self.btn_live.setChecked(True)
        self.btn_signals = ModeButton("SIGNALS")
        self.btn_live.clicked.connect(lambda: self._set_view("live"))
        self.btn_signals.clicked.connect(lambda: self._set_view("signals"))
        self.status = QLabel("idle")
        self.status.setStyleSheet(f"color:{T.hexs(T.TEXT_MUTED)};font:8pt '{T.MONO}';")
        r3.addWidget(self.btn_live)
        r3.addWidget(self.btn_signals)
        r3.addWidget(self.status, 1)
        root.addLayout(r3)

        self.stack = QStackedWidget()
        self.packets = _table(["  TIME", "SOURCE", "DESTINATION",
                               "PROTO", "LEN", "INFO"], stretch={1, 2, 5})
        self.stack.addWidget(self.packets)

        signals_page = QWidget()
        sig_row = QHBoxLayout(signals_page)
        sig_row.setContentsMargins(0, 0, 0, 0)
        sig_row.setSpacing(7)
        self.signals = _table(["  SIGNAL", "DETAIL"], stretch={1})
        self.summary = _table(["  METRIC", "VALUE"], stretch={0})
        sig_row.addWidget(self.signals, 3)
        sig_row.addWidget(self.summary, 2)
        self.stack.addWidget(signals_page)
        root.addWidget(self.stack, 1)

        api_missing = None
        if not eng.SNIFF_DIR or not eng.load_sniffer():
            api_missing = eng.SNIFF_ERROR or "Asphalt engine not found next to Overlay"
        elif not eng.SNIFF_HAS_SCAPY:
            api_missing = "scapy is not installed  -  pip install scapy"
        if api_missing:
            self.start_btn.setEnabled(False)
            self.status.setText(api_missing)

    # -- interfaces --------------------------------------------------------
    def _load_interfaces(self):
        if not self.start_btn.isEnabled():
            self.iface.clear()
            self.iface.addItem("unavailable", None)
            return
        self.ifaces = InterfaceWorker(self)
        self.ifaces.ready.connect(self._on_interfaces)
        self.ifaces.failed.connect(self._on_failed)
        self.ifaces.start()

    def _on_interfaces(self, interfaces):
        self.iface.clear()
        if not interfaces:
            self.iface.addItem("no interfaces found", None)
            self.start_btn.setEnabled(False)
            return
        best = 0
        for i, info in enumerate(interfaces):
            label = info.get("display_name") or info.get("name")
            ips = [ip for ip in (info.get("ips") or []) if ":" not in str(ip)]
            if ips:
                label += f"  {ips[0]}"
            self.iface.addItem(label, info.get("name"))
            self.iface.setItemData(i, info.get("description", ""), Qt.ToolTipRole)
            # prefer a real, addressed adapter over loopback
            if not best and ips and info.get("link_type") != "Loopback":
                best = i
        self.iface.setCurrentIndex(best)
        self.status.setText(f"{len(interfaces)} interfaces  |  idle")

    # -- capture -----------------------------------------------------------
    def _toggle(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.status.setText("stopping...")
            return
        iface = self.iface.currentData()
        if not iface:
            self.status.setText("pick an interface first")
            return
        self.packets.setRowCount(0)
        self.signals.setRowCount(0)
        self.summary.setRowCount(0)
        self.worker = SniffWorker(iface, self.bpf.text().strip(),
                                  self.expr.text().strip(), self)
        self.worker.batch.connect(self._on_batch)
        self.worker.report.connect(self._on_report)
        self.worker.running.connect(self._on_running)
        self.worker.failed.connect(self._on_failed)
        self.worker.finished.connect(self._on_finished)
        self.worker.set_report_enabled(self._view == "signals")
        self.start_btn.setText("STOP")
        self.status.setText("starting capture...")
        self.worker.start()

    def _on_running(self, iface):
        self.status.setText("capturing on " + iface)

    def _on_batch(self, rows, stats):
        pps = stats.get("packets_per_sec", 0)
        self.spark.push(pps)
        self.spark.set_label("packets/sec", f"{pps:,}")

        # newest first: in a HUD this short you should never have to scroll
        # to see what just happened
        for row in rows:
            self.packets.insertRow(0)
            for col, text in enumerate(row):
                item = QTableWidgetItem(text)
                if col in (0, 4):
                    item.setForeground(T.TEXT_DIM)
                elif col == 3:
                    item.setForeground(T.ACCENT)
                elif col == 5:
                    item.setForeground(T.TEXT_MUTED)
                if col == 4:
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.packets.setItem(0, col, item)
        while self.packets.rowCount() > _MAX_ROWS:
            self.packets.removeRow(self.packets.rowCount() - 1)

        total = stats.get("packets_total", 0)
        drops = stats.get("drops_total", 0)
        self._tally = f"{total:,} packets  |  {_si_bytes(stats.get('bytes_total', 0))}"
        if drops:
            self._tally += f"  |  {drops:,} dropped"
        self.status.setText("capturing  |  " + self._tally)

    def _on_report(self, report):
        rows = _signal_rows(report)
        self.signals.setRowCount(0)
        if not rows:
            self.signals.insertRow(0)
            quiet = QTableWidgetItem("  nothing anomalous yet")
            quiet.setForeground(T.TEXT_DIM)
            self.signals.setItem(0, 0, quiet)
            self.signals.setItem(0, 1, QTableWidgetItem(""))
        for sev, title, detail in rows:
            row = self.signals.rowCount()
            self.signals.insertRow(row)
            dot = QTableWidgetItem(f"● {title}")
            dot.setForeground({"high": T.DANGER, "medium": T.WARN}.get(sev, T.POSITIVE))
            detail_item = QTableWidgetItem(detail)
            detail_item.setForeground(T.TEXT_MUTED)
            self.signals.setItem(row, 0, dot)
            self.signals.setItem(row, 1, detail_item)

        self.summary.setRowCount(0)
        for metric, value in _summary_rows(report):
            row = self.summary.rowCount()
            self.summary.insertRow(row)
            key = QTableWidgetItem("  " + metric)
            key.setForeground(T.TEXT_MUTED)
            val = QTableWidgetItem(value)
            val.setForeground(T.TEXT)
            val.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.summary.setItem(row, 0, key)
            self.summary.setItem(row, 1, val)

    def _on_failed(self, msg):
        self.start_btn.setText("SNIFF")
        self.status.setText("error: " + msg)

    def _on_finished(self):
        self.start_btn.setText("SNIFF")
        if not self.status.text().startswith("error"):
            self.status.setText("stopped  |  " + (self._tally or "no packets"))

    def _set_view(self, view):
        self._view = view
        self.btn_live.setChecked(view == "live")
        self.btn_signals.setChecked(view == "signals")
        self.stack.setCurrentIndex(0 if view == "live" else 1)
        if self.worker and self.worker.isRunning():
            self.worker.set_report_enabled(view == "signals")

    def shutdown(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.worker.wait(3000)
        if self.ifaces and self.ifaces.isRunning():
            self.ifaces.wait(2000)
