"""
Port scanner panel - a thin Qt UI over the EXISTING engine in
../Port Scanner/port_scanner.py. It reuses that module's primitives
verbatim (parse_ports, resolve_target, RateLimiter, scan_port,
scan_udp_port, get_service_name); nothing is reimplemented here.

run_scan() in the engine only returns once everything is done, so for a
live-updating table we drive the same scan_port/scan_udp_port calls through
our own ThreadPoolExecutor in a QThread and emit one signal per finished
port. The "Polite" preset maps to the engine's rate-limit + randomize
behaviour exactly like the CLI's --polite.
"""
import concurrent.futures
import random
import time

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
                               QPushButton, QComboBox, QCheckBox, QLabel,
                               QTableWidget, QTableWidgetItem, QHeaderView,
                               QSpinBox, QAbstractItemView)

from ..core import bridge as eng
from .. import theme as T


class ScanWorker(QThread):
    found = Signal(dict)          # one open/interesting port
    progress = Signal(int, int)   # done, total
    done = Signal(int, float)     # open_count, elapsed_s
    failed = Signal(str)

    def __init__(self, target, port_spec, protocol, threads, timeout,
                 rate, randomize, deep, parent=None):
        super().__init__(parent)
        self.target = target
        self.port_spec = port_spec
        self.protocol = protocol
        self.threads = threads
        self.timeout = timeout
        self.rate = rate
        self.randomize = randomize
        self.deep = deep
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        ps = eng.port_scanner
        try:
            ip = ps.resolve_target(self.target)
            ports = ps.parse_ports(self.port_spec)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
            return
        if not ports:
            self.failed.emit("no valid ports in that spec")
            return
        if self.randomize:
            ports = list(ports)
            random.shuffle(ports)

        limiter = ps.RateLimiter(self.rate)
        total = len(ports)
        done = 0
        open_count = 0
        start = time.perf_counter()

        def work(p):
            if self._cancel:
                return None
            if self.protocol == "udp":
                return ps.scan_udp_port(ip, p, self.timeout, limiter=limiter)
            return ps.scan_port(ip, p, self.timeout, do_banner=True,
                                deep_probe=self.deep, limiter=limiter)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            for r in pool.map(work, ports):
                if self._cancel:
                    break
                done += 1
                if r and r["status"] in ("open", "open|filtered"):
                    open_count += 1
                    r["_ip"] = ip
                    self.found.emit(r)
                if done % 25 == 0 or done == total:
                    self.progress.emit(done, total)

        self.done.emit(open_count, time.perf_counter() - start)


class PortScanPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 6, 12, 10)
        root.setSpacing(7)

        input_qss = T.input_qss(height=24)
        r1 = QHBoxLayout()
        r1.setSpacing(7)
        self.target = QLineEdit("127.0.0.1")
        self.target.setPlaceholderText("target host / IP")
        self.ports = QLineEdit("1-1024")
        self.ports.setPlaceholderText("80, 1-1024, 22,443,8000-8100")
        for w in (self.target, self.ports):
            w.setStyleSheet(input_qss)
        r1.addWidget(self.target, 3)
        r1.addWidget(self.ports, 4)
        root.addLayout(r1)

        r2 = QHBoxLayout()
        r2.setSpacing(7)
        self.proto = QComboBox()
        self.proto.addItems(["TCP", "UDP"])
        self.threads = QSpinBox()
        self.threads.setRange(1, 500)
        self.threads.setValue(100)
        self.threads.setPrefix("thr ")
        self.rate = QSpinBox()
        self.rate.setRange(0, 5000)
        self.rate.setValue(0)
        self.rate.setPrefix("rate ")
        self.polite = QCheckBox("Polite")
        self.polite.setToolTip("rate 50 + randomized order (engine --polite)")
        self.deep = QCheckBox("Deep")
        self.deep.setToolTip("HTTP/TLS cert probe on open web ports")
        for w in (self.proto, self.threads, self.rate):
            w.setStyleSheet(input_qss)
        for c in (self.polite, self.deep):
            c.setStyleSheet(T.checkbox_qss())
        r2.addWidget(self.proto)
        r2.addWidget(self.threads)
        r2.addWidget(self.rate)
        r2.addWidget(self.polite)
        r2.addWidget(self.deep)
        r2.addStretch(1)
        root.addLayout(r2)

        r3 = QHBoxLayout()
        r3.setSpacing(9)
        self.scan_btn = QPushButton("SCAN")
        self.scan_btn.setCursor(Qt.PointingHandCursor)
        self.scan_btn.setStyleSheet(T.primary_btn_qss())
        self.scan_btn.clicked.connect(self._toggle)
        self.status = QLabel("idle")
        self.status.setStyleSheet(f"color:{T.hexs(T.TEXT_MUTED)};font:8pt '{T.MONO}';")
        r3.addWidget(self.scan_btn)
        r3.addWidget(self.status, 1)
        root.addLayout(r3)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["  PORT", "SERVICE", "VERSION / BANNER", "ms"])
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setDefaultSectionSize(24)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.setStyleSheet(T.table_qss())
        root.addWidget(self.table, 1)

        if not eng.ENGINE_OK:
            self.scan_btn.setEnabled(False)
            self.status.setText("engine unavailable: " + str(eng.ENGINE_ERROR))

    # -- actions -----------------------------------------------------------
    def _toggle(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.status.setText("cancelling...")
            return
        self.table.setRowCount(0)
        rate = self.rate.value()
        randomize = False
        if self.polite.isChecked():
            rate = rate or 50
            randomize = True
        self.worker = ScanWorker(
            self.target.text().strip(), self.ports.text().strip(),
            self.proto.currentText().lower(), self.threads.value(),
            2.0, rate, randomize, self.deep.isChecked(), self)
        self.worker.found.connect(self._on_found)
        self.worker.progress.connect(self._on_progress)
        self.worker.done.connect(self._on_done)
        self.worker.failed.connect(self._on_failed)
        self.scan_btn.setText("STOP")
        self.status.setText("resolving...")
        self.worker.start()

    def _on_found(self, r):
        banner = (r.get("version") or r.get("banner") or "").strip().replace("\n", " ")
        if len(banner) > 90:
            banner = banner[:88] + ".."
        row = self.table.rowCount()
        self.table.insertRow(row)
        dot = "●" if r["status"] == "open" else "◐"
        cells = [f"{dot} {r['port']}", r.get("service", ""), banner,
                 "" if r.get("response_ms") is None else f"{r['response_ms']:.0f}"]
        for col, text in enumerate(cells):
            it = QTableWidgetItem(text)
            if col == 0:
                it.setForeground(T.POSITIVE if r["status"] == "open" else T.WARN)
            elif col == 1:
                it.setForeground(T.ACCENT)
            elif col == 2:
                it.setForeground(T.TEXT_MUTED)
            elif col == 3:
                it.setForeground(T.TEXT_DIM)
                it.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.table.setItem(row, col, it)

    def _on_progress(self, done, total):
        self.status.setText(f"scanning {done}/{total} ports  |  {self.table.rowCount()} open")

    def _on_done(self, open_count, elapsed):
        self.scan_btn.setText("SCAN")
        self.status.setText(f"done: {open_count} open in {elapsed:.1f}s")

    def _on_failed(self, msg):
        self.scan_btn.setText("SCAN")
        self.status.setText("error: " + msg)

    def shutdown(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.worker.wait(2000)
