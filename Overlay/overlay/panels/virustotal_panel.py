"""
VirusTotal panel - drag a file in and see its VirusTotal report.

Privacy-first and keyless by default: the file is hashed LOCALLY (SHA-256)
and only the hash is used - the file itself never leaves the machine. The
panel opens the public VirusTotal report for that hash in an embedded browser.

If you paste a free VirusTotal API key in Settings, it additionally queries
the API (v3 GET /files/{hash}) on a worker thread and shows a compact
detection banner (malicious / suspicious / harmless) above the report.
"""
import hashlib
import json
import urllib.request

from PySide6.QtCore import QThread, Signal, Qt, QUrl
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFileDialog

from .. import theme as T
from ..settings import settings

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView
    WEBENGINE_OK = True
except Exception as exc:  # pragma: no cover
    WEBENGINE_OK = False
    WEBENGINE_ERR = f"{type(exc).__name__}: {exc}"

_GUI = "https://www.virustotal.com/gui/file/{}"
_API = "https://www.virustotal.com/api/v3/files/{}"


class VtWorker(QThread):
    hashed = Signal(str, str)      # sha256, filename
    stats = Signal(dict)           # last_analysis_stats
    note = Signal(str)

    def __init__(self, path, api_key, parent=None):
        super().__init__(parent)
        self._path, self._key = path, api_key

    def run(self):
        import os
        try:
            h = hashlib.sha256()
            with open(self._path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            digest = h.hexdigest()
        except OSError as exc:
            self.note.emit(f"couldn't read file: {exc}")
            return
        self.hashed.emit(digest, os.path.basename(self._path))

        if not self._key:
            self.note.emit("keyless: showing the public report. Add a VT API "
                           "key in Settings for inline detection stats.")
            return
        try:
            req = urllib.request.Request(_API.format(digest),
                                         headers={"x-apikey": self._key})
            with urllib.request.urlopen(req, timeout=15) as r:
                payload = json.loads(r.read().decode("utf-8", "replace"))
            stats = (payload.get("data", {}).get("attributes", {})
                     .get("last_analysis_stats"))
            if stats:
                self.stats.emit(stats)
            else:
                self.note.emit("VT had no analysis stats for this file yet.")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                self.note.emit("not in VirusTotal yet — open the report to upload it.")
            elif exc.code == 401:
                self.note.emit("VT API key rejected (401). Check it in Settings.")
            else:
                self.note.emit(f"VT API error: HTTP {exc.code}")
        except Exception as exc:
            self.note.emit(f"VT lookup failed: {type(exc).__name__}")


class VirusTotalPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.setAcceptDrops(True)
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 8, 12, 10)
        root.setSpacing(7)

        # drop zone
        self.drop = QLabel("⤓  drag a file here to scan  ·  or")
        self.drop.setAlignment(Qt.AlignCenter)
        self.drop.setStyleSheet(
            f"color:{T.hexs(T.TEXT_MUTED)};font:9pt '{T.UI}';"
            f"border:1px dashed {T.hexs(T.BORDER)};border-radius:{T.R_CTRL}px;"
            f"padding:12px;")
        row = QHBoxLayout(); row.setSpacing(8)
        row.addWidget(self.drop, 1)
        self.pick = QPushButton("Choose file…")
        self.pick.setCursor(Qt.PointingHandCursor)
        self.pick.setStyleSheet(T.ghost_btn_qss())
        self.pick.clicked.connect(self._choose)
        row.addWidget(self.pick)
        root.addLayout(row)

        self.banner = QLabel("")
        self.banner.setStyleSheet(f"color:{T.hexs(T.TEXT)};font:700 9pt '{T.MONO}';")
        self.banner.hide()
        root.addWidget(self.banner)

        self.status = QLabel("no file scanned yet")
        self.status.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:8pt '{T.MONO}';")
        self.status.setWordWrap(True)
        root.addWidget(self.status)

        if WEBENGINE_OK:
            self.view = QWebEngineView(self)
            self.view.hide()
            root.addWidget(self.view, 1)
        else:
            self.view = None
            root.addWidget(QLabel("QtWebEngine unavailable: " + str(WEBENGINE_ERR)))
        root.addStretch(0)

    # -- drag & drop -------------------------------------------------------
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self.drop.setStyleSheet(
                f"color:{T.hexs(T.TEXT)};font:9pt '{T.UI}';"
                f"border:1px dashed {T.hexs(T.ACCENT)};border-radius:{T.R_CTRL}px;"
                f"padding:12px;")

    def dragLeaveEvent(self, _e):
        self._reset_drop_style()

    def dropEvent(self, e):
        self._reset_drop_style()
        urls = e.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if path:
                self._scan(path)

    def _reset_drop_style(self):
        self.drop.setStyleSheet(
            f"color:{T.hexs(T.TEXT_MUTED)};font:9pt '{T.UI}';"
            f"border:1px dashed {T.hexs(T.BORDER)};border-radius:{T.R_CTRL}px;"
            f"padding:12px;")

    # -- actions -----------------------------------------------------------
    def _choose(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file to scan")
        if path:
            self._scan(path)

    def _scan(self, path):
        if self.worker and self.worker.isRunning():
            return
        self.banner.hide()
        self.status.setText("hashing file locally…")
        self.worker = VtWorker(path, settings.get("vt_api_key") or "", self)
        self.worker.hashed.connect(self._on_hashed)
        self.worker.stats.connect(self._on_stats)
        self.worker.note.connect(self.status.setText)
        self.worker.start()

    def _on_hashed(self, digest, name):
        self.status.setText(f"{name}  ·  sha256 {digest[:16]}…  (only the hash is sent)")
        if self.view:
            self.view.setUrl(QUrl(_GUI.format(digest)))
            self.view.show()

    def _on_stats(self, stats):
        mal = stats.get("malicious", 0)
        susp = stats.get("suspicious", 0)
        harm = stats.get("harmless", 0)
        undet = stats.get("undetected", 0)
        total = mal + susp + harm + undet
        verdict = "CLEAN" if mal == 0 and susp == 0 else f"{mal} MALICIOUS"
        self.banner.setText(f"{verdict}   ·   {mal} malicious / {susp} suspicious "
                            f"/ {harm} harmless   of {total} engines")
        color = T.DANGER if mal else (T.WARN if susp else T.POSITIVE)
        self.banner.setStyleSheet(f"color:{T.hexs(color)};font:700 9pt '{T.MONO}';")
        self.banner.show()

    def shutdown(self):
        if self.worker and self.worker.isRunning():
            self.worker.wait(2000)
