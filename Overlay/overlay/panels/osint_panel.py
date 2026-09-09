"""
OSINT panel - embeds the user's "Image Geolocator" Next.js app
(sibling repo ./osint) in a Chromium view. Because it's a web app, not a
Python library, the panel manages its dev server as a child process
(QProcess) and points the embedded browser at http://localhost:3000.

First run needs a one-time `npm install`; the AI visual estimate needs a
VISION_API_KEY in osint/.env.local (EXIF / place tags / OpenStreetMap
geocoding work keyless). All of that is surfaced in the status line rather
than failing silently.
"""
import os
import platform

from PySide6.QtCore import QUrl, Qt, QProcess, QTimer
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QPushButton)

from .. import theme as T

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView
    WEBENGINE_OK = True
except Exception as exc:  # pragma: no cover
    WEBENGINE_OK = False
    WEBENGINE_ERR = f"{type(exc).__name__}: {exc}"

_HERE = os.path.dirname(os.path.abspath(__file__))
_OSINT_DIR = os.path.normpath(os.path.join(_HERE, "..", "..", "..", "osint"))
_URL = "http://localhost:3000"
IS_WINDOWS = platform.system().lower().startswith("win")


def _no_window(args):  # keep npm/node from flashing a console under pythonw
    if IS_WINDOWS:
        args.flags |= 0x08000000  # CREATE_NO_WINDOW
    return args


class OsintPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.proc = None
        self._phase = "idle"   # idle | installing | serving | ready
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 8, 12, 10)
        root.setSpacing(7)

        bar = QHBoxLayout(); bar.setSpacing(8)
        self.start_btn = QPushButton("Start server")
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.setStyleSheet(T.primary_btn_qss())
        self.start_btn.clicked.connect(self._toggle)
        self.open_btn = QPushButton("Open in browser")
        self.open_btn.setCursor(Qt.PointingHandCursor)
        self.open_btn.setStyleSheet(T.ghost_btn_qss())
        self.open_btn.clicked.connect(self._open_external)
        bar.addWidget(self.start_btn)
        bar.addWidget(self.open_btn)
        bar.addStretch(1)
        root.addLayout(bar)

        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setStyleSheet(f"color:{T.hexs(T.TEXT_MUTED)};font:8pt '{T.MONO}';")
        root.addWidget(self.status)

        if not os.path.isdir(_OSINT_DIR):
            self._set(f"osint app not found next to the project at {_OSINT_DIR}")
            self.start_btn.setEnabled(False)
        elif not WEBENGINE_OK:
            self._set("QtWebEngine unavailable: " + str(WEBENGINE_ERR))
            self.start_btn.setEnabled(False)
        else:
            need_install = not os.path.isdir(os.path.join(_OSINT_DIR, "node_modules"))
            self._set("Image Geolocator (Next.js). "
                      + ("First start runs a one-time npm install (minutes)."
                         if need_install else "Click Start to launch the local server."))

        if WEBENGINE_OK:
            self.view = QWebEngineView(self)
            self.view.hide()
            root.addWidget(self.view, 1)
        else:
            self.view = None

    # -- helpers -----------------------------------------------------------
    def _set(self, text):
        self.status.setText(text)

    def _npm_process(self, args):
        p = QProcess(self)
        p.setWorkingDirectory(_OSINT_DIR)
        p.setProcessChannelMode(QProcess.MergedChannels)
        try:
            p.setCreateProcessArgumentsModifier(_no_window)
        except AttributeError:
            pass
        program = "npm.cmd" if IS_WINDOWS else "npm"
        p.setProgram(program)
        p.setArguments(args)
        return p

    # -- lifecycle ---------------------------------------------------------
    def _toggle(self):
        if self.proc is not None:
            self._stop()
        else:
            self._start()

    def _start(self):
        if not WEBENGINE_OK or not os.path.isdir(_OSINT_DIR):
            return
        need_install = not os.path.isdir(os.path.join(_OSINT_DIR, "node_modules"))
        if need_install:
            self._phase = "installing"
            self._set("installing dependencies (one-time, may take a few minutes)…")
            self.proc = self._npm_process(["install"])
            self.proc.finished.connect(self._after_install)
            self.proc.errorOccurred.connect(self._proc_error)
            self.proc.start()
        else:
            self._serve()
        self.start_btn.setText("Stop server")

    def _after_install(self, code, _status):
        if self.proc:
            self.proc.deleteLater()
            self.proc = None
        if code != 0:
            self._phase = "idle"
            self.start_btn.setText("Start server")
            self._set(f"npm install failed (exit {code}). Run it manually in {_OSINT_DIR}.")
            return
        self._serve()

    def _serve(self):
        self._phase = "serving"
        self._set("starting dev server on :3000 …")
        self.proc = self._npm_process(["run", "dev"])
        self.proc.readyReadStandardOutput.connect(self._read_output)
        self.proc.errorOccurred.connect(self._proc_error)
        self.proc.finished.connect(self._proc_finished)
        self.proc.start()
        self.start_btn.setText("Stop server")

    def _read_output(self):
        if not self.proc:
            return
        try:
            chunk = bytes(self.proc.readAllStandardOutput()).decode("utf-8", "replace")
        except Exception:
            return
        low = chunk.lower()
        if self._phase == "serving" and ("localhost:3000" in low or "ready in" in low
                                         or "started server" in low):
            self._phase = "ready"
            QTimer.singleShot(600, self._load_view)

    def _load_view(self):
        if self.view:
            self.view.setUrl(QUrl(_URL))
            self.view.show()
            self._set("server ready — Image Geolocator loaded. "
                      "(AI estimate needs VISION_API_KEY in osint/.env.local)")

    def _stop(self):
        self._phase = "idle"
        if self.proc:
            self.proc.kill()
            self.proc.waitForFinished(3000)
            self.proc.deleteLater()
            self.proc = None
        if self.view:
            self.view.setUrl(QUrl("about:blank"))
            self.view.hide()
        self.start_btn.setText("Start server")
        self._set("server stopped.")

    def _proc_error(self, _err):
        self._set("could not run npm — is Node.js installed and on PATH?")
        self.start_btn.setText("Start server")

    def _proc_finished(self, code, _status):
        if self._phase in ("serving", "ready"):
            self._set(f"dev server exited (code {code}).")
            self.start_btn.setText("Start server")
            self.proc = None

    def _open_external(self):
        import webbrowser
        webbrowser.open(_URL)

    def shutdown(self):
        if self.proc:
            self.proc.kill()
            self.proc.waitForFinished(2000)
