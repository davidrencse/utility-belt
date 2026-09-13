"""
VirusTotal panel - just the VirusTotal website in an embedded Chromium view,
the same way the CHAT tab embeds chatgpt.com. No API, no key, no local
hashing: upload files, search hashes/URLs and read reports exactly as you
would in a browser.

Persistent profile (separate from ChatGPT's) so a VirusTotal sign-in and its
cookie/consent choices survive restarts. A few webview gaps are closed so it
behaves like a real browser tab:
  * the site's "Choose file" button opens a file picker parented to the
    overlay (so the hover menu stays open while you pick)
  * `target=_blank` links open in this same view instead of doing nothing
  * a file dropped outside VT's drop zone doesn't navigate the tab away to
    file:// (the drop zone itself still accepts drag & drop)
"""
import os

from PySide6.QtCore import QUrl, Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QPushButton, QLineEdit, QFileDialog)

from .. import theme as T

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView
    from PySide6.QtWebEngineCore import QWebEngineProfile, QWebEnginePage
    WEBENGINE_OK = True
    WEBENGINE_ERR = None
except Exception as exc:  # pragma: no cover
    WEBENGINE_OK = False
    WEBENGINE_ERR = f"{type(exc).__name__}: {exc}"

HOME_URL = "https://www.virustotal.com/gui/home/upload"
_SEARCH_URL = "https://www.virustotal.com/gui/search/"
_PROFILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "_webprofile_vt")
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")


if WEBENGINE_OK:
    class _VtPage(QWebEnginePage):
        def __init__(self, profile, view):
            super().__init__(profile, view)
            self._view = view

        def chooseFiles(self, mode, old_files, mime_types):
            parent = self._view.window()
            if mode == QWebEnginePage.FileSelectionMode.FileSelectOpenMultiple:
                files, _ = QFileDialog.getOpenFileNames(parent, "Choose files for VirusTotal")
                return files
            path, _ = QFileDialog.getOpenFileName(parent, "Choose a file for VirusTotal")
            return [path] if path else []

        def createWindow(self, _type):
            return self                       # open new-tab links in place

        def acceptNavigationRequest(self, url, nav_type, is_main_frame):
            if is_main_frame and url.scheme() == "file":
                return False                  # stray drop: stay on VirusTotal
            return super().acceptNavigationRequest(url, nav_type, is_main_frame)


class VirusTotalPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 6, 8, 8)
        root.setSpacing(6)

        if not WEBENGINE_OK:
            msg = QLabel("QtWebEngine is not available.\n\n" + str(WEBENGINE_ERR) +
                         "\n\nInstall it with:  pip install PySide6-Addons")
            msg.setWordWrap(True)
            msg.setAlignment(Qt.AlignCenter)
            msg.setStyleSheet(T.label_qss("muted") + "padding:20px;")
            root.addWidget(msg)
            self.view = None
            return

        bar = QHBoxLayout()
        bar.setSpacing(6)
        back = QPushButton("‹")
        back.setFixedSize(28, 26)
        back.setToolTip("Back")
        back.setAccessibleName("Back")
        back.setStyleSheet(T.icon_btn_qss())
        self.url = QLineEdit(HOME_URL)
        self.url.setPlaceholderText("URL, or a hash / domain / IP to search")
        self.url.setStyleSheet(T.input_qss(height=22))
        self.url.returnPressed.connect(self._go)
        home = QPushButton("VirusTotal")
        reload_b = QPushButton("Reload")
        for b in (home, reload_b):
            b.setStyleSheet(T.ghost_btn_qss())
        for b in (back, home, reload_b):
            b.setCursor(Qt.PointingHandCursor)
        bar.addWidget(back)
        bar.addWidget(self.url, 1)
        bar.addWidget(home)
        bar.addWidget(reload_b)
        root.addLayout(bar)

        os.makedirs(_PROFILE_DIR, exist_ok=True)
        self.profile = QWebEngineProfile("overlay_virustotal", self)
        self.profile.setPersistentStoragePath(os.path.abspath(_PROFILE_DIR))
        self.profile.setCachePath(os.path.abspath(os.path.join(_PROFILE_DIR, "cache")))
        self.profile.setPersistentCookiesPolicy(QWebEngineProfile.ForcePersistentCookies)
        self.profile.setHttpUserAgent(_UA)

        self.view = QWebEngineView(self)
        self.view.setPage(_VtPage(self.profile, self.view))
        self.view.urlChanged.connect(lambda u: self.url.setText(u.toString()))
        back.clicked.connect(self.view.back)
        home.clicked.connect(lambda: self._load(HOME_URL))
        reload_b.clicked.connect(self.view.reload)
        self.view.setUrl(QUrl(HOME_URL))
        root.addWidget(self.view, 1)

    def _go(self):
        self._load(self.url.text().strip())

    def _load(self, text):
        if not self.view or not text:
            return
        if "://" not in text:
            # a bare hash / domain / IP typed in the bar -> VirusTotal search
            text = _SEARCH_URL + bytes(QUrl.toPercentEncoding(text)).decode()
        self.view.setUrl(QUrl(text))

    def shutdown(self):
        if self.view:
            self.view.stop()
