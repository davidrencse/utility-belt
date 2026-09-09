"""
ChatGPT panel - an embedded Chromium view (QtWebEngine) pointed at
chatgpt.com with a PERSISTENT profile, so a sign-in survives restarts. No API
key: this is your normal web session.

Two ways to be logged in:
  * Manual  - just sign in once inside the panel; the persistent profile keeps
    you signed in across restarts.
  * "Use my browser login" - reuses the session you ALREADY have in your real
    Chrome / Edge / Firefox. It reads your existing chatgpt.com cookies (on
    THIS machine, for YOUR account) and injects them into this view, so you're
    logged in without typing anything - and it sidesteps the Cloudflare
    "unsupported browser" walls that often block signing in inside a webview.
    Cookie values never leave the machine; the read only happens when you click
    the button.

If QtWebEngine isn't installed (it ships in PySide6-Addons / the PySide6
metapackage), the panel degrades to an explanatory message.
"""
import os
import platform

from PySide6.QtCore import QUrl, Qt, QDateTime
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QPushButton, QLineEdit)

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView
    from PySide6.QtWebEngineCore import QWebEngineProfile, QWebEnginePage
    from PySide6.QtNetwork import QNetworkCookie
    WEBENGINE_OK = True
    WEBENGINE_ERR = None
except Exception as exc:  # pragma: no cover
    WEBENGINE_OK = False
    WEBENGINE_ERR = f"{type(exc).__name__}: {exc}"

_PROFILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "_webprofile")
DEFAULT_URL = "https://chatgpt.com/"
if platform.system().lower() == "linux":
    _UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
else:
    _UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

# domains whose cookies matter for a ChatGPT session
_AUTH_DOMAINS = ("chatgpt.com", "openai.com", "auth0.openai.com",
                 "auth.openai.com")


def _read_browser_cookies():
    """Return (cookies, source_name) from the first browser we can read, or
    ([], reason). Imported lazily so the app doesn't hard-depend on it."""
    try:
        import browser_cookie3 as bc
    except Exception:
        return [], "browser_cookie3 not installed (pip install browser_cookie3)"

    loaders = [("Chrome", getattr(bc, "chrome", None)),
               ("Edge", getattr(bc, "edge", None)),
               ("Brave", getattr(bc, "brave", None)),
               ("Firefox", getattr(bc, "firefox", None))]
    last_err = "no supported browser found"
    for name, fn in loaders:
        if fn is None:
            continue
        try:
            jar = fn(domain_name="chatgpt.com")
            hits = [c for c in jar if any(d in (c.domain or "") for d in _AUTH_DOMAINS)]
            if hits:
                return hits, name
        except Exception as exc:
            last_err = f"{name}: {type(exc).__name__}"
    return [], last_err


class ChatGPTPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 6, 8, 8)
        root.setSpacing(6)

        if not WEBENGINE_OK:
            msg = QLabel(
                "QtWebEngine is not available.\n\n" + str(WEBENGINE_ERR) +
                "\n\nInstall it with:\n    pip install PySide6-Addons\n"
                "(or the full  pip install PySide6  metapackage),\n"
                "then restart the overlay.")
            msg.setWordWrap(True)
            msg.setAlignment(Qt.AlignCenter)
            msg.setStyleSheet("color:#f4f4f5; font:9pt 'Segoe UI'; padding:20px;")
            root.addWidget(msg)
            self.view = None
            return

        from .. import theme as T
        # toolbar
        bar = QHBoxLayout()
        bar.setSpacing(6)
        self.url = QLineEdit(DEFAULT_URL)
        self.url.setStyleSheet(T.input_qss(height=22))
        self.url.returnPressed.connect(self._go)
        home = QPushButton("ChatGPT")
        reload_b = QPushButton("Reload")
        self.login_btn = QPushButton("Use my browser login")
        self.login_btn.setToolTip(
            "Reuse the ChatGPT session you're already signed into in Chrome/"
            "Edge/Firefox on this machine. Nothing is typed or sent anywhere.")
        for b in (home, reload_b, self.login_btn):
            b.setCursor(Qt.PointingHandCursor)
            b.setStyleSheet(T.ghost_btn_qss())
        home.clicked.connect(lambda: self._load(DEFAULT_URL))
        reload_b.clicked.connect(lambda: self.view and self.view.reload())
        self.login_btn.clicked.connect(self._import_login)
        bar.addWidget(self.url, 1)
        bar.addWidget(home)
        bar.addWidget(reload_b)
        bar.addWidget(self.login_btn)
        root.addLayout(bar)

        self.status = QLabel("")
        self.status.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:8pt '{T.MONO}';")
        self.status.hide()
        root.addWidget(self.status)

        os.makedirs(_PROFILE_DIR, exist_ok=True)
        self.profile = QWebEngineProfile("overlay_chatgpt", self)
        self.profile.setPersistentStoragePath(os.path.abspath(_PROFILE_DIR))
        self.profile.setCachePath(os.path.abspath(os.path.join(_PROFILE_DIR, "cache")))
        self.profile.setPersistentCookiesPolicy(
            QWebEngineProfile.ForcePersistentCookies)
        self.profile.setHttpUserAgent(_UA)

        self.view = QWebEngineView(self)
        page = QWebEnginePage(self.profile, self.view)
        self.view.setPage(page)
        self.view.setUrl(QUrl(DEFAULT_URL))
        root.addWidget(self.view, 1)

    # -- navigation --------------------------------------------------------
    def _go(self):
        self._load(self.url.text().strip())

    def _load(self, text):
        if not self.view or not text:
            return
        if "://" not in text:
            text = "https://" + text
        self.url.setText(text)
        self.view.setUrl(QUrl(text))

    # -- session import ----------------------------------------------------
    def _set_status(self, text):
        self.status.setText(text)
        self.status.show()

    def _import_login(self):
        if not self.view:
            return
        self._set_status("reading your browser session...")
        self.login_btn.setEnabled(False)
        try:
            cookies, source = _read_browser_cookies()
            if not cookies:
                self._set_status(
                    f"couldn't read a browser session ({source}). "
                    "Sign in manually in the panel instead - it will persist.")
                return
            store = self.profile.cookieStore()
            n = 0
            for c in cookies:
                qc = QNetworkCookie(
                    bytes(c.name, "utf-8"), bytes(c.value or "", "utf-8"))
                dom = c.domain or "chatgpt.com"
                qc.setDomain(dom)
                qc.setPath(c.path or "/")
                qc.setSecure(bool(c.secure))
                if getattr(c, "expires", None):
                    qc.setExpirationDate(
                        QDateTime.fromSecsSinceEpoch(int(c.expires)))
                host = dom[1:] if dom.startswith(".") else dom
                store.setCookie(qc, QUrl(f"https://{host}/"))
                n += 1
            self._set_status(
                f"imported {n} cookies from {source}; loading ChatGPT...")
            self.view.setUrl(QUrl(DEFAULT_URL))
        except Exception as exc:
            self._set_status(f"import failed: {type(exc).__name__}: {exc}")
        finally:
            self.login_btn.setEnabled(True)

    def shutdown(self):
        if self.view:
            self.view.stop()
