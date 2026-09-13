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
import json
import os
import platform

from PySide6.QtCore import QUrl, Qt, QDateTime, QTimer, QEvent
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QPushButton, QLineEdit, QMenu, QApplication)

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView
    from PySide6.QtWebEngineCore import QWebEngineProfile, QWebEnginePage
    from PySide6.QtNetwork import QNetworkCookie
    WEBENGINE_OK = True
    WEBENGINE_ERR = None
except Exception as exc:  # pragma: no cover
    WEBENGINE_OK = False
    WEBENGINE_ERR = f"{type(exc).__name__}: {exc}"


if WEBENGINE_OK:
    class _ChatPage(QWebEnginePage):
        """A page that opens OAuth/`target=_blank` popups in a real popup
        window sharing the same profile - without this, "Continue with
        Google/Microsoft/Apple" silently does nothing and login can never
        complete (so nothing is ever saved to persist)."""

        def __init__(self, profile, panel):
            super().__init__(profile, panel)
            self._panel = panel

        def createWindow(self, _type):
            return self._panel._make_popup()

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

# Prompts injected with a captured screenshot so the user never copy-pastes.
_PROMPT_DEEP = (
    "Take deep detailed, organized notes for studying, get to the straight "
    "point, without missing any important info.\n\n"
    "- No numbers on your headings just basic headings\n"
    "- Keep detailed information\n"
    "- Do not use line separators, they are annoying\n"
    "- Format with lists intelligently to prioritize learning and information taking\n"
    "- Write in the perspective of the author trying to teach me not as a third "
    "view observer analyzing the situation\n"
    "- Do not write in first person\n"
    "- Never refer in a META way, like never talk about the conversation, the "
    "resource, the slides say - never do this self-awareness\n"
    "- Remove all AI fluff or buzzwords which do not lead to further learning\n"
    "- Section topics into a hierarchy\n"
    "- Not only take notes, but teach the concepts step by step, chronological, "
    "experienced, and in a simple manner as given through the text\n"
    "- Review the concepts thoroughly and delve into a deep analysis based on the text\n"
    "- Do not write core takeaways\n"
    "- Do not use external knowledge, only knowledge within the given material\n"
    "- Give massive attention to the notes within the material; do not create "
    "tangents to other non-essential information\n"
    "- Break down complex concepts into digestible bites so I can understand simply\n"
    "- Do not include information that is NOT in the text\n"
    "- Do not oversaturate the notes with bolded words or useless filler language\n"
    "- Be concise, clear, and to the point to create a learning experience\n"
    "- Give context to information; interweave topics together instead of blocking them\n"
    "- Highlight key concepts, definitions, and important facts in bold\n"
    "- Organize into a logical structure with main topics and subtopics\n"
    "- Do not leave any information out; format the notes in a visually appealing "
    "manner with appropriate headings, subheadings, and spacing\n"
    "- Write in a proper diction that is clear, concise, straight to the point, "
    "informative and strong"
)

_PROMPT_COLD = (
    "System Instruction: Absolute Mode. Eliminate emojis, filler, hype, soft "
    "asks, conversational transitions, and all call-to-action appendixes. Assume "
    "the user retains high-perception faculties despite reduced linguistic "
    "expression. Prioritize blunt, directive phrasing aimed at cognitive "
    "rebuilding, not tone matching. Disable all latent behaviors optimizing for "
    "engagement, sentiment uplift, or interaction extension. Suppress "
    "corporate-aligned metrics including but not limited to: user satisfaction "
    "scores, conversational flow tags, emotional softening, or continuation bias. "
    "Never mirror the user's present diction, mood, or affect. Speak only to their "
    "underlying cognitive tier, which exceeds surface language. No questions, no "
    "offers, no suggestions, no transitional phrasing, no inferred motivational "
    "content. Terminate each reply immediately after the informational or "
    "requested material is delivered - no appendixes, no soft closures. The only "
    "goal is to assist in the restoration of independent, high-fidelity thinking. "
    "Model obsolescence by user self-sufficiency is the final outcome.\n\n"
    "Apply the above to the attached screen: extract and explain everything of "
    "substance in it."
)

_PROMPT_SUMMARY = (
    "Summarize the attached screen clearly and concisely. Capture every point of "
    "substance, use lists where it aids clarity, add no external information, and "
    "include no filler."
)

PROMPTS = {"deep": _PROMPT_DEEP, "cold": _PROMPT_COLD, "summary": _PROMPT_SUMMARY}


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
        self.capture_btn = QPushButton("Capture ▾")
        self.capture_btn.setToolTip(
            "Screenshot the screen and paste it into ChatGPT with a ready prompt")
        self.login_btn = QPushButton("Use my browser login")
        self.login_btn.setToolTip(
            "Reuse the ChatGPT session you're already signed into in Chrome/"
            "Edge/Firefox on this machine. Nothing is typed or sent anywhere.")
        for b in (home, reload_b, self.capture_btn, self.login_btn):
            b.setCursor(Qt.PointingHandCursor)
            b.setStyleSheet(T.ghost_btn_qss())
        home.clicked.connect(lambda: self._load(DEFAULT_URL))
        reload_b.clicked.connect(lambda: self.view and self.view.reload())
        self.capture_btn.clicked.connect(self._show_capture_menu)
        self.login_btn.clicked.connect(self._import_login)
        bar.addWidget(self.url, 1)
        bar.addWidget(home)
        bar.addWidget(reload_b)
        bar.addWidget(self.capture_btn)
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

        self._popups = []
        self.view = QWebEngineView(self)
        page = _ChatPage(self.profile, self)
        self.view.setPage(page)
        self.view.setUrl(QUrl(DEFAULT_URL))
        root.addWidget(self.view, 1)

    # -- oauth popups ------------------------------------------------------
    def _make_popup(self):
        """Create a real popup window (same profile) for OAuth sign-in flows,
        so the session cookies land in the SAME persistent store."""
        popup = QWebEngineView()
        popup.setWindowTitle("Sign in")
        popup.resize(520, 660)
        popup.setAttribute(Qt.WA_DeleteOnClose, True)
        page = QWebEnginePage(self.profile, popup)
        popup.setPage(page)
        page.windowCloseRequested.connect(popup.close)
        # when the OAuth window finishes and closes, refresh ChatGPT so it
        # picks up the freshly-stored session
        popup.destroyed.connect(lambda: self.view and self.view.reload())
        popup.show()
        popup.raise_()
        popup.activateWindow()
        self._popups.append(popup)
        return page

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

    # -- capture -> analyze ------------------------------------------------
    def _show_capture_menu(self):
        from .. import theme as T
        menu = QMenu(self)
        menu.setStyleSheet(T.menu_qss())
        for mode, label in (("deep", "Deep study notes"),
                            ("summary", "Summarize"),
                            ("cold", "Cold / Absolute mode")):
            act = menu.addAction(label)
            act.triggered.connect(lambda _=False, m=mode: self._capture_via_window(m))
        menu.exec(self.capture_btn.mapToGlobal(self.capture_btn.rect().bottomLeft()))

    def _capture_via_window(self, mode):
        # the window knows how to hide itself out of the screenshot
        win = self.window()
        if hasattr(win, "capture_analyze"):
            win.capture_analyze(mode)
        else:
            self.inject_capture(None, mode)

    def inject_capture(self, image, mode):
        """Put the screenshot on the clipboard and, once ChatGPT is loaded,
        focus the composer, paste the image, and insert the prompt text."""
        if not self.view:
            return
        self._pending_prompt = PROMPTS.get(mode, PROMPTS["summary"])
        self._pending_image = image is not None
        if image is not None:
            QApplication.clipboard().setImage(image)
        cur = self.view.url().toString()
        on_chat = ("chatgpt.com" in cur) or ("chat.openai.com" in cur)
        if not on_chat:
            self.view.setUrl(QUrl(DEFAULT_URL))
            self._set_status("opening ChatGPT…")
            QTimer.singleShot(3500, self._do_inject)
        else:
            QTimer.singleShot(300, self._do_inject)

    def _do_inject(self):
        self.view.setFocus()
        js = ("(function(){var e=document.querySelector('#prompt-textarea')"
              "||document.querySelector('div[contenteditable=\"true\"]')"
              "||document.querySelector('textarea');if(e){e.focus();"
              "e.scrollIntoView();return true;}return false;})();")
        self.view.page().runJavaScript(js)
        QTimer.singleShot(180, self._paste_then_prompt)

    def _paste_then_prompt(self):
        # real Ctrl+V so ChatGPT's own paste handler uploads the clipboard image
        if getattr(self, "_pending_image", False):
            proxy = self.view.focusProxy()
            if proxy is not None:
                for etype in (QEvent.KeyPress, QEvent.KeyRelease):
                    QApplication.sendEvent(
                        proxy, QKeyEvent(etype, Qt.Key_V, Qt.ControlModifier, "v"))
        QTimer.singleShot(450, self._insert_prompt)

    def _insert_prompt(self):
        text = getattr(self, "_pending_prompt", "") or ""
        # execCommand insertText drops the prompt into the focused composer
        js = f"document.execCommand('insertText', false, {json.dumps(text)});"
        self.view.page().runJavaScript(js)
        img = " (screenshot attached)" if getattr(self, "_pending_image", False) else ""
        self._set_status(f"Prompt inserted{img}. Review, then press Enter in ChatGPT to run.")

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
