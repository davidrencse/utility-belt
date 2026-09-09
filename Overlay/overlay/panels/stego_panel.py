"""
Steganography panel - a thin UI over the StegKit library (sibling repo
Steganography-Multi-Tool, imported via engine_bridge). Reuses its
image/text encode+decode verbatim; nothing is reimplemented.

Two modes:
  IMAGE - hide a secret message inside a PNG/BMP's pixels (LSB), optionally
          AES-256-GCM encrypted with a passphrase, and extract it back.
  TEXT  - hide a message in zero-width Unicode inside a longer cover text.

Encode/decode run on a worker thread so a large image never freezes the HUD.
The passphrase is a local crypto key for the user's own files - not an
account credential.
"""
from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QPlainTextEdit,
                               QFileDialog, QApplication)

from ..core import bridge as eng
from .. import theme as T


class StegoWorker(QThread):
    ok = Signal(str, object)     # message, payload (str path / bytes / str)
    err = Signal(str)

    def __init__(self, fn, *args, describe="", want="text", parent=None):
        super().__init__(parent)
        self._fn, self._args = fn, args
        self._describe, self._want = describe, want

    def run(self):
        try:
            result = self._fn(*self._args)
            self.ok.emit(self._describe, result)
        except Exception as exc:
            self.err.emit(f"{type(exc).__name__}: {exc}")


class ModeButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet(
            f"QPushButton{{background:{T.hexs(T.SURFACE_2)};color:{T.hexs(T.TEXT_MUTED)};"
            f"border:1px solid {T.hexs(T.BORDER)};border-radius:{T.R_CTRL}px;"
            f"padding:4px 16px;font:700 8pt '{T.UI}';}}"
            f"QPushButton:checked{{background:{T.hexs(T.ACCENT)};color:{T.hexs(T.ACCENT_INK)};"
            f"border:1px solid {T.hexs(T.ACCENT)};}}")


class StegoPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self._mode = "image"
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 8, 12, 10)
        root.setSpacing(8)

        if not eng.STEGO_OK:
            msg = QLabel("StegKit unavailable:\n" + str(eng.STEGO_ERROR) +
                         "\n\nEnsure the Steganography-Multi-Tool folder sits "
                         "next to the Overlay folder and Pillow/numpy/"
                         "cryptography are installed.")
            msg.setWordWrap(True)
            msg.setStyleSheet(f"color:{T.hexs(T.TEXT)};font:9pt '{T.UI}';padding:16px;")
            root.addWidget(msg)
            return

        # mode switch
        modes = QHBoxLayout(); modes.setSpacing(6)
        self.btn_img = ModeButton("IMAGE"); self.btn_img.setChecked(True)
        self.btn_txt = ModeButton("TEXT")
        self.btn_img.clicked.connect(lambda: self._set_mode("image"))
        self.btn_txt.clicked.connect(lambda: self._set_mode("text"))
        modes.addWidget(self.btn_img); modes.addWidget(self.btn_txt)
        modes.addStretch(1)
        root.addLayout(modes)

        iqss = T.input_qss(height=24)

        # cover (image path OR text) --------------------------------------
        self.cover_row = QHBoxLayout(); self.cover_row.setSpacing(6)
        self.cover_path = QLineEdit()
        self.cover_path.setPlaceholderText("cover image (PNG/BMP)")
        self.cover_path.setStyleSheet(iqss)
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.setCursor(Qt.PointingHandCursor)
        self.browse_btn.setStyleSheet(T.ghost_btn_qss())
        self.browse_btn.clicked.connect(self._browse_cover)
        self.cover_row.addWidget(self.cover_path, 1)
        self.cover_row.addWidget(self.browse_btn)
        root.addLayout(self.cover_row)

        self.cover_text = QPlainTextEdit()
        self.cover_text.setPlaceholderText(
            "cover text — needs to be long (zero-width chars hide between "
            "visible characters; ~78 chars per secret byte)")
        self.cover_text.setStyleSheet(self._edit_qss())
        self.cover_text.setFixedHeight(70)
        self.cover_text.hide()
        root.addWidget(self.cover_text)

        # secret + password ------------------------------------------------
        self.secret = QLineEdit()
        self.secret.setPlaceholderText("secret message to hide")
        self.secret.setStyleSheet(iqss)
        root.addWidget(self.secret)

        self.password = QLineEdit()
        self.password.setPlaceholderText("passphrase (AES-256-GCM; optional)")
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setStyleSheet(iqss)
        root.addWidget(self.password)

        # actions ----------------------------------------------------------
        acts = QHBoxLayout(); acts.setSpacing(8)
        self.enc_btn = QPushButton("ENCODE")
        self.enc_btn.setCursor(Qt.PointingHandCursor)
        self.enc_btn.setStyleSheet(T.primary_btn_qss())
        self.enc_btn.clicked.connect(self._encode)
        self.dec_btn = QPushButton("DECODE")
        self.dec_btn.setCursor(Qt.PointingHandCursor)
        self.dec_btn.setStyleSheet(T.ghost_btn_qss())
        self.dec_btn.clicked.connect(self._decode)
        acts.addWidget(self.enc_btn)
        acts.addWidget(self.dec_btn)
        acts.addStretch(1)
        self.copy_btn = QPushButton("Copy output")
        self.copy_btn.setCursor(Qt.PointingHandCursor)
        self.copy_btn.setStyleSheet(T.ghost_btn_qss())
        self.copy_btn.clicked.connect(self._copy_output)
        self.copy_btn.hide()
        acts.addWidget(self.copy_btn)
        root.addLayout(acts)

        # output -----------------------------------------------------------
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("output / extracted message appears here")
        self.output.setStyleSheet(self._edit_qss())
        root.addWidget(self.output, 1)

        self.status = QLabel("ready")
        self.status.setStyleSheet(f"color:{T.hexs(T.TEXT_DIM)};font:8pt '{T.MONO}';")
        root.addWidget(self.status)

    # -- styling helpers ---------------------------------------------------
    def _edit_qss(self):
        return (
            f"QPlainTextEdit{{background:{T.hexs(T.SURFACE)};color:{T.hexs(T.TEXT)};"
            f"border:1px solid {T.hexs(T.BORDER)};border-radius:{T.R_CTRL}px;"
            f"padding:5px;font:9pt '{T.MONO}';selection-background-color:{T.hexs(T.ACCENT)};"
            f"selection-color:{T.hexs(T.ACCENT_INK)};}}"
            f"QPlainTextEdit:focus{{border:1px solid {T.hexs(T.ACCENT)};}}")

    # -- mode --------------------------------------------------------------
    def _set_mode(self, mode):
        self._mode = mode
        img = mode == "image"
        self.btn_img.setChecked(img)
        self.btn_txt.setChecked(not img)
        self.cover_path.setVisible(img)
        self.browse_btn.setVisible(img)
        self.cover_text.setVisible(not img)
        self.copy_btn.hide()
        self._set_status("ready")

    # -- helpers -----------------------------------------------------------
    def _set_status(self, text):
        self.status.setText(text)

    def _busy(self, on):
        for b in (self.enc_btn, self.dec_btn, self.browse_btn):
            b.setEnabled(not on)

    def _browse_cover(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose cover image", "", "Images (*.png *.bmp)")
        if path:
            self.cover_path.setText(path)

    def _pw(self):
        return self.password.text() or None

    def _copy_output(self):
        QApplication.clipboard().setText(self.output.toPlainText())
        self._set_status("output copied to clipboard")

    # -- encode ------------------------------------------------------------
    def _encode(self):
        secret = self.secret.text().encode("utf-8")
        if not secret:
            self._set_status("enter a secret message first")
            return
        if self._mode == "image":
            src = self.cover_path.text().strip()
            if not src:
                self._set_status("choose a cover image first")
                return
            out, _ = QFileDialog.getSaveFileName(
                self, "Save stego image as", "secret.png", "PNG image (*.png)")
            if not out:
                return
            self._run(eng.stego_image.encode, src, out, secret, self._pw(),
                      describe=f"encoded → {out}", want="path")
        else:
            cover = self.cover_text.toPlainText()
            if not cover.strip():
                self._set_status("enter cover text first")
                return
            self._run(eng.stego_text.encode, cover, secret, self._pw(),
                      describe="encoded (copy the output text)", want="text")

    # -- decode ------------------------------------------------------------
    def _decode(self):
        if self._mode == "image":
            src = self.cover_path.text().strip()
            if not src:
                src, _ = QFileDialog.getOpenFileName(
                    self, "Choose stego image", "", "Images (*.png *.bmp)")
                if not src:
                    return
                self.cover_path.setText(src)
            self._run(eng.stego_image.decode, src, self._pw(),
                      describe="decoded", want="bytes")
        else:
            stego = self.cover_text.toPlainText()
            if not stego:
                self._set_status("paste stego text into the cover box first")
                return
            self._run(eng.stego_text.decode, stego, self._pw(),
                      describe="decoded", want="bytes")

    # -- worker plumbing ---------------------------------------------------
    def _run(self, fn, *args, describe="", want="text"):
        if self.worker and self.worker.isRunning():
            return
        self._busy(True)
        self._set_status("working...")
        self.worker = StegoWorker(fn, *args, describe=describe, want=want, parent=self)
        self.worker.ok.connect(self._on_ok)
        self.worker.err.connect(self._on_err)
        self.worker.start()

    def _on_ok(self, message, payload):
        self._busy(False)
        self.copy_btn.hide()
        if isinstance(payload, bytes):
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                text = repr(payload)
            self.output.setPlainText(text)
        elif isinstance(payload, str) and self._mode == "text":
            self.output.setPlainText(payload)
            self.copy_btn.show()
        else:  # image path written
            self.output.setPlainText(str(payload))
        self._set_status(message)

    def _on_err(self, msg):
        self._busy(False)
        self._set_status("error: " + msg)

    def shutdown(self):
        if self.worker and self.worker.isRunning():
            self.worker.wait(3000)
