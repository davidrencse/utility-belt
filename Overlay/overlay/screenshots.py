"""
Screenshot history - every screenshot the overlay takes (the `screenshot`
hotkey, the History panel's button, and Capture -> ChatGPT) is saved as a PNG
so you can find it again later: copy it back to the clipboard, open it, send
it to ChatGPT, or delete it.

Unlike clipboard history this IS written to disk (overlay/_screenshots/, git-
ignored) because screenshots are only useful if they survive a restart. The
newest `screenshot_keep` shots are kept; older ones are pruned automatically.

PNG encoding of a 4K frame takes a few hundred ms, so saving + thumbnailing
runs on a worker thread; `added` fires on the GUI thread once the file exists.

`history` is the module singleton.
"""
import os
import time

from PySide6.QtCore import QObject, Signal, QRunnable, QThreadPool, Qt, QUrl
from PySide6.QtGui import QImage, QDesktopServices
from PySide6.QtWidgets import QApplication

from .settings import settings

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_screenshots")
THUMB_DIR = os.path.join(DIR, ".thumbs")
THUMB_W, THUMB_H = 320, 180


def _thumb_path(path):
    return os.path.join(THUMB_DIR, os.path.splitext(os.path.basename(path))[0] + ".jpg")


class _SaveJob(QRunnable):
    def __init__(self, image, path, done):
        super().__init__()
        self._image, self._path, self._done = image, path, done

    def run(self):
        ok = self._image.save(self._path, "PNG")
        if ok:
            thumb = self._image.scaled(THUMB_W, THUMB_H, Qt.KeepAspectRatio,
                                       Qt.SmoothTransformation)
            thumb.save(_thumb_path(self._path), "JPG", 85)
        self._done.emit(self._path if ok else "")


class ScreenshotHistory(QObject):
    added = Signal(str)        # path of a newly saved shot
    changed = Signal()         # removal / clear / prune
    _saved = Signal(str)       # worker -> GUI thread

    def __init__(self):
        super().__init__()
        self._pool = QThreadPool(self)
        self._pool.setMaxThreadCount(1)     # keep saves ordered
        self._saved.connect(self._on_saved)

    # -- capture -----------------------------------------------------------
    @staticmethod
    def grab_screen():
        """Grab the primary screen. Callers hide the overlay first."""
        screen = QApplication.primaryScreen()
        if screen is None:
            return None
        image = screen.grabWindow(0).toImage()
        return None if image.isNull() else image

    def add(self, image):
        """Save a QImage into the history (async). Returns the target path."""
        if image is None or image.isNull():
            return None
        os.makedirs(THUMB_DIR, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S") + f"-{int(time.time() * 1000) % 1000:03d}"
        path = os.path.join(DIR, f"shot-{stamp}.png")
        self._pool.start(_SaveJob(image.copy(), path, self._saved))
        return path

    def _on_saved(self, path):
        if not path:
            return
        self._prune()
        self.added.emit(path)

    def _prune(self):
        keep = max(1, int(settings.get("screenshot_keep") or 200))
        extra = self.items()[keep:]
        for p in extra:
            self._delete_files(p)
        if extra:
            self.changed.emit()

    # -- queries -----------------------------------------------------------
    def items(self):
        """Paths of saved shots, newest first."""
        try:
            names = [n for n in os.listdir(DIR)
                     if n.startswith("shot-") and n.endswith(".png")]
        except OSError:
            return []
        return [os.path.join(DIR, n) for n in sorted(names, reverse=True)]

    @staticmethod
    def thumbnail(path):
        """Small QImage for a shot; regenerates the cached JPG if missing."""
        tp = _thumb_path(path)
        img = QImage(tp)
        if img.isNull():
            full = QImage(path)
            if full.isNull():
                return QImage()
            img = full.scaled(THUMB_W, THUMB_H, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            os.makedirs(THUMB_DIR, exist_ok=True)
            img.save(tp, "JPG", 85)
        return img

    @staticmethod
    def taken_at(path):
        """Epoch seconds parsed from the file name (falls back to mtime)."""
        base = os.path.basename(path)[5:-4]           # YYYYmmdd-HHMMSS-mmm
        try:
            return time.mktime(time.strptime(base[:15], "%Y%m%d-%H%M%S"))
        except ValueError:
            try:
                return os.path.getmtime(path)
            except OSError:
                return time.time()

    # -- actions -----------------------------------------------------------
    @staticmethod
    def load(path):
        img = QImage(path)
        return None if img.isNull() else img

    def copy(self, path):
        img = self.load(path)
        if img is not None:
            QApplication.clipboard().setImage(img)
        return img is not None

    @staticmethod
    def open(path):
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    @staticmethod
    def open_folder():
        os.makedirs(DIR, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(DIR))

    @staticmethod
    def _delete_files(path):
        for p in (path, _thumb_path(path)):
            try:
                os.remove(p)
            except OSError:
                pass

    def remove(self, path):
        self._delete_files(path)
        self.changed.emit()

    def clear(self):
        for p in self.items():
            self._delete_files(p)
        self.changed.emit()


history = ScreenshotHistory()
