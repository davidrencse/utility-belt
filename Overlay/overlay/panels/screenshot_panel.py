"""
Screenshot history panel - a thumbnail grid of saved screenshots, newest
first. Click a shot to select it, double-click to open it; the action row
copies it to the clipboard, sends it to ChatGPT, opens it, or deletes it
(Delete key works too). Backed by the `screenshots.history` singleton.

Thumbnails are small cached JPGs, so the grid stays quick with hundreds of
shots; new captures are inserted at the top instead of rebuilding the list.
"""
import time

from PySide6.QtCore import Qt, QSize, QTimer
from PySide6.QtGui import QIcon, QPixmap, QKeySequence
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QPushButton, QListWidget, QListWidgetItem,
                               QAbstractItemView, QMenu, QMessageBox)

from .. import theme as T
from ..screenshots import history

_ICON = QSize(160, 90)


def _when(ts):
    t = time.localtime(ts)
    if time.strftime("%Y%m%d", t) == time.strftime("%Y%m%d"):
        return time.strftime("%H:%M:%S", t)
    return time.strftime("%b %d  %H:%M", t)


class ScreenshotPanel(QWidget):
    def __init__(self, take=None, send_to_chat=None, parent=None):
        """take(): capture a new shot (the overlay hides itself first).
        send_to_chat(image, mode): hand an image to the ChatGPT panel."""
        super().__init__(parent)
        self._take = take
        self._send = send_to_chat

        root = QVBoxLayout(self)
        root.setContentsMargins(10, 7, 10, 8)
        root.setSpacing(6)

        head = QHBoxLayout()
        head.setSpacing(6)
        self.take_btn = QPushButton("Take screenshot")
        self.take_btn.setCursor(Qt.PointingHandCursor)
        self.take_btn.setStyleSheet(T.primary_btn_qss())
        self.take_btn.setEnabled(take is not None)
        self.take_btn.clicked.connect(lambda: self._take and self._take())
        head.addWidget(self.take_btn)
        self.count = QLabel("")
        self.count.setStyleSheet(T.label_qss("caption"))
        head.addWidget(self.count)
        head.addStretch(1)
        self.status = QLabel("")
        self.status.setStyleSheet(T.label_qss("value"))
        head.addWidget(self.status)
        folder = QPushButton("Folder")
        folder.setToolTip("Open the screenshots folder")
        clear = QPushButton("Clear")
        clear.setToolTip("Delete every saved screenshot")
        for b in (folder, clear):
            b.setCursor(Qt.PointingHandCursor)
            b.setStyleSheet(T.ghost_btn_qss())
        folder.clicked.connect(history.open_folder)
        clear.clicked.connect(self._clear)
        head.addWidget(folder)
        head.addWidget(clear)
        root.addLayout(head)

        self.grid = QListWidget()
        self.grid.setViewMode(QListWidget.IconMode)
        self.grid.setIconSize(_ICON)
        self.grid.setGridSize(QSize(_ICON.width() + 16, _ICON.height() + 30))
        self.grid.setResizeMode(QListWidget.Adjust)
        self.grid.setMovement(QListWidget.Static)
        self.grid.setUniformItemSizes(True)
        self.grid.setWordWrap(False)
        self.grid.setSpacing(4)
        self.grid.setSelectionMode(QAbstractItemView.SingleSelection)
        self.grid.setContextMenuPolicy(Qt.CustomContextMenu)
        self.grid.setStyleSheet(
            f"QListWidget{{background:transparent;border:none;outline:none;"
            f"color:{T.hexs(T.TEXT_MUTED)};font:8pt '{T.MONO}';}}"
            f"QListWidget::item{{border-radius:{T.R_CTRL}px;padding:4px;}}"
            f"QListWidget::item:hover{{background:{T.hexs(T.SURFACE_2)};}}"
            f"QListWidget::item:selected{{background:{T.hexs(T.SURFACE_HOVER)};"
            f"color:{T.hexs(T.TEXT)};}}")
        self.grid.itemDoubleClicked.connect(lambda it: history.open(it.data(Qt.UserRole)))
        self.grid.itemSelectionChanged.connect(self._sync_actions)
        self.grid.customContextMenuRequested.connect(self._menu)
        root.addWidget(self.grid, 1)

        self.empty = QLabel("No screenshots yet — press the screenshot hotkey "
                            "(Settings › Keybinds) or Take screenshot.")
        self.empty.setAlignment(Qt.AlignCenter)
        self.empty.setWordWrap(True)
        self.empty.setStyleSheet(T.label_qss("muted"))
        root.addWidget(self.empty, 1)

        actions = QHBoxLayout()
        actions.setSpacing(6)
        self.copy_btn = QPushButton("Copy")
        self.chat_btn = QPushButton("Send to ChatGPT")
        self.open_btn = QPushButton("Open")
        self.del_btn = QPushButton("Delete")
        for b in (self.copy_btn, self.chat_btn, self.open_btn, self.del_btn):
            b.setCursor(Qt.PointingHandCursor)
            b.setStyleSheet(T.ghost_btn_qss())
            actions.addWidget(b)
        actions.addStretch(1)
        self.copy_btn.clicked.connect(self._copy)
        self.chat_btn.clicked.connect(self._chat)
        self.open_btn.clicked.connect(lambda: self._selected() and history.open(self._selected()))
        self.del_btn.clicked.connect(self._delete)
        self.chat_btn.setVisible(send_to_chat is not None)
        root.addLayout(actions)

        history.added.connect(self._on_added)
        history.changed.connect(self._rebuild)
        self._rebuild()

    # -- list --------------------------------------------------------------
    def _item(self, path):
        img = history.thumbnail(path)
        icon = QIcon(QPixmap.fromImage(img)) if not img.isNull() else QIcon()
        it = QListWidgetItem(icon, _when(history.taken_at(path)))
        it.setData(Qt.UserRole, path)
        it.setToolTip(path)
        it.setTextAlignment(Qt.AlignHCenter | Qt.AlignTop)
        return it

    def _rebuild(self):
        keep = self._selected()
        self.grid.clear()
        for path in history.items():
            self.grid.addItem(self._item(path))
        if keep:
            for i in range(self.grid.count()):
                if self.grid.item(i).data(Qt.UserRole) == keep:
                    self.grid.setCurrentRow(i)
                    break
        self._sync_actions()

    def _on_added(self, path):
        # a prune right before this signal already rebuilt the grid from disk,
        # which includes the new file - don't insert it twice
        shown = {self.grid.item(i).data(Qt.UserRole) for i in range(self.grid.count())}
        if path not in shown:
            self.grid.insertItem(0, self._item(path))
        # prune may have dropped old files; trim rows whose file is gone
        live = set(history.items())
        for i in range(self.grid.count() - 1, -1, -1):
            if self.grid.item(i).data(Qt.UserRole) not in live:
                self.grid.takeItem(i)
        self.grid.setCurrentRow(0)
        self._flash("saved ✓")
        self._sync_actions()

    def _selected(self):
        it = self.grid.currentItem()
        return it.data(Qt.UserRole) if it and it.isSelected() else None

    def _sync_actions(self):
        n = self.grid.count()
        self.count.setText(f"{n} saved" if n else "")
        self.grid.setVisible(n > 0)
        self.empty.setVisible(n == 0)
        has = self._selected() is not None
        for b in (self.copy_btn, self.chat_btn, self.open_btn, self.del_btn):
            b.setEnabled(has)

    # -- actions -----------------------------------------------------------
    def _flash(self, text):
        self.status.setText(text)
        QTimer.singleShot(1500, lambda: self.status.setText(""))

    def _copy(self):
        path = self._selected()
        if path and history.copy(path):
            self._flash("copied ✓")

    def _chat(self, mode="summary"):
        path = self._selected()
        img = history.load(path) if path else None
        if img is not None and self._send:
            self._send(img, mode)

    def _delete(self):
        path = self._selected()
        if path:
            row = self.grid.currentRow()
            history.remove(path)
            if self.grid.count():
                self.grid.setCurrentRow(min(row, self.grid.count() - 1))

    def _clear(self):
        if not self.grid.count():
            return
        ok = QMessageBox.question(self, "Clear screenshots",
                                  f"Delete all {self.grid.count()} saved screenshots?",
                                  QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel)
        if ok == QMessageBox.Yes:
            history.clear()

    def _menu(self, pos):
        it = self.grid.itemAt(pos)
        if not it:
            return
        self.grid.setCurrentItem(it)
        menu = QMenu(self)
        menu.addAction("Copy", self._copy)
        if self._send:
            chat = menu.addMenu("Send to ChatGPT")
            for mode, label in (("summary", "Summarize"), ("deep", "Deep study notes"),
                                ("cold", "Cold / Absolute mode")):
                chat.addAction(label, lambda m=mode: self._chat(m))
        menu.addAction("Open", lambda: history.open(it.data(Qt.UserRole)))
        menu.addSeparator()
        menu.addAction("Delete", self._delete)
        menu.exec(self.grid.viewport().mapToGlobal(pos))

    def keyPressEvent(self, e):
        if e.key() == Qt.Key_Delete:
            self._delete()
        elif e.matches(QKeySequence.Copy):
            self._copy()
        else:
            super().keyPressEvent(e)
