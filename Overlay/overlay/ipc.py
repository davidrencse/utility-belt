"""Local single-instance command channel used by compositor keybinds."""
import getpass

from PySide6.QtCore import QObject, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket


SOCKET_NAME = f"sysmon-overlay-{getpass.getuser()}"
VALID_COMMANDS = {
    "toggle_visible",
    "cycle_tab",
    "capture",
    "click_through",
    "panic",
    "nudge_left",
    "nudge_right",
    "nudge_up",
    "nudge_down",
}


class CommandServer(QObject):
    received = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.server = QLocalServer(self)
        self.server.newConnection.connect(self._drain)

    def listen(self):
        QLocalServer.removeServer(SOCKET_NAME)
        return self.server.listen(SOCKET_NAME)

    def _drain(self):
        while self.server.hasPendingConnections():
            sock = self.server.nextPendingConnection()
            sock.readyRead.connect(lambda s=sock: self._read(s))
            sock.disconnected.connect(sock.deleteLater)
            if sock.bytesAvailable():
                self._read(sock)

    def _read(self, sock):
        data = bytes(sock.readAll()).decode("utf-8", "replace").strip()
        if data in VALID_COMMANDS:
            self.received.emit(data)
            sock.write(b"ok\n")
        else:
            sock.write(b"unknown command\n")
        sock.flush()
        sock.disconnectFromServer()


def send_command(command, timeout_ms=800):
    if command not in VALID_COMMANDS:
        return False, f"unknown command: {command}"
    sock = QLocalSocket()
    sock.connectToServer(SOCKET_NAME)
    if not sock.waitForConnected(timeout_ms):
        return False, "overlay is not running"
    sock.write(command.encode("utf-8"))
    sock.flush()
    sock.waitForBytesWritten(timeout_ms)
    sock.waitForReadyRead(timeout_ms)
    reply = bytes(sock.readAll()).decode("utf-8", "replace").strip()
    sock.disconnectFromServer()
    return reply == "ok", reply or "no reply"
