from __future__ import annotations

import threading
from typing import Optional

from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff


class SnifferThread(QThread):
    """Background thread that uses scapy to capture packets."""

    packet_captured = pyqtSignal(object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._stop_event = threading.Event()
        self._interface: Optional[str] = None

    def set_interface(self, interface: Optional[str]) -> None:
        """Configure the network interface that will be sniffed."""
        self._interface = interface

    def stop_sniffing(self) -> None:
        """Signal the sniffer loop to stop."""
        self._stop_event.set()

    def run(self) -> None:
        """Run the scapy sniffing loop until stopped."""
        self._stop_event.clear()

        def _emit_packet(packet):
            if not self._stop_event.is_set():
                self.packet_captured.emit(packet)

        def _should_stop(_):
            return self._stop_event.is_set()

        while not self._stop_event.is_set():
            sniff(
                iface=self._interface,
                prn=_emit_packet,
                store=False,
                stop_filter=_should_stop,
                timeout=1,
            )
