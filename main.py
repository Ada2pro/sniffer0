from __future__ import annotations

import sys
from collections import Counter
from datetime import datetime
from typing import Optional

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QTreeView,
    QVBoxLayout,
    QWidget,
    QComboBox,
)
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, get_if_list
from scapy.packet import NoPayload, Packet

from sniffer_thread import SnifferThread


class StatisticsCanvas(FigureCanvas):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        self.figure = Figure(figsize=(5, 4))
        super().__init__(self.figure)
        self.setParent(parent)
        self.axes = self.figure.add_subplot(111)
        self.figure.tight_layout()

    def update_chart(self, data: Counter) -> None:
        self.figure.clf()
        self.axes = self.figure.add_subplot(111)
        if data:
            labels = list(data.keys())
            sizes = list(data.values())
            self.axes.pie(sizes, labels=labels, autopct="%1.1f%%")
        else:
            self.axes.text(0.5, 0.5, "No data", ha="center", va="center")
        self.figure.canvas.draw_idle()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PyQt5 网络嗅探器")
        self.resize(1200, 800)

        self.packet_counter = 0
        self.protocol_counts: Counter[str] = Counter()

        self.sniffer_thread = SnifferThread(self)
        self.sniffer_thread.packet_captured.connect(self.add_packet_to_table)

        self._init_ui()
        self._populate_interfaces()

        self.stats_timer = QTimer(self)
        self.stats_timer.timeout.connect(self.refresh_statistics)
        self.stats_timer.start(2000)

    def _init_ui(self) -> None:
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        # Capture tab
        capture_tab = QWidget()
        capture_layout = QVBoxLayout(capture_tab)

        control_layout = QHBoxLayout()
        self.interface_combo = QComboBox()
        control_layout.addWidget(QLabel("网络适配器:"))
        control_layout.addWidget(self.interface_combo)

        self.start_button = QPushButton("开始")
        self.start_button.clicked.connect(self.start_capture)
        control_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("停止")
        self.stop_button.clicked.connect(self.stop_capture)
        control_layout.addWidget(self.stop_button)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("显示过滤器")
        control_layout.addWidget(self.filter_input)

        self.apply_filter_button = QPushButton("应用过滤器")
        control_layout.addWidget(self.apply_filter_button)

        capture_layout.addLayout(control_layout)

        splitter = QSplitter(Qt.Vertical)
        capture_layout.addWidget(splitter)

        self.packet_table = QTableWidget(0, 7)
        self.packet_table.setHorizontalHeaderLabels([
            "序号",
            "时间",
            "源IP",
            "目的IP",
            "协议",
            "长度",
            "信息",
        ])
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packet_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.packet_table.cellClicked.connect(self.display_packet_details)
        splitter.addWidget(self.packet_table)

        detail_splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(detail_splitter)

        self.protocol_tree = QTreeView()
        self.protocol_model = QStandardItemModel()
        self.protocol_model.setHorizontalHeaderLabels(["协议解析"])
        self.protocol_tree.setModel(self.protocol_model)
        detail_splitter.addWidget(self.protocol_tree)

        self.raw_data_text = QTextEdit()
        self.raw_data_text.setReadOnly(True)
        detail_splitter.addWidget(self.raw_data_text)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)

        self.tab_widget.addTab(capture_tab, "捕获")

        # Statistics tab
        stats_tab = QWidget()
        stats_layout = QVBoxLayout(stats_tab)
        self.statistics_canvas = StatisticsCanvas(stats_tab)
        stats_layout.addWidget(self.statistics_canvas)

        self.tab_widget.addTab(stats_tab, "统计")

    def _populate_interfaces(self) -> None:
        try:
            interfaces = get_if_list()
        except Exception:
            interfaces = []
        if not interfaces:
            interfaces = ["any"]
        self.interface_combo.addItems(interfaces)

    def start_capture(self) -> None:
        if self.sniffer_thread.isRunning():
            return
        interface = self.interface_combo.currentText() or None
        self.sniffer_thread.set_interface(interface)
        self.sniffer_thread.start()

    def stop_capture(self) -> None:
        if not self.sniffer_thread.isRunning():
            return
        self.sniffer_thread.stop_sniffing()
        self.sniffer_thread.wait()

    def add_packet_to_table(self, packet) -> None:
        self.packet_counter += 1
        timestamp = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S.%f")[:-3]
        src_ip = self._get_ip(packet, source=True)
        dst_ip = self._get_ip(packet, source=False)
        protocol = self._get_protocol(packet)
        length = len(packet)
        info = packet.summary()

        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)

        columns = [
            str(self.packet_counter),
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            str(length),
            info,
        ]

        for col, text in enumerate(columns):
            item = QTableWidgetItem(text)
            if col == 0:
                item.setData(Qt.UserRole, packet)
            self.packet_table.setItem(row_position, col, item)

        self.packet_table.scrollToBottom()

        if protocol:
            self.protocol_counts[protocol] += 1
        else:
            self.protocol_counts["Unknown"] += 1

    def display_packet_details(self, row: int, column: int) -> None:  # noqa: ARG002
        item = self.packet_table.item(row, 0)
        if item is None:
            return
        packet = item.data(Qt.UserRole)
        if packet is None:
            return

        self._populate_protocol_tree(packet)
        self._populate_raw_data(packet)

    def _populate_protocol_tree(self, packet) -> None:
        self.protocol_model.removeRows(0, self.protocol_model.rowCount())

        for layer in self._iter_layers(packet):
            layer_item = QStandardItem(layer.__class__.__name__)
            for field_name, value in layer.fields.items():
                field_item = QStandardItem(f"{field_name}: {value}")
                layer_item.appendRow(field_item)
            self.protocol_model.appendRow(layer_item)

    def _iter_layers(self, packet):
        layer = packet
        while isinstance(layer, Packet):
            yield layer
            layer = layer.payload
            if isinstance(layer, NoPayload):
                break

    def _populate_raw_data(self, packet) -> None:
        raw_bytes = bytes(packet)
        lines = []
        for offset in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[offset : offset + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{offset:04x}  {hex_part:<47}  {ascii_part}")
        self.raw_data_text.setPlainText("\n".join(lines))

    def _get_ip(self, packet, *, source: bool) -> str:
        if packet.haslayer(IP):
            layer = packet[IP]
            return layer.src if source else layer.dst
        if packet.haslayer(IPv6):
            layer = packet[IPv6]
            return layer.src if source else layer.dst
        if packet.haslayer(ARP):
            layer = packet[ARP]
            return layer.psrc if source else layer.pdst
        return "-"

    def _get_protocol(self, packet) -> str:
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        if packet.haslayer(ARP):
            return "ARP"
        if packet.haslayer(IPv6):
            return "IPv6"
        if packet.haslayer(IP):
            return str(packet[IP].proto)
        try:
            return packet.name
        except AttributeError:
            return "Unknown"

    def refresh_statistics(self) -> None:
        self.statistics_canvas.update_chart(self.protocol_counts)

    def closeEvent(self, event) -> None:
        if self.sniffer_thread.isRunning():
            self.sniffer_thread.stop_sniffing()
            self.sniffer_thread.wait()
        super().closeEvent(event)


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
