from __future__ import annotations

import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from PyQt5.QtCore import QModelIndex, Qt, QTimer
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QFileDialog,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
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
    QDial,
)
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IGMP,
    IP,
    IPv6,
    TCP,
    UDP,
    get_if_list,
)
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.packet import NoPayload, Packet

from sniffer_thread import SnifferThread


@dataclass(frozen=True)
class FlowIdentifier:
    protocol: str
    endpoint_a: Tuple[str, int]
    endpoint_b: Tuple[str, int]

    def label(self) -> str:
        src, dst = self.endpoint_a, self.endpoint_b
        return f"{self.protocol} {src[0]}:{src[1]} ↔ {dst[0]}:{dst[1]}"


@dataclass
class FlowEvent:
    timestamp: datetime
    direction: str
    summary: str

    def format(self) -> str:
        ts = self.timestamp.strftime("%H:%M:%S.%f")[:-3]
        return f"[{ts}] {self.direction} {self.summary}"


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


class FlowTracker:
    """Aggregate application flows, credentials, cookies, and extracted files."""

    def __init__(self) -> None:
        self.streams: Dict[FlowIdentifier, List[FlowEvent]] = defaultdict(list)
        self.extracted_files: Dict[str, bytes] = {}
        self.file_metadata: Dict[str, Dict[str, str]] = {}
        self.credentials: List[Dict[str, str]] = []
        self.session_tokens: List[Dict[str, str]] = []
        self.http_bodies: Dict[FlowIdentifier, bytearray] = defaultdict(bytearray)

    def add_event(
        self,
        identifier: FlowIdentifier,
        timestamp: datetime,
        direction: str,
        summary: str,
    ) -> None:
        self.streams[identifier].append(FlowEvent(timestamp, direction, summary))

    def record_file(
        self,
        identifier: FlowIdentifier,
        filename: str,
        content: bytes,
        content_type: str,
    ) -> str:
        key = f"{identifier.label()}::{filename}::{len(self.extracted_files)}"
        self.extracted_files[key] = content
        self.file_metadata[key] = {
            "filename": filename,
            "content_type": content_type,
            "stream": identifier.label(),
        }
        return key

    def add_credential(self, protocol: str, host: str, username: str, password: str) -> None:
        self.credentials.append(
            {
                "protocol": protocol,
                "host": host,
                "username": username,
                "password": password,
            }
        )

    def add_session_token(self, protocol: str, host: str, token: str) -> None:
        self.session_tokens.append(
            {
                "protocol": protocol,
                "host": host,
                "token": token,
            }
        )


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PyQt5 网络嗅探器")
        self.resize(1200, 800)

        self.packet_counter = 0
        self.protocol_counts: Counter[str] = Counter()
        self.visited_sites: Counter[str] = Counter()
        self.category_counts: Counter[str] = Counter()
        self.total_bytes = 0
        self.current_display_filter = ""
        self.parsed_display_filter: List[Tuple[str, str]] = []

        self.flow_tracker = FlowTracker()
        self.flow_items: Dict[FlowIdentifier, QStandardItem] = {}
        self.flow_text_cache: Dict[FlowIdentifier, List[str]] = defaultdict(list)
        self.row_file_keys: Dict[int, List[str]] = defaultdict(list)
        self.row_metadata: Dict[int, Dict[str, Any]] = {}

        self.category_keywords: Dict[str, str] = {
            "qq": "即时通讯",
            "wechat": "即时通讯",
            "baidu": "搜索",
            "google": "搜索",
            "sogou": "搜索",
            "news": "新闻",
            "xinhuanet": "新闻",
            "people": "新闻",
            "game": "游戏",
            "steam": "游戏",
            "taobao": "购物",
            "tmall": "购物",
            "jd": "购物",
            "youku": "视频",
            "bilibili": "视频",
            "tencent": "综合",
        }

        self.sniffer_thread = SnifferThread(self)
        self.sniffer_thread.packet_captured.connect(self.add_packet_to_table)

        self._init_ui()
        self._populate_interfaces()

        self.stats_timer = QTimer(self)
        self.stats_timer.timeout.connect(self.refresh_statistics)
        self.stats_timer.start(2000)

        self.current_row: Optional[int] = None

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

        control_layout.addWidget(QLabel("捕获过滤器:"))
        self.capture_filter_input = QLineEdit()
        self.capture_filter_input.setPlaceholderText("tcp port 80 or host 8.8.8.8")
        control_layout.addWidget(self.capture_filter_input)

        control_layout.addWidget(QLabel("显示过滤器:"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("protocol:tcp port:80 host:example.com")
        control_layout.addWidget(self.filter_input)

        self.apply_filter_button = QPushButton("应用过滤器")
        self.apply_filter_button.clicked.connect(self.apply_display_filter)
        control_layout.addWidget(self.apply_filter_button)

        self.clear_filter_button = QPushButton("清除过滤器")
        self.clear_filter_button.clicked.connect(self.clear_display_filter)
        control_layout.addWidget(self.clear_filter_button)

        capture_layout.addLayout(control_layout)

        extra_controls_layout = QHBoxLayout()
        self.save_file_button = QPushButton("保存提取文件")
        self.save_file_button.clicked.connect(self.save_selected_file)
        extra_controls_layout.addWidget(self.save_file_button)

        self.track_stream_button = QPushButton("追踪当前流")
        self.track_stream_button.clicked.connect(self.open_selected_flow)
        extra_controls_layout.addWidget(self.track_stream_button)

        extra_controls_layout.addStretch()
        capture_layout.addLayout(extra_controls_layout)

        self.filter_input.returnPressed.connect(self.apply_display_filter)

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
        self.packet_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
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
        self.stats_tabs = QTabWidget()
        stats_layout.addWidget(self.stats_tabs)

        protocol_tab = QWidget()
        protocol_layout = QVBoxLayout(protocol_tab)

        chart_layout = QHBoxLayout()
        self.statistics_canvas = StatisticsCanvas(protocol_tab)
        chart_layout.addWidget(self.statistics_canvas, stretch=2)

        gauge_layout = QVBoxLayout()
        gauge_layout.addWidget(QLabel("累计捕获字节"))
        self.traffic_gauge = QDial()
        self.traffic_gauge.setNotchesVisible(True)
        self.traffic_gauge.setMinimum(0)
        self.traffic_gauge.setMaximum(100)
        self.traffic_gauge.setEnabled(False)
        gauge_layout.addWidget(self.traffic_gauge)
        self.traffic_progress = QProgressBar()
        self.traffic_progress.setRange(0, 100)
        gauge_layout.addWidget(self.traffic_progress)
        chart_layout.addLayout(gauge_layout, stretch=1)

        protocol_layout.addLayout(chart_layout)

        self.protocol_table = QTableWidget(0, 2)
        self.protocol_table.setHorizontalHeaderLabels(["协议", "数量"])
        self.protocol_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.protocol_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        protocol_layout.addWidget(self.protocol_table)

        self.stats_tabs.addTab(protocol_tab, "协议分布")

        sites_tab = QWidget()
        sites_layout = QVBoxLayout(sites_tab)
        self.visited_sites_table = QTableWidget(0, 2)
        self.visited_sites_table.setHorizontalHeaderLabels(["站点", "访问次数"])
        self.visited_sites_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.visited_sites_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        sites_layout.addWidget(self.visited_sites_table)
        self.stats_tabs.addTab(sites_tab, "访问网站")

        category_tab = QWidget()
        category_layout = QVBoxLayout(category_tab)
        self.category_table = QTableWidget(0, 2)
        self.category_table.setHorizontalHeaderLabels(["分类", "数量"])
        self.category_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.category_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        category_layout.addWidget(self.category_table)
        self.stats_tabs.addTab(category_tab, "流量分类")

        self.tab_widget.addTab(stats_tab, "统计")

        # Analysis tab
        analysis_tab = QWidget()
        analysis_layout = QVBoxLayout(analysis_tab)

        analysis_splitter = QSplitter(Qt.Vertical)
        analysis_layout.addWidget(analysis_splitter)

        flow_splitter = QSplitter(Qt.Horizontal)
        analysis_splitter.addWidget(flow_splitter)

        self.flow_tree = QTreeView()
        self.flow_tree_model = QStandardItemModel()
        self.flow_tree_model.setHorizontalHeaderLabels(["TCP/UDP 会话追踪"])
        self.flow_tree.setModel(self.flow_tree_model)
        self.flow_tree.clicked.connect(self.display_flow_conversation)
        flow_splitter.addWidget(self.flow_tree)

        self.flow_detail_text = QTextEdit()
        self.flow_detail_text.setReadOnly(True)
        flow_splitter.addWidget(self.flow_detail_text)

        detail_tables_splitter = QSplitter(Qt.Horizontal)
        analysis_splitter.addWidget(detail_tables_splitter)

        self.credentials_table = QTableWidget(0, 4)
        self.credentials_table.setHorizontalHeaderLabels(["协议", "主机", "用户名", "密码"])
        self.credentials_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.credentials_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        detail_tables_splitter.addWidget(self.credentials_table)

        self.session_table = QTableWidget(0, 3)
        self.session_table.setHorizontalHeaderLabels(["协议", "主机", "Cookie/Token"])
        self.session_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.session_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        detail_tables_splitter.addWidget(self.session_table)

        self.analysis_tab = analysis_tab
        self.tab_widget.addTab(analysis_tab, "分析")

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
        capture_filter = self.capture_filter_input.text().strip() or None
        self.sniffer_thread.set_interface(interface)
        self.sniffer_thread.set_capture_filter(capture_filter)
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

        self.total_bytes += length
        self._update_flow_tracking(packet, protocol, row_position)
        self._apply_display_filter_to_row(row_position)

    def display_packet_details(self, row: int, column: int) -> None:  # noqa: ARG002
        item = self.packet_table.item(row, 0)
        if item is None:
            return
        packet = item.data(Qt.UserRole)
        if packet is None:
            return

        self.current_row = row

        self._populate_protocol_tree(packet)
        self._populate_raw_data(packet)
        self._highlight_flow_for_row(row)

    def _populate_protocol_tree(self, packet) -> None:
        self.protocol_model.removeRows(0, self.protocol_model.rowCount())

        for layer in self._iter_layers(packet):
            layer_item = QStandardItem(layer.__class__.__name__)
            for field_name, value in self._format_layer_fields(layer).items():
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

    def _format_layer_fields(self, layer: Packet) -> Dict[str, str]:
        formatted: Dict[str, str] = {}
        for field_name, value in layer.fields.items():
            if isinstance(value, bytes):
                try:
                    text = value.decode("utf-8", errors="ignore")
                except Exception:
                    text = value.hex()
                formatted[field_name] = text
            else:
                formatted[field_name] = str(value)
        if isinstance(layer, TCP):
            tcp_layer = layer
            formatted.update(
                {
                    "sport": str(tcp_layer.sport),
                    "dport": str(tcp_layer.dport),
                    "flags": tcp_layer.flags.__repr__(),
                    "seq": str(getattr(tcp_layer, "seq", "")),
                    "ack": str(getattr(tcp_layer, "ack", "")),
                }
            )
        if isinstance(layer, UDP):
            udp_layer = layer
            formatted.update(
                {
                    "sport": str(udp_layer.sport),
                    "dport": str(udp_layer.dport),
                    "len": str(getattr(udp_layer, "len", "")),
                }
            )
        if isinstance(layer, ICMP):
            icmp_layer = layer
            formatted.update(
                {
                    "type": str(getattr(icmp_layer, "type", "")),
                    "code": str(getattr(icmp_layer, "code", "")),
                }
            )
        if isinstance(layer, IGMP):
            igmp_layer = layer
            formatted.update(
                {
                    "type": str(getattr(igmp_layer, "type", "")),
                    "gaddr": str(getattr(igmp_layer, "gaddr", "")),
                }
            )
        return formatted

    def _populate_raw_data(self, packet) -> None:
        raw_bytes = bytes(packet)
        lines = []
        for offset in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[offset : offset + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{offset:04x}  {hex_part:<47}  {ascii_part}")
        self.raw_data_text.setPlainText("\n".join(lines))

    def _record_flow_event(
        self,
        identifier: FlowIdentifier,
        timestamp: datetime,
        direction: str,
        summary: str,
    ) -> None:
        self.flow_tracker.add_event(identifier, timestamp, direction, summary)
        formatted = self.flow_tracker.streams[identifier][-1].format()
        self.flow_text_cache[identifier].append(formatted)
        item = self._ensure_flow_item(identifier)
        child = QStandardItem(formatted)
        child.setData(identifier, Qt.UserRole)
        item.appendRow(child)
        index = self.flow_tree_model.indexFromItem(item)
        if index.isValid():
            self.flow_tree.expand(index)

    def _ensure_flow_item(self, identifier: FlowIdentifier) -> QStandardItem:
        item = self.flow_items.get(identifier)
        if item is None:
            item = QStandardItem(identifier.label())
            item.setData(identifier, Qt.UserRole)
            self.flow_items[identifier] = item
            self.flow_tree_model.appendRow(item)
        return item

    def _update_flow_tracking(self, packet, protocol: str, row: int) -> None:
        metadata: Dict[str, Any] = {}
        timestamp = datetime.fromtimestamp(float(packet.time))
        identifier_info = self._flow_identifier_from_packet(packet, protocol)
        if identifier_info is not None:
            identifier, direction = identifier_info
            summary = self._summarize_packet(packet, protocol)
            self._record_flow_event(identifier, timestamp, direction, summary)
            metadata["flow_identifier"] = identifier

        self._handle_dns_payload(packet, metadata)
        self._handle_application_payload(packet, identifier_info, timestamp, metadata, row)
        self.row_metadata[row] = metadata

    def _summarize_packet(self, packet, protocol: str) -> str:
        if protocol == "TCP" and packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            payload_len = len(bytes(tcp_layer.payload))
            return (
                f"TCP {tcp_layer.sport}->{tcp_layer.dport} "
                f"Flags={tcp_layer.flags} Len={payload_len}"
            )
        if protocol == "UDP" and packet.haslayer(UDP):
            udp_layer = packet[UDP]
            payload_len = len(bytes(udp_layer.payload))
            return f"UDP {udp_layer.sport}->{udp_layer.dport} Len={payload_len}"
        if protocol == "ICMP" and packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            return f"ICMP type={icmp_layer.type} code={icmp_layer.code}"
        if protocol == "IGMP" and packet.haslayer(IGMP):
            igmp_layer = packet[IGMP]
            return f"IGMP type={igmp_layer.type} group={getattr(igmp_layer, 'gaddr', '')}"
        if protocol == "DNS" and packet.haslayer(DNS):
            dns_layer = packet[DNS]
            if dns_layer.qr == 0 and dns_layer.qd:
                query = dns_layer.qd.qname.decode(errors="ignore").rstrip(".")
                return f"DNS Query {query}"
            if dns_layer.qr == 1 and dns_layer.an:
                answer = dns_layer.an.rdata
                return f"DNS Response {answer}"
        if protocol == "ARP" and packet.haslayer(ARP):
            arp_layer = packet[ARP]
            return f"ARP {arp_layer.psrc} -> {arp_layer.pdst}"
        return packet.summary()

    def _flow_identifier_from_packet(
        self, packet, protocol: str
    ) -> Optional[Tuple[FlowIdentifier, str]]:
        src_ip, dst_ip = self._get_ip(packet, True), self._get_ip(packet, False)
        if src_ip == "-" or dst_ip == "-":
            return None
        sport = 0
        dport = 0
        if protocol == "TCP" and packet.haslayer(TCP):
            sport = int(packet[TCP].sport)
            dport = int(packet[TCP].dport)
        elif protocol == "UDP" and packet.haslayer(UDP):
            sport = int(packet[UDP].sport)
            dport = int(packet[UDP].dport)
        endpoints = sorted([(src_ip, sport), (dst_ip, dport)], key=lambda x: (x[0], x[1]))
        identifier = FlowIdentifier(protocol, tuple(endpoints[0]), tuple(endpoints[1]))
        direction = f"{src_ip}:{sport} -> {dst_ip}:{dport}" if sport or dport else f"{src_ip} -> {dst_ip}"
        return identifier, direction

    def _categorize_domain(self, domain: str) -> None:
        if not domain:
            return
        lower = domain.lower()
        for keyword, category in self.category_keywords.items():
            if keyword in lower:
                self.category_counts[category] += 1
                return
        self.category_counts["其他"] += 1

    def _handle_dns_payload(self, packet, metadata: Dict[str, str]) -> None:
        if not packet.haslayer(DNS):
            return
        dns_layer = packet[DNS]
        if dns_layer.qr == 0 and isinstance(dns_layer.qd, DNSQR):
            query = dns_layer.qd.qname.decode(errors="ignore").rstrip(".")
            self.visited_sites[query] += 1
            self._categorize_domain(query)
            metadata["host"] = query
        elif dns_layer.qr == 1 and isinstance(dns_layer.an, DNSRR):
            answer = dns_layer.an.rdata
            metadata["answer"] = str(answer)

    def _handle_application_payload(
        self,
        packet,
        identifier_info: Optional[Tuple[FlowIdentifier, str]],
        timestamp: datetime,
        metadata: Dict[str, Any],
        row: int,
    ) -> None:
        payload_bytes = b""
        protocol = None
        if packet.haslayer(TCP):
            payload_bytes = bytes(packet[TCP].payload)
            protocol = "TCP"
        elif packet.haslayer(UDP):
            payload_bytes = bytes(packet[UDP].payload)
            protocol = "UDP"
        if not payload_bytes:
            return

        identifier = identifier_info[0] if identifier_info else None
        direction = identifier_info[1] if identifier_info else ""

        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            method = self._decode_bytes(http_layer.Method)
            host = self._decode_bytes(http_layer.Host)
            path = self._decode_bytes(http_layer.Path)
            metadata["host"] = host
            request_line = f"HTTP 请求 {method} {host}{path}"
            if identifier:
                self._record_flow_event(identifier, timestamp, direction, request_line)
                self.flow_tracker.http_bodies[identifier].extend(payload_bytes)
            if host:
                self.visited_sites[host] += 1
                self._categorize_domain(host)
            self._check_for_credentials(payload_bytes, host)
            self._check_for_session_tokens(payload_bytes, host=host, is_request=True)
        elif packet.haslayer(HTTPResponse):
            http_layer = packet[HTTPResponse]
            status = self._decode_bytes(http_layer.Status_Code)
            reason = self._decode_bytes(http_layer.Reason_Phrase)
            summary = f"HTTP 响应 {status} {reason}"
            if identifier:
                self._record_flow_event(identifier, timestamp, direction, summary)
                self.flow_tracker.http_bodies[identifier].extend(payload_bytes)
            if identifier and "host" not in metadata:
                guessed_host = self._guess_host_from_flow(identifier)
                if guessed_host:
                    metadata["host"] = guessed_host
            headers, body = self._split_http_payload(payload_bytes)
            filename, content_type = self._detect_http_file(headers)
            if body and filename and identifier:
                file_key = self.flow_tracker.record_file(identifier, filename, body, content_type)
                self.row_file_keys[row].append(file_key)
            self._check_for_session_tokens(headers, host=metadata.get("host", ""))
        else:
            text_payload = payload_bytes.decode(errors="ignore")
            if "USER" in text_payload or "PASS" in text_payload:
                host = metadata.get("host", self._get_ip(packet, False))
                self._check_for_credentials(payload_bytes, host, protocol_hint="FTP")

        if identifier and (packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443)):
            sni = self._extract_sni(payload_bytes)
            if sni:
                metadata["host"] = sni
                if sni:
                    self.visited_sites[sni] += 1
                    self._categorize_domain(sni)

    def _decode_bytes(self, value) -> str:
        if isinstance(value, bytes):
            return value.decode(errors="ignore")
        return str(value)

    def _guess_host_from_flow(self, identifier: FlowIdentifier) -> str:
        for event in reversed(self.flow_tracker.streams.get(identifier, [])):
            if event.summary.startswith("HTTP 请求"):
                parts = event.summary.split()
                if len(parts) >= 3:
                    target = parts[2]
                    return target.split("/")[0]
        return ""

    def _split_http_payload(self, payload: bytes) -> Tuple[bytes, bytes]:
        marker = b"\r\n\r\n"
        if marker in payload:
            header_bytes, body = payload.split(marker, 1)
            return header_bytes, body
        return payload, b""

    def _detect_http_file(self, headers: bytes) -> Tuple[Optional[str], str]:
        text = headers.decode(errors="ignore")
        filename = None
        content_type = "application/octet-stream"
        for line in text.splitlines():
            lower = line.lower()
            if lower.startswith("content-disposition") and "filename=" in lower:
                part = line.split("filename=", 1)[1]
                part = part.split(";", 1)[0]
                filename = part.strip().strip('"')
            if lower.startswith("content-type"):
                content_type = line.split(":", 1)[1].strip()
        return filename, content_type

    def _extract_sni(self, payload: bytes) -> Optional[str]:
        if len(payload) < 5 or payload[0] != 0x16:  # TLS Handshake
            return None
        try:
            idx = 5
            idx += 1  # handshake type
            idx += 3  # length
            idx += 2 + 32  # version + random
            session_id_len = payload[idx]
            idx += 1 + session_id_len
            cipher_len = int.from_bytes(payload[idx : idx + 2], "big")
            idx += 2 + cipher_len
            compression_len = payload[idx]
            idx += 1 + compression_len
            ext_len = int.from_bytes(payload[idx : idx + 2], "big")
            idx += 2
            end = idx + ext_len
            while idx + 4 <= end:
                ext_type = int.from_bytes(payload[idx : idx + 2], "big")
                ext_size = int.from_bytes(payload[idx + 2 : idx + 4], "big")
                idx += 4
                if ext_type == 0 and idx + ext_size <= len(payload):
                    # SNI extension
                    sni_len = int.from_bytes(payload[idx + 3 : idx + 5], "big")
                    server_name = payload[idx + 5 : idx + 5 + sni_len]
                    return server_name.decode(errors="ignore")
                idx += ext_size
        except Exception:
            return None
        return None

    def _check_for_credentials(
        self, payload: bytes, host: str, protocol_hint: str = "HTTP"
    ) -> None:
        text = payload.decode(errors="ignore")
        username = ""
        password = ""
        if "Authorization:" in text and "Basic" in text:
            for line in text.splitlines():
                if line.lower().startswith("authorization:") and "basic" in line.lower():
                    try:
                        encoded = line.split("Basic", 1)[1].strip()
                        import base64

                        decoded = base64.b64decode(encoded).decode(errors="ignore")
                        if ":" in decoded:
                            username, password = decoded.split(":", 1)
                    except Exception:
                        continue
        else:
            for token in ["username=", "user=", "login=", "email="]:
                if token in text:
                    username = text.split(token, 1)[1].split("&", 1)[0]
                    break
            for token in ["password=", "pass=", "pwd="]:
                if token in text:
                    password = text.split(token, 1)[1].split("&", 1)[0]
                    break
        if username or password:
            self.flow_tracker.add_credential(protocol_hint, host, username, password)
            row = self.credentials_table.rowCount()
            self.credentials_table.insertRow(row)
            self.credentials_table.setItem(row, 0, QTableWidgetItem(protocol_hint))
            self.credentials_table.setItem(row, 1, QTableWidgetItem(host))
            self.credentials_table.setItem(row, 2, QTableWidgetItem(username))
            self.credentials_table.setItem(row, 3, QTableWidgetItem(password))

    def _check_for_session_tokens(
        self, headers: bytes, host: str = "", *, is_request: bool = False
    ) -> None:
        text = headers.decode(errors="ignore")
        for line in text.splitlines():
            lower = line.lower()
            if lower.startswith("set-cookie:") or (is_request and lower.startswith("cookie:")):
                token = line.split(":", 1)[1].strip()
                protocol_label = "HTTP" if not is_request else "HTTP(Request)"
                self.flow_tracker.add_session_token(protocol_label, host, token)
                row = self.session_table.rowCount()
                self.session_table.insertRow(row)
                self.session_table.setItem(row, 0, QTableWidgetItem(protocol_label))
                self.session_table.setItem(row, 1, QTableWidgetItem(host))
                self.session_table.setItem(row, 2, QTableWidgetItem(token))

    def _update_protocol_table(self) -> None:
        self.protocol_table.setRowCount(0)
        for protocol, count in self.protocol_counts.most_common():
            row = self.protocol_table.rowCount()
            self.protocol_table.insertRow(row)
            self.protocol_table.setItem(row, 0, QTableWidgetItem(protocol))
            self.protocol_table.setItem(row, 1, QTableWidgetItem(str(count)))

    def _update_sites_table(self) -> None:
        self.visited_sites_table.setRowCount(0)
        for site, count in self.visited_sites.most_common(50):
            row = self.visited_sites_table.rowCount()
            self.visited_sites_table.insertRow(row)
            self.visited_sites_table.setItem(row, 0, QTableWidgetItem(site))
            self.visited_sites_table.setItem(row, 1, QTableWidgetItem(str(count)))

    def _update_category_table(self) -> None:
        self.category_table.setRowCount(0)
        for category, count in self.category_counts.most_common():
            row = self.category_table.rowCount()
            self.category_table.insertRow(row)
            self.category_table.setItem(row, 0, QTableWidgetItem(category))
            self.category_table.setItem(row, 1, QTableWidgetItem(str(count)))

    def _apply_display_filter_to_row(self, row: int) -> None:
        if not self.current_display_filter:
            self.packet_table.setRowHidden(row, False)
            return
        item = self.packet_table.item(row, 0)
        packet = item.data(Qt.UserRole) if item else None
        matches = self._packet_matches_current_filter(packet, row)
        self.packet_table.setRowHidden(row, not matches)

    def apply_display_filter(self) -> None:
        self.current_display_filter = self.filter_input.text().strip()
        self.parsed_display_filter = self._parse_display_filter(self.current_display_filter)
        for row in range(self.packet_table.rowCount()):
            self._apply_display_filter_to_row(row)

    def clear_display_filter(self) -> None:
        self.current_display_filter = ""
        self.filter_input.clear()
        self.parsed_display_filter = []
        for row in range(self.packet_table.rowCount()):
            self.packet_table.setRowHidden(row, False)

    def _parse_display_filter(self, expression: str) -> List[Tuple[str, str]]:
        parsed: List[Tuple[str, str]] = []
        if not expression:
            return parsed
        for token in expression.split():
            if ":" in token:
                key, value = token.split(":", 1)
                parsed.append((key.lower(), value.lower()))
            else:
                parsed.append(("contains", token.lower()))
        return parsed

    def _packet_matches_current_filter(self, packet, row: int) -> bool:
        if not getattr(self, "parsed_display_filter", []):
            return True
        info_text = self.packet_table.item(row, 6)
        info_lower = info_text.text().lower() if info_text else ""
        src_text = self.packet_table.item(row, 2)
        dst_text = self.packet_table.item(row, 3)
        src_lower = src_text.text().lower() if src_text else ""
        dst_lower = dst_text.text().lower() if dst_text else ""
        protocol = self._get_protocol(packet).lower() if packet else ""
        ports = self._get_ports(packet)
        metadata = self.row_metadata.get(row, {})
        host = metadata.get("host", "").lower()
        for key, value in getattr(self, "parsed_display_filter", []):
            if key == "protocol" and protocol != value:
                return False
            if key == "src" and value not in src_lower:
                return False
            if key == "dst" and value not in dst_lower:
                return False
            if key == "host" and value not in host:
                return False
            if key == "port" and value not in ports:
                return False
            if key == "sport" and (not packet or value != str(self._get_port(packet, True))):
                return False
            if key == "dport" and (not packet or value != str(self._get_port(packet, False))):
                return False
            if key == "contains" and value not in info_lower:
                return False
        return True

    def _get_ports(self, packet) -> List[str]:
        ports: List[str] = []
        if not packet:
            return ports
        if packet.haslayer(TCP):
            ports.extend([str(packet[TCP].sport), str(packet[TCP].dport)])
        elif packet.haslayer(UDP):
            ports.extend([str(packet[UDP].sport), str(packet[UDP].dport)])
        return ports

    def _get_port(self, packet, source: bool) -> int:
        if packet is None:
            return -1
        if packet.haslayer(TCP):
            return int(packet[TCP].sport if source else packet[TCP].dport)
        if packet.haslayer(UDP):
            return int(packet[UDP].sport if source else packet[UDP].dport)
        return -1

    def _highlight_flow_for_row(self, row: int) -> None:
        metadata = self.row_metadata.get(row)
        if not metadata:
            return
        identifier = metadata.get("flow_identifier")
        if not identifier:
            return
        item = self.flow_items.get(identifier)
        if item is None:
            return
        index = self.flow_tree_model.indexFromItem(item)
        if index.isValid():
            self.flow_tree.setCurrentIndex(index)
            self.display_flow_conversation(index)

    def display_flow_conversation(self, index: QModelIndex) -> None:
        if not index.isValid():
            return
        item = self.flow_tree_model.itemFromIndex(index)
        data = item.data(Qt.UserRole)
        identifier: Optional[FlowIdentifier]
        if isinstance(data, FlowIdentifier):
            identifier = data
        elif item.parent() is not None:
            parent = item.parent()
            parent_data = parent.data(Qt.UserRole)
            identifier = parent_data if isinstance(parent_data, FlowIdentifier) else None
        else:
            identifier = None
        if not identifier:
            return
        conversation_lines = self.flow_text_cache.get(identifier, [])
        conversation = "\n".join(conversation_lines)
        http_body = self.flow_tracker.http_bodies.get(identifier)
        if http_body:
            preview = http_body[:512].decode(errors="ignore")
            conversation += "\n\n[HTTP流重组预览]\n" + preview
        self.flow_detail_text.setPlainText(conversation)

    def save_selected_file(self) -> None:
        row = getattr(self, "current_row", None)
        if row is None:
            QMessageBox.information(self, "文件提取", "请先选择一个数据包")
            return
        file_keys = self.row_file_keys.get(row)
        if not file_keys:
            QMessageBox.information(self, "文件提取", "当前数据包没有可提取文件")
            return
        for key in file_keys:
            metadata = self.flow_tracker.file_metadata.get(key, {})
            suggested = metadata.get("filename", "extracted.bin")
            path, _ = QFileDialog.getSaveFileName(self, "保存提取文件", suggested)
            if path:
                try:
                    with open(path, "wb") as handle:
                        handle.write(self.flow_tracker.extracted_files[key])
                except OSError as exc:
                    QMessageBox.warning(self, "保存失败", str(exc))

    def open_selected_flow(self) -> None:
        row = getattr(self, "current_row", None)
        if row is None:
            QMessageBox.information(self, "流追踪", "请先选择一个数据包")
            return
        metadata = self.row_metadata.get(row)
        if not metadata or "flow_identifier" not in metadata:
            QMessageBox.information(self, "流追踪", "选中数据包未关联任何会话")
            return
        identifier = metadata["flow_identifier"]
        item = self.flow_items.get(identifier)
        if item is None:
            QMessageBox.information(self, "流追踪", "未找到对应会话记录")
            return
        index = self.flow_tree_model.indexFromItem(item)
        self.tab_widget.setCurrentWidget(self.analysis_tab)
        if index.isValid():
            self.flow_tree.setCurrentIndex(index)
            self.display_flow_conversation(index)
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
        if packet.haslayer(IGMP):
            return "IGMP"
        if packet.haslayer(ICMP):
            return "ICMP"
        if packet.haslayer(DNS):
            return "DNS"
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
        self._update_protocol_table()
        self._update_sites_table()
        self._update_category_table()
        total_kilobytes = self.total_bytes / 1024
        gauge_value = int(min(total_kilobytes / 5, 100))
        progress_value = int(min(self.packet_counter / 5, 100))
        self.traffic_gauge.setValue(gauge_value)
        self.traffic_progress.setValue(progress_value)

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
