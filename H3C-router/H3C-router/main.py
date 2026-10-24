#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
H3C 路由器配置泄露检测工具

功能：
    1. H3C 设备指纹识别
    2. 路径穿越配置泄露检测
    3. 敏感信息自动提取
    4. 弱口令验证
    5. 结果导出 (CSV/TXT)

漏洞原理：
    利用路径穿越漏洞访问 /userLogin.asp/../actionpolicy_status/../ER8300G2-X.cfg
    获取路由器配置文件，泄露 Telnet/Web 管理密码等敏感信息。
"""
import sys
import os
import json
import csv
from typing import List, Dict, Any, Optional
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QPlainTextEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QTabWidget, QGroupBox,
    QSpinBox, QComboBox, QCheckBox, QProgressBar, QFileDialog,
    QMessageBox, QSplitter, QFrame, QGridLayout, QRadioButton,
    QButtonGroup, QAbstractItemView,
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QRect, QMetaObject,
)
from PyQt5.QtGui import (
    QFont, QPalette, QColor, QBrush, QIcon, QPixmap, QTextCursor,
)

# 项目内部模块
from config import load_config, update_config, get_config
from core import ScanEngine, FingerprintScanner
from utils.log import setup_logger, get_logger, info, error, warning
from utils.common import extract_sensitive_info

# 初始化日志
setup_logger(level="INFO", log_file="logs/scanner.log")
logger = get_logger()


# ======================== 暗色主题样式 ========================
DARK_STYLE = """
QMainWindow {
    background-color: #1e1e2e;
}
QWidget {
    background-color: #1e1e2e;
    color: #cdd6f4;
    font-family: 'Consolas', 'Microsoft YaHei', monospace;
    font-size: 12px;
}
QGroupBox {
    border: 1px solid #313244;
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 16px;
    font-weight: bold;
    color: #89b4fa;
}
QGroupBox::title {
    subcontrol-origin: margin;
    padding: 0 8px;
    color: #89b4fa;
}
QLineEdit {
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 4px;
    padding: 6px 10px;
    color: #cdd6f4;
    selection-background-color: #89b4fa;
}
QLineEdit:focus {
    border-color: #89b4fa;
}
QPlainTextEdit {
    background-color: #1e1e2e;
    border: 1px solid #45475a;
    border-radius: 4px;
    color: #cdd6f4;
}
QPushButton {
    background-color: #89b4fa;
    color: #1e1e2e;
    border: none;
    border-radius: 4px;
    padding: 8px 16px;
    font-weight: bold;
    min-width: 80px;
}
QPushButton:hover {
    background-color: #74c7ec;
}
QPushButton:pressed {
    background-color: #89dceb;
}
QPushButton:disabled {
    background-color: #45475a;
    color: #6c7086;
}
QPushButton#btnDanger {
    background-color: #f38ba8;
}
QPushButton#btnDanger:hover {
    background-color: #eba0ac;
}
QPushButton#btnSuccess {
    background-color: #a6e3a1;
    color: #1e1e2e;
}
QTableWidget {
    background-color: #1e1e2e;
    border: 1px solid #45475a;
    border-radius: 4px;
    gridline-color: #313244;
    selection-background-color: #313244;
    selection-color: #cdd6f4;
}
QTableWidget::item {
    padding: 4px 8px;
}
QHeaderView::section {
    background-color: #313244;
    color: #89b4fa;
    border: none;
    padding: 6px;
    font-weight: bold;
}
QProgressBar {
    border: 1px solid #45475a;
    border-radius: 4px;
    text-align: center;
    color: #cdd6f4;
    background-color: #313244;
}
QProgressBar::chunk {
    background-color: #89b4fa;
    border-radius: 3px;
}
QSpinBox, QComboBox {
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 4px;
    padding: 4px 8px;
    color: #cdd6f4;
}
QComboBox::drop-down {
    border: none;
}
QComboBox QAbstractItemView {
    background-color: #313244;
    color: #cdd6f4;
    selection-background-color: #89b4fa;
}
QCheckBox {
    spacing: 6px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border-radius: 3px;
    border: 1px solid #45475a;
    background-color: #313244;
}
QCheckBox::indicator:checked {
    background-color: #89b4fa;
    border-color: #89b4fa;
}
QScrollBar:vertical {
    background-color: #1e1e2e;
    width: 10px;
    border: none;
}
QScrollBar::handle:vertical {
    background-color: #45475a;
    border-radius: 5px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background-color: #585b70;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QSplitter::handle {
    background-color: #45475a;
    width: 2px;
}
QLabel {
    color: #cdd6f4;
}
QLabel#titleLabel {
    color: #89b4fa;
    font-size: 18px;
    font-weight: bold;
}
QLabel#vulnLabel {
    color: #f38ba8;
    font-weight: bold;
}
QLabel#safeLabel {
    color: #a6e3a1;
    font-weight: bold;
}
QLabel#infoLabel {
    color: #89b4fa;
}
"""


# ======================== 扫描工作线程 ========================
class ScanWorker(QThread):
    """扫描工作线程"""
    progress_updated = pyqtSignal(int, int)
    result_found = pyqtSignal(dict)
    scan_finished = pyqtSignal()
    log_message = pyqtSignal(str, str)  # level, message
    scan_log = pyqtSignal(str)  # 实时扫描日志（线程安全）

    def __init__(self, target_input: str, ports: List[int],
                 threads: int, timeout: int, parent=None):
        super().__init__(parent)
        self.target_input = target_input
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.engine = ScanEngine()

    def run(self):
        # 设置回调
        self.engine.set_progress_callback(
            lambda done, total: self.progress_updated.emit(done, total)
        )
        self.engine.set_result_callback(
            lambda result: self.result_found.emit(result)
        )
        # 实时扫描日志回调（通过信号发射，保证线程安全）
        self.engine.set_log_callback(
            lambda msg: self.scan_log.emit(msg)
        )

        self.log_message.emit("INFO", f"扫描线程启动...")
        self.log_message.emit("INFO", f"目标: {self.target_input}")
        self.log_message.emit("INFO", f"端口: {self.ports}")
        self.log_message.emit("INFO", f"线程: {self.threads}")

        try:
            self.engine.start_scan(
                target_input=self.target_input,
                ports=self.ports,
                threads=self.threads,
                timeout=self.timeout,
            )
        except Exception as e:
            self.log_message.emit("ERROR", f"扫描异常: {e}")

        self.scan_finished.emit()

    def stop(self):
        self.engine.stop_scan()
        self.log_message.emit("WARNING", "扫描已停止")


# ======================== 主窗口 ========================
class MainWindow(QMainWindow):
    """主窗口"""

    def __init__(self):
        super().__init__()
        self.scan_worker: Optional[ScanWorker] = None
        self.results: List[Dict[str, Any]] = []
        self._vuln_first = False  # 状态列排序：False=原始顺序, True=脆弱优先
        self.init_ui()
        self.apply_dark_theme()

    def init_ui(self):
        """初始化 UI"""
        self.setWindowTitle("H3CRouterSecurityScannerv1.o|路由器配置泄露检测工具")
        self.setMinimumSize(1100, 750)
        self.setWindowFlags(self.windowFlags() | Qt.WindowMaximizeButtonHint)

        # 中央部件
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(8)
        main_layout.setContentsMargins(12, 12, 12, 12)

        # ===== 参数配置区域 =====
        config_group = QGroupBox("扫描参数配置")
        config_layout = QGridLayout()
        config_layout.setSpacing(8)

        # 目标输入（含 TXT/CSV 文件选择按钮）
        config_layout.addWidget(QLabel("扫描目标:"), 0, 0)
        target_input_layout = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText(
            "IP地址 / 域名 / CIDR(192.168.1.0/24) / 范围(192.168.1.1-100) / IP:端口 / 逗号分隔 / txt/csv批量导入"
        )
        self.target_input.setText("")
        self.target_input.setMinimumWidth(350)
        target_input_layout.addWidget(self.target_input, 1)

        self.load_txt_btn = QPushButton("📂 选择 TXT")
        self.load_txt_btn.setFixedWidth(110)
        self.load_txt_btn.clicked.connect(self.load_targets_from_txt)
        target_input_layout.addWidget(self.load_txt_btn)

        self.load_csv_btn = QPushButton("📂 选择 CSV")
        self.load_csv_btn.setFixedWidth(110)
        self.load_csv_btn.clicked.connect(self.load_targets_from_csv)
        target_input_layout.addWidget(self.load_csv_btn)

        config_layout.addLayout(target_input_layout, 0, 1, 1, 4)

        # 端口
        config_layout.addWidget(QLabel("扫描端口:"), 1, 0)
        port_layout = QHBoxLayout()
        self.port_input = QLineEdit("8081,10001,8090")
        self.port_input.setPlaceholderText("英文逗号(,)分隔多个端口")
        port_layout.addWidget(self.port_input)
        config_layout.addLayout(port_layout, 1, 1, 1, 2)

        # 线程数
        config_layout.addWidget(QLabel("并发线程:"), 1, 3)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 100)
        self.threads_spin.setValue(10)
        config_layout.addWidget(self.threads_spin, 1, 4)

        # 超时
        config_layout.addWidget(QLabel("超时(秒):"), 2, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 30)
        self.timeout_spin.setValue(5)
        config_layout.addWidget(self.timeout_spin, 2, 1)

        # 控制按钮
        btn_layout = QHBoxLayout()

        self.start_btn = QPushButton("▶ 开始扫描")
        self.start_btn.setObjectName("btnSuccess")
        self.start_btn.clicked.connect(self.start_scan)
        btn_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("■ 停止")
        self.stop_btn.setObjectName("btnDanger")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        btn_layout.addWidget(self.stop_btn)

        self.clear_btn = QPushButton("清空结果")
        self.clear_btn.clicked.connect(self.clear_results)
        btn_layout.addWidget(self.clear_btn)

        btn_layout.addStretch()
        config_layout.addLayout(btn_layout, 2, 2, 1, 3)

        config_group.setLayout(config_layout)
        main_layout.addWidget(config_group)

        # ===== 进度区域 =====
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar, 1)

        self.status_label = QLabel("就绪")
        self.status_label.setObjectName("infoLabel")
        progress_layout.addWidget(self.status_label)

        main_layout.addLayout(progress_layout)

        # ===== 主内容区域（拆分器） =====
        splitter = QSplitter(Qt.Vertical)

        # 上半部 - 结果表格
        result_widget = QWidget()
        result_layout = QVBoxLayout(result_widget)
        result_layout.setContentsMargins(0, 0, 0, 0)

        result_header = QHBoxLayout()
        result_header.addWidget(QLabel("扫描结果"))
        result_header.addStretch()

        self.export_csv_btn = QPushButton("导出 CSV")
        self.export_csv_btn.clicked.connect(lambda: self.export_results("csv"))
        result_header.addWidget(self.export_csv_btn)

        self.export_txt_btn = QPushButton("导出 TXT")
        self.export_txt_btn.clicked.connect(lambda: self.export_results("txt"))
        result_header.addWidget(self.export_txt_btn)

        result_layout.addLayout(result_header)

        self.result_table = QTableWidget()
        self.result_table.setColumnCount(7)
        self.result_table.setHorizontalHeaderLabels([
            "状态", "目标", "端口", "指纹", "漏洞类型", "敏感信息", "详情"
        ])
        # 状态列点击排序（脆弱优先 / 原始顺序）
        self.result_table.horizontalHeader().sectionClicked.connect(self.on_header_clicked)
        # 所有列均可拖动调整宽度
        header = self.result_table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.Interactive)
        # 设置默认列宽
        header.resizeSection(0, 60)   # 状态
        header.resizeSection(1, 160)  # 目标
        header.resizeSection(2, 60)   # 端口
        header.resizeSection(3, 100)  # 指纹
        header.resizeSection(4, 100)  # 漏洞类型
        header.resizeSection(5, 250)  # 敏感信息
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.result_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.result_table.setAlternatingRowColors(False)
        self.result_table.verticalHeader().setVisible(False)
        self.result_table.itemDoubleClicked.connect(self.on_result_cell_double_clicked)
        result_layout.addWidget(self.result_table)

        splitter.addWidget(result_widget)

        # 下半部 - 日志
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        log_layout.setContentsMargins(0, 0, 0, 0)

        log_header = QHBoxLayout()
        log_header.addWidget(QLabel("运行日志"))
        log_header.addStretch()

        self.clear_log_btn = QPushButton("清空日志")
        self.clear_log_btn.clicked.connect(lambda: self.log_output.clear())
        log_header.addWidget(self.clear_log_btn)

        log_layout.addLayout(log_header)

        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumBlockCount(1000)
        font = QFont("Consolas", 10)
        self.log_output.setFont(font)
        log_layout.addWidget(self.log_output)

        splitter.addWidget(log_widget)

        # 设置初始比例
        splitter.setSizes([400, 200])
        main_layout.addWidget(splitter, 1)

        # ===== 统计信息 =====
        stats_layout = QHBoxLayout()
        self.total_label = QLabel("总计: 0")
        self.total_label.setObjectName("infoLabel")
        self.vuln_label = QLabel("脆弱: 0")
        self.vuln_label.setObjectName("vulnLabel")
        self.safe_label = QLabel("安全: 0")
        self.safe_label.setObjectName("safeLabel")
        self.sensitive_label = QLabel("敏感信息: 0")
        self.sensitive_label.setObjectName("infoLabel")

        stats_layout.addWidget(self.total_label)
        stats_layout.addWidget(self.vuln_label)
        stats_layout.addWidget(self.safe_label)
        stats_layout.addWidget(self.sensitive_label)
        stats_layout.addStretch()

        main_layout.addLayout(stats_layout)

        # 初始日志
        self.append_log("INFO", "H3C 路由器配置泄露检测工具已启动")
        self.append_log("INFO", "输入目标地址后点击「开始扫描」")
        self.append_log("INFO", f"已加载 finger.json 设备指纹数据库")

    def apply_dark_theme(self):
        """应用暗色主题"""
        self.setStyleSheet(DARK_STYLE)

    # ---------- 扫描控制 ----------
    def _apply_imported_targets(self, targets: List[str]):
        """导入目标后处理：若目标包含显式 IP:端口，则清空扫描端口框，避免端口列表干扰。"""
        if not targets:
            return
        has_explicit_ports = any(
            target.count(":") == 1 and target.rsplit(":", 1)[1].isdigit()
            for target in targets
        )
        if has_explicit_ports:
            self.port_input.clear()
            self.append_log("INFO", "检测到目标包含显式 IP:端口，已清空扫描端口输入框")

    def load_targets_from_txt(self):
        """从 TXT 文件加载目标列表（每行一个 IP / IP:端口）"""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "选择目标文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if not filepath:
            return
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()
            targets = [line.strip() for line in lines if line.strip()]
            if not targets:
                QMessageBox.information(self, "提示", "文件中没有有效的目标地址")
                return
            self.target_input.setText(", ".join(targets))
            self._apply_imported_targets(targets)
            self.append_log("INFO", f"已从 TXT 文件加载 {len(targets)} 个目标: {filepath}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"读取 TXT 文件失败: {e}")

    def load_targets_from_csv(self):
        """从 CSV 文件加载目标列表，兼容 host 列为 ip:port 的写法。"""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "选择 CSV 目标文件", "", "CSV 文件 (*.csv);;所有文件 (*)"
        )
        if not filepath:
            return

        try:
            from utils.common import extract_targets_from_csv
            targets = extract_targets_from_csv(filepath)
            if not targets:
                QMessageBox.information(self, "提示", "CSV 文件中没有发现可识别的目标列（支持 host/ip/port）")
                return
            self.target_input.setText(", ".join(targets))
            self._apply_imported_targets(targets)
            self.append_log("INFO", f"已从 CSV 文件加载 {len(targets)} 个目标: {filepath}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"读取 CSV 文件失败: {e}")

    def on_result_cell_double_clicked(self, item):
        """双击结果单元格复制内容，便于复制敏感信息。"""
        if not item:
            return
        text = item.text()
        if not text:
            return
        QApplication.clipboard().setText(text)
        self.append_log("INFO", f"已复制结果内容: {text[:80]}")

    def start_scan(self):
        """开始扫描"""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "警告", "请输入扫描目标")
            return

        # 允许目标使用 IP:端口 显式端口格式，交给 parse_target 统一解析
        # 例如：192.168.1.1:8081, 10.0.0.5:8443

        # 解析端口
        ports = []
        try:
            port_str = self.port_input.text().strip()
            if port_str:
                # 同时支持中文逗号(，)和英文逗号(,)
                port_str = port_str.replace("，", ",")
                ports = [int(p.strip()) for p in port_str.split(",") if p.strip()]
        except ValueError:
            QMessageBox.warning(self, "警告", "端口格式错误，请使用英文逗号(,)分隔")
            return

        # 校验目标合法性
        from utils.common import parse_target
        parsed = parse_target(target)
        if not parsed:
            QMessageBox.warning(
                self, "目标格式错误",
                f"无法识别目标: {target}\n\n"
                "请检查输入格式是否正确\n"
                "支持格式：IP地址、域名、CIDR、范围、逗号分隔"
            )
            return

        threads = self.threads_spin.value()
        timeout = self.timeout_spin.value()

        # 禁用开始按钮，启用停止按钮
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("扫描中...")

        # 清空之前的结果
        self.results.clear()
        self.result_table.setRowCount(0)

        # 启动工作线程
        self.scan_worker = ScanWorker(target, ports, threads, timeout)
        self.scan_worker.progress_updated.connect(self.on_progress_updated)
        self.scan_worker.result_found.connect(self.on_result_found)
        self.scan_worker.scan_finished.connect(self.on_scan_finished)
        self.scan_worker.log_message.connect(self.append_log)
        self.scan_worker.scan_log.connect(
            lambda msg: self.append_log("INFO", msg)
        )
        self.scan_worker.start()

        self.append_log("INFO", f"扫描开始: {target}")

    def stop_scan(self):
        """停止扫描"""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status_label.setText("已停止")

    def clear_results(self):
        """清空结果"""
        self.results.clear()
        self.result_table.setRowCount(0)
        self.update_statistics()
        self.append_log("INFO", "结果已清空")

    # ---------- 回调处理 ----------
    def on_progress_updated(self, done: int, total: int):
        """进度更新"""
        if total > 0:
            percent = int(done / total * 100)
            self.progress_bar.setValue(percent)
            self.status_label.setText(f"扫描中... {done}/{total} ({percent}%)")

    def on_result_found(self, result: dict):
        """发现新结果"""
        self.results.append(result)
        self.add_result_to_table(result)
        self.update_statistics()
        # 如果当前是脆弱优先模式，新结果插入后重新排序
        if self._vuln_first:
            self._reorder_results()

        # 如果发现漏洞，高亮显示
        if result.get("vulnerable"):
            sensitive = result.get("sensitive_info", {})
            if sensitive:
                self.append_log("WARNING",
                    f"漏洞发现: {result['target']}:{result['port']} - "
                    f"Web密码: {sensitive.get('admpwd', 'N/A')} / "
                    f"Telnet密码: {sensitive.get('vtypasswd', 'N/A')}"
                )
            else:
                self.append_log("WARNING",
                    f"漏洞发现: {result['target']}:{result['port']} - "
                    f"{result.get('detail', '')}"
                )
        else:
            self.append_log("DEBUG",
                f"安全: {result['target']}:{result['port']}"
            )

    def on_scan_finished(self):
        """扫描完成"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        self.status_label.setText("扫描完成")

        vuln_count = sum(1 for r in self.results if r.get("vulnerable"))
        stats = f"扫描完成! 发现 {vuln_count} 个漏洞/配置泄露"
        self.append_log("INFO", stats)

        if vuln_count > 0:
            QMessageBox.information(self, "扫描完成", stats)

    # ---------- 表格排序 ----------
    def on_header_clicked(self, index: int):
        """点击表头排序"""
        if index == 0:  # 状态列
            self._vuln_first = not self._vuln_first
            self._reorder_results()
            mode = "脆弱优先" if self._vuln_first else "原始顺序"
            self.append_log("INFO", f"状态排序: {mode}")

    def _reorder_results(self):
        """重新排序表格显示（不影响 self.results，导出文件不变）"""
        if not self.results:
            return
        # 保存当前选中行
        current_row = self.result_table.currentRow()
        # 重建表格
        self.result_table.setRowCount(0)
        if self._vuln_first:
            # 脆弱在前，安全在后，组内保持原始顺序
            sorted_results = sorted(
                self.results,
                key=lambda r: (not r.get("vulnerable", False))
            )
        else:
            sorted_results = self.results
        for r in sorted_results:
            self.add_result_to_table(r)
        # 恢复选中行（近似位置）
        if current_row >= 0 and current_row < self.result_table.rowCount():
            self.result_table.selectRow(current_row)

    # ---------- 表格操作 ----------
    def add_result_to_table(self, result: dict):
        """添加结果到表格"""
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)

        # 状态列
        is_vuln = result.get("vulnerable", False)
        status_item = QTableWidgetItem("✓ 脆弱" if is_vuln else "✗ 安全")
        status_item.setForeground(QColor("#f38ba8" if is_vuln else "#a6e3a1"))
        self.result_table.setItem(row, 0, status_item)

        # 目标
        self.result_table.setItem(row, 1, QTableWidgetItem(result.get("target", "")))

        # 端口
        self.result_table.setItem(row, 2, QTableWidgetItem(str(result.get("port", ""))))

        # 指纹（移到端口后面）
        self.result_table.setItem(row, 3, QTableWidgetItem(result.get("fingerprint", "")))

        # 漏洞类型
        self.result_table.setItem(row, 4, QTableWidgetItem(result.get("type", "")))

        # 敏感信息 - 按用户要求的格式显示
        sensitive = result.get("sensitive_info", {})
        sensitive_str = ""
        if sensitive:
            parts = []
            if "admpwd" in sensitive:
                parts.append(f"admpwd={sensitive['admpwd']}（@webadmin 段）")
            if "vtypasswd" in sensitive:
                parts.append(f"vtypasswd={sensitive['vtypasswd']}（@base 段 #1/#2）")
            if "admpwdpromt" in sensitive:
                parts.append(f"admpwdpromt={sensitive['admpwdpromt']}（密码找回验证信息）")
            if "model" in sensitive:
                parts.append(f"型号={sensitive['model']}")
            if "version" in sensitive:
                parts.append(f"固件={sensitive['version']}")
            if "passwd" in sensitive:
                parts.append(f"passwd={sensitive['passwd']}")
            sensitive_str = " | ".join(parts)
        sensitive_item = QTableWidgetItem(sensitive_str)
        if "admpwd" in sensitive or "vtypasswd" in sensitive:
            sensitive_item.setForeground(QColor("#f9e2af"))  # 黄色高亮密码字段
        elif sensitive:
            sensitive_item.setForeground(QColor("#89b4fa"))  # 蓝色其他信息
        self.result_table.setItem(row, 5, sensitive_item)

        # 详情 - 显示简明的利用方式
        detail = result.get("detail", "")
        # 从多行详情中提取核心利用信息用于表格显示
        brief = ""
        if detail:
            lines = detail.split("\n")
            # 取第一行（漏洞利用成功状态）和利用路径行
            for line in lines:
                if "利用路径:" in line:
                    brief = line.strip()
                    break
            if not brief:
                brief = lines[0] if lines else detail[:80]
        detail_item = QTableWidgetItem(brief if brief else detail)
        detail_item.setToolTip(detail)  # 完整的详细信息通过tooltip展示
        self.result_table.setItem(row, 6, detail_item)

    def update_statistics(self):
        """更新统计信息"""
        total = len(self.results)
        vuln = sum(1 for r in self.results if r.get("vulnerable"))
        safe = total - vuln
        sensitive = sum(1 for r in self.results if r.get("sensitive_info"))

        self.total_label.setText(f"总计: {total}")
        self.vuln_label.setText(f"脆弱: {vuln}")
        self.safe_label.setText(f"安全: {safe}")
        self.sensitive_label.setText(f"敏感信息: {sensitive}")

    # ---------- 日志 ----------
    def append_log(self, level: str, message: str):
        """添加日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix_map = {
            "INFO": "[INF]",
            "WARNING": "[WRN]",
            "ERROR": "[ERR]",
            "DEBUG": "[DBG]",
        }
        prefix = prefix_map.get(level, "[INF]")
        line = f"[{timestamp}] {prefix} {message}"
        self.log_output.appendPlainText(line)
        # 自动滚动到底部
        scrollbar = self.log_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    # ---------- 导出 ----------
    def export_results(self, format_type: str):
        """导出结果"""
        if not self.results:
            QMessageBox.information(self, "提示", "没有结果可导出")
            return

        # 确保 results 目录存在
        os.makedirs("results", exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if format_type == "csv":
            default_path = os.path.join("results", f"scan_result_{timestamp}.csv")
            filepath, _ = QFileDialog.getSaveFileName(
                self, "导出 CSV", default_path, "CSV 文件 (*.csv)"
            )
            if filepath:
                self._export_csv(filepath)
        elif format_type == "txt":
            default_path = os.path.join("results", f"scan_report_{timestamp}.txt")
            filepath, _ = QFileDialog.getSaveFileName(
                self, "导出 TXT 报告", default_path, "文本文件 (*.txt)"
            )
            if filepath:
                self._export_txt(filepath)

    def _export_csv(self, filepath: str):
        """导出为 CSV"""
        try:
            with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "目标", "端口", "脆弱", "漏洞类型", "指纹",
                    "Web密码", "Telnet密码", "设备型号", "详情"
                ])
                for r in self.results:
                    sensitive = r.get("sensitive_info", {})
                    writer.writerow([
                        r.get("target", ""),
                        r.get("port", ""),
                        "是" if r.get("vulnerable") else "否",
                        r.get("type", ""),
                        r.get("fingerprint", ""),
                        sensitive.get("admpwd", ""),
                        sensitive.get("vtypasswd", ""),
                        sensitive.get("model", ""),
                        r.get("detail", ""),
                    ])
            self.append_log("INFO", f"结果已导出: {filepath}")
            QMessageBox.information(self, "成功", f"CSV 已导出: {filepath}")
        except Exception as e:
            self.append_log("ERROR", f"导出失败: {e}")
            QMessageBox.critical(self, "错误", f"导出失败: {e}")

    def _export_txt(self, filepath: str):
        """导出为 TXT 报告"""
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("H3C 路由器配置泄露检测报告\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"扫描目标: {self.target_input.text()}\n")
                f.write(f"总结果数: {len(self.results)}\n")
                f.write(f"漏洞数: {sum(1 for r in self.results if r.get('vulnerable'))}\n")
                f.write("-" * 60 + "\n\n")

                for i, r in enumerate(self.results, 1):
                    f.write(f"结果 #{i}\n")
                    f.write(f"  目标: {r.get('target', 'N/A')}\n")
                    f.write(f"  端口: {r.get('port', 'N/A')}\n")
                    f.write(f"  状态: {'✓ 脆弱' if r.get('vulnerable') else '✗ 安全'}\n")
                    f.write(f"  类型: {r.get('type', 'N/A')}\n")
                    f.write(f"  指纹: {r.get('fingerprint', 'N/A')}\n")

                    sensitive = r.get("sensitive_info", {})
                    if sensitive:
                        f.write("  敏感信息:\n")
                        for k, v in sensitive.items():
                            f.write(f"    - {k}: {v}\n")

                    f.write(f"  详情: {r.get('detail', 'N/A')}\n")
                    f.write("-" * 40 + "\n")

            self.append_log("INFO", f"报告已导出: {filepath}")
            QMessageBox.information(self, "成功", f"TXT 报告已导出: {filepath}")
        except Exception as e:
            self.append_log("ERROR", f"导出失败: {e}")
            QMessageBox.critical(self, "错误", f"导出失败: {e}")

    def closeEvent(self, event):
        """关闭事件"""
        if self.scan_worker and self.scan_worker.isRunning():
            reply = QMessageBox.question(
                self, "确认退出",
                "扫描正在进行中，确定要退出吗？",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                # 断开所有信号连接，防止残留回调
                try:
                    self.scan_worker.progress_updated.disconnect()
                except TypeError:
                    pass
                try:
                    self.scan_worker.result_found.disconnect()
                except TypeError:
                    pass
                try:
                    self.scan_worker.scan_finished.disconnect()
                except TypeError:
                    pass
                try:
                    self.scan_worker.log_message.disconnect()
                except TypeError:
                    pass
                try:
                    self.scan_worker.scan_log.disconnect()
                except TypeError:
                    pass
                self.scan_worker.stop()
                self.scan_worker.quit()
                self.scan_worker.terminate()  # 强制终止，不阻塞主线程
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


# ======================== 入口 ========================
def main():
    app = QApplication(sys.argv)
    app.setApplicationName("H3C Router Scanner")
    app.setApplicationVersion("1.0")

    window = MainWindow()

    # 设置应用图标
    icon_path = os.path.join(os.path.dirname(__file__), "images", "chibiabyss.png")
    if os.path.exists(icon_path):
        window.setWindowIcon(QIcon(icon_path))
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
