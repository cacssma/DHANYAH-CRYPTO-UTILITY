"""
Dhanyah Crypto Utility - Local Loopback Gateway Controller Widget
Supports native multi-port listening across:
- GST Portal & Offline Tool (15085, 1585, 26443)
- MCA V2 & V3 (1585, 26769, 26770, 15085)
- TDS TRACES (1585, 15085, 26443, 8080)
- Income Tax e-Filing (26769, 26770)
- Custom user-added government & ERP ports (HTTP/HTTPS)
"""

import datetime
from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QGuiApplication, QDesktopServices
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QFrame,
    QPlainTextEdit,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QAbstractItemView,
    QSpinBox,
    QComboBox,
    QLineEdit,
    QScrollArea,
)

from server.loopback_server import (
    LoopbackServer,
    check_embridge_service_running,
    stop_embridge_service,
)


class ServerWidget(QWidget):
    """Loopback server monitor, multi-port government gateway manager, and live HTTP request stream."""

    def __init__(self, server: LoopbackServer, parent=None):
        super().__init__(parent)
        self.server = server
        self._init_ui()
        # Connect log callback
        self.server.log_callback = self._on_server_log

        # Auto refresh table periodically (every 5 seconds)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_ports_table)
        self._refresh_timer.start(5000)

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Scroll area container for clean display on all screens
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent;")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(14)

        # -------------------------------------------------------------
        # 1. Master Server Control Card
        # -------------------------------------------------------------
        ctrl_card = QFrame()
        ctrl_card.setProperty("class", "CardFrame")
        c_layout = QVBoxLayout(ctrl_card)
        c_layout.setContentsMargins(18, 16, 18, 16)
        c_layout.setSpacing(10)

        top_row = QHBoxLayout()
        lbl_head = QLabel("LOCAL HTTP / HTTPS LOOPBACK GATEWAY")
        lbl_head.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff;")
        top_row.addWidget(lbl_head)
        top_row.addStretch()

        self.lbl_server_status = QLabel("ONLINE")
        self.lbl_server_status.setProperty("class", "BadgeValid")
        top_row.addWidget(self.lbl_server_status)

        self.btn_toggle_server = QPushButton("Stop Service")
        self.btn_toggle_server.setProperty("class", "DangerButton")
        self.btn_toggle_server.clicked.connect(self._toggle_server)
        top_row.addWidget(self.btn_toggle_server)

        c_layout.addLayout(top_row)

        lbl_desc = QLabel(
            "Listens simultaneously across standard Indian government portal loopback ports "
            "(GST: 15085 & 1585, MCA & Income Tax: 26769 & 26770, TRACES: 1585 & 8080) with full CORS headers. "
            "Web portals trigger hardware cryptographic signing through these local endpoints."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("color: #94a3b8; font-size: 12px; line-height: 1.4;")
        c_layout.addWidget(lbl_desc)

        layout.addWidget(ctrl_card)

        # -------------------------------------------------------------
        # 2. Government Portals & Multi-Port Manager Card
        # -------------------------------------------------------------
        ports_card = QFrame()
        ports_card.setProperty("class", "CardFrame")
        p_layout = QVBoxLayout(ports_card)
        p_layout.setContentsMargins(18, 16, 18, 16)
        p_layout.setSpacing(12)

        p_header = QHBoxLayout()
        lbl_ports_title = QLabel("GOVERNMENT PORTALS & CONFIGURED PORTS")
        lbl_ports_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #ffffff;")
        p_header.addWidget(lbl_ports_title)
        p_header.addStretch()

        btn_refresh_ports = QPushButton("🔄 Refresh Port Statuses")
        btn_refresh_ports.clicked.connect(self._refresh_ports_table)
        p_header.addWidget(btn_refresh_ports)

        p_layout.addLayout(p_header)

        # Ports Table
        self.table_ports = QTableWidget()
        self.table_ports.setColumnCount(5)
        self.table_ports.setHorizontalHeaderLabels([
            "Port",
            "Protocol",
            "Portal / Target Service",
            "Listener Status",
            "Actions",
        ])
        self.table_ports.verticalHeader().setVisible(False)
        self.table_ports.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_ports.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table_ports.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table_ports.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_ports.setMinimumHeight(240)
        p_layout.addWidget(self.table_ports)

        # -------------------------------------------------------------
        # "Add Custom Port for Other Govt Portal" Form
        # -------------------------------------------------------------
        add_box = QFrame()
        add_box.setProperty("class", "SubCardFrame")
        ab_layout = QVBoxLayout(add_box)
        ab_layout.setContentsMargins(14, 12, 14, 12)
        ab_layout.setSpacing(10)

        lbl_add_title = QLabel("➕ Add Custom Port for Other Government Portal or ERP")
        lbl_add_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #38bdf8;")
        ab_layout.addWidget(lbl_add_title)

        form_row = QHBoxLayout()
        form_row.setSpacing(10)

        form_row.addWidget(QLabel("Port:"))
        self.spin_port = QSpinBox()
        self.spin_port.setRange(80, 65535)
        self.spin_port.setValue(8085)
        self.spin_port.setFixedWidth(90)
        form_row.addWidget(self.spin_port)

        form_row.addWidget(QLabel("Protocol:"))
        self.combo_proto = QComboBox()
        self.combo_proto.addItems(["HTTP", "HTTPS"])
        self.combo_proto.setFixedWidth(90)
        form_row.addWidget(self.combo_proto)

        form_row.addWidget(QLabel("Portal / Description:"))
        self.edit_portal_desc = QLineEdit()
        self.edit_portal_desc.setPlaceholderText("e.g., State Commercial Tax Portal, e-Procurement, Custom ERP")
        form_row.addWidget(self.edit_portal_desc)

        btn_add_port = QPushButton("➕ Add & Activate Port")
        btn_add_port.setProperty("class", "PrimaryButton")
        btn_add_port.clicked.connect(self._add_custom_port)
        form_row.addWidget(btn_add_port)

        ab_layout.addLayout(form_row)
        p_layout.addWidget(add_box)

        # Quick Actions Row
        action_row = QHBoxLayout()
        action_row.setSpacing(8)

        btn_trust_ssl = QPushButton("🛡️ Install Localhost SSL to Windows Trusted Root")
        btn_trust_ssl.setToolTip("Enables Chrome and Edge on HTTPS government portals to talk to localhost without warnings")
        btn_trust_ssl.clicked.connect(self._trust_ssl)
        action_row.addWidget(btn_trust_ssl)

        btn_claim_embridge = QPushButton("⚡ Claim emBridge Port 26769")
        btn_claim_embridge.setToolTip("Stops conflicting background emBridge service so Dhanyah claims port 26769 for Income Tax & MCA")
        btn_claim_embridge.clicked.connect(self._claim_embridge)
        action_row.addWidget(btn_claim_embridge)

        btn_free_conflicts = QPushButton("⚡ Free All Conflicted Ports")
        btn_free_conflicts.setToolTip("Terminates external blocking processes and claims all government portal ports for Dhanyah")
        btn_free_conflicts.clicked.connect(self._free_all_conflicts)
        action_row.addWidget(btn_free_conflicts)

        btn_open_browser = QPushButton("🌐 Open Status in Browser")
        btn_open_browser.clicked.connect(self._open_browser_status)
        action_row.addWidget(btn_open_browser)

        action_row.addStretch()
        p_layout.addLayout(action_row)

        layout.addWidget(ports_card)

        # -------------------------------------------------------------
        # 3. Live Request Stream & Gateway Logs Card
        # -------------------------------------------------------------
        log_card = QFrame()
        log_card.setProperty("class", "CardFrame")
        l_layout = QVBoxLayout(log_card)
        l_layout.setContentsMargins(18, 16, 18, 16)
        l_layout.setSpacing(10)

        log_head = QHBoxLayout()
        lbl_log_title = QLabel("LIVE REQUEST STREAM & GATEWAY LOGS")
        lbl_log_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #94a3b8;")
        log_head.addWidget(lbl_log_title)
        log_head.addStretch()

        btn_clear = QPushButton("Clear Logs")
        btn_clear.setFixedWidth(80)
        btn_clear.clicked.connect(self._clear_logs)
        log_head.addWidget(btn_clear)

        btn_copy = QPushButton("Copy URL")
        btn_copy.setFixedWidth(80)
        btn_copy.clicked.connect(self._copy_url)
        log_head.addWidget(btn_copy)

        l_layout.addLayout(log_head)

        self.text_logs = QPlainTextEdit()
        self.text_logs.setReadOnly(True)
        self.text_logs.setStyleSheet(
            "font-family: monospace; font-size: 11px; background-color: #0b1120; color: #e2e8f0; border-radius: 6px;"
        )
        self.text_logs.setMinimumHeight(150)
        self.text_logs.appendPlainText(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Gateway service ready.")
        l_layout.addWidget(self.text_logs)

        layout.addWidget(log_card)

        scroll.setWidget(container)
        main_layout.addWidget(scroll)

        # Populate initial table
        self._refresh_ports_table()

    def _refresh_stats(self):
        """Alias for refreshing ports table."""
        self._refresh_ports_table()

    def _refresh_ports_table(self):
        """Populates ports table with real-time status and action buttons."""
        overview = self.server.get_port_overview(check_conflicts=True)
        self.table_ports.setRowCount(len(overview))

        active_count = 0
        for row, item in enumerate(overview):
            port = item["port"]
            protocol = item["protocol"].upper()
            name = item["name"]
            is_active = item["is_active"]
            enabled = item["enabled"]
            builtin = item["builtin"]
            conflict = item["conflict"]

            if is_active:
                active_count += 1

            # Col 0: Port
            item_port = QTableWidgetItem(str(port))
            item_port.setTextAlignment(Qt.AlignCenter)
            item_port.setForeground(Qt.white)
            self.table_ports.setItem(row, 0, item_port)

            # Col 1: Protocol Badge
            w_proto = QWidget()
            l_proto = QHBoxLayout(w_proto)
            l_proto.setContentsMargins(4, 2, 4, 2)
            lbl_proto = QLabel(protocol)
            if protocol == "HTTPS":
                lbl_proto.setStyleSheet(
                    "background-color: #064e3b; color: #34d399; border: 1px solid #059669; "
                    "border-radius: 4px; padding: 2px 6px; font-weight: 700; font-size: 11px;"
                )
            else:
                lbl_proto.setStyleSheet(
                    "background-color: #1e3a8a; color: #93c5fd; border: 1px solid #2563eb; "
                    "border-radius: 4px; padding: 2px 6px; font-weight: 700; font-size: 11px;"
                )
            l_proto.addWidget(lbl_proto)
            l_proto.setAlignment(Qt.AlignCenter)
            self.table_ports.setCellWidget(row, 1, w_proto)

            # Col 2: Portal / Service Name
            item_name = QTableWidgetItem(f"{name}")
            item_name.setForeground(Qt.white)
            self.table_ports.setItem(row, 2, item_name)

            # Col 3: Status Badge
            w_status = QWidget()
            l_status = QHBoxLayout(w_status)
            l_status.setContentsMargins(4, 2, 4, 2)
            lbl_status = QLabel()

            if is_active:
                lbl_status.setText("● ACTIVE (Listening)")
                lbl_status.setStyleSheet(
                    "background-color: #064e3b; color: #34d399; border: 1px solid #059669; "
                    "border-radius: 4px; padding: 2px 8px; font-weight: 600; font-size: 11px;"
                )
            elif conflict:
                proc_name = conflict.get("process", "Process")
                proc_pid = conflict.get("pid", "?")
                lbl_status.setText(f"● CONFLICT: {proc_name} (PID {proc_pid})")
                lbl_status.setStyleSheet(
                    "background-color: #7f1d1d; color: #fca5a5; border: 1px solid #dc2626; "
                    "border-radius: 4px; padding: 2px 8px; font-weight: 600; font-size: 11px;"
                )
            elif not enabled:
                lbl_status.setText("○ DISABLED")
                lbl_status.setStyleSheet(
                    "background-color: #334155; color: #94a3b8; border: 1px solid #475569; "
                    "border-radius: 4px; padding: 2px 8px; font-size: 11px;"
                )
            else:
                lbl_status.setText("○ STOPPED")
                lbl_status.setStyleSheet(
                    "background-color: #334155; color: #cbd5e1; border: 1px solid #475569; "
                    "border-radius: 4px; padding: 2px 8px; font-size: 11px;"
                )
            l_status.addWidget(lbl_status)
            self.table_ports.setCellWidget(row, 3, w_status)

            # Col 4: Action Buttons (Test, Free/Claim, Remove)
            w_acts = QWidget()
            l_acts = QHBoxLayout(w_acts)
            l_acts.setContentsMargins(4, 2, 4, 2)
            l_acts.setSpacing(6)

            # Test Ping Button
            btn_test = QPushButton("Test")
            btn_test.setFixedWidth(52)
            btn_test.setToolTip(f"Ping port {port} via loopback HTTP/HTTPS")
            btn_test.clicked.connect(lambda _, p=port: self._test_single_port(p))
            l_acts.addWidget(btn_test)

            # Claim / Free Button if conflict exists
            if conflict:
                btn_claim = QPushButton("⚡ Claim")
                btn_claim.setFixedWidth(64)
                btn_claim.setProperty("class", "DangerButton")
                btn_claim.setToolTip(f"Kill conflicting {conflict.get('process')} to free port {port}")
                btn_claim.clicked.connect(lambda _, p=port: self._claim_single_port(p))
                l_acts.addWidget(btn_claim)

            # Toggle Enable/Disable
            btn_tog = QPushButton("Disable" if enabled else "Enable")
            btn_tog.setFixedWidth(60)
            btn_tog.clicked.connect(lambda _, p=port, en=enabled: self._toggle_single_port(p, not en))
            l_acts.addWidget(btn_tog)

            # Delete button if custom port
            if not builtin:
                btn_del = QPushButton("🗑")
                btn_del.setFixedWidth(30)
                btn_del.setToolTip("Remove custom port")
                btn_del.clicked.connect(lambda _, p=port: self._remove_single_port(p))
                l_acts.addWidget(btn_del)

            l_acts.addStretch()
            self.table_ports.setCellWidget(row, 4, w_acts)

        # Update Master Badge
        if self.server.is_running() and active_count > 0:
            self.lbl_server_status.setText(f"ONLINE ({active_count} Ports Active)")
            self.lbl_server_status.setProperty("class", "BadgeValid")
            self.btn_toggle_server.setText("Stop Service")
            self.btn_toggle_server.setProperty("class", "DangerButton")
        else:
            self.lbl_server_status.setText("STOPPED")
            self.lbl_server_status.setProperty("class", "BadgeExpired")
            self.btn_toggle_server.setText("Start Service")
            self.btn_toggle_server.setProperty("class", "SuccessButton")

        self.lbl_server_status.setStyleSheet("")
        self.btn_toggle_server.setStyleSheet("")

    def _add_custom_port(self):
        port = self.spin_port.value()
        proto = self.combo_proto.currentText().lower()
        desc = self.edit_portal_desc.text().strip()
        if not desc:
            desc = f"Custom Govt Portal ({proto.upper()}:{port})"

        ok, msg = self.server.add_custom_port(port=port, protocol=proto, name=desc, portal=desc)
        self._log_local(f"Add custom port {port}: {msg}")
        self._refresh_ports_table()

        if ok:
            QMessageBox.information(self, "Port Added", f"Success:\n{msg}")
            self.edit_portal_desc.clear()
        else:
            QMessageBox.warning(self, "Port Notice", f"Notice:\n{msg}")

    def _test_single_port(self, port: int):
        ok, msg = self.server.test_port(port)
        self._log_local(f"Ping port {port}: {msg}")
        if ok:
            QMessageBox.information(self, f"Port {port} Responsive", f"✅ {msg}")
        else:
            QMessageBox.warning(self, f"Port {port} Ping Failed", f"⚠️ {msg}")

    def _claim_single_port(self, port: int):
        reply = QMessageBox.question(
            self,
            "Claim Port",
            f"Are you sure you want to terminate the process currently occupying port {port}?\n"
            f"Dhanyah Crypto Utility will claim port {port} immediately.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            ok, msg = self.server.free_and_claim_port(port)
            self._log_local(f"Claim port {port}: {msg}")
            self._refresh_ports_table()
            if ok:
                QMessageBox.information(self, "Port Claimed", f"✅ {msg}")
            else:
                QMessageBox.warning(self, "Port Claim Notice", f"⚠️ {msg}")

    def _toggle_single_port(self, port: int, enable: bool):
        ok, msg = self.server.toggle_port(port, enable)
        self._log_local(f"Toggle port {port}: {msg}")
        self._refresh_ports_table()

    def _remove_single_port(self, port: int):
        reply = QMessageBox.question(
            self,
            "Remove Custom Port",
            f"Are you sure you want to remove port {port} from configuration?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.server.remove_custom_port(port)
            self._log_local(f"Removed custom port {port}")
            self._refresh_ports_table()

    def _free_all_conflicts(self):
        """Scans all ports with conflicts and frees them."""
        overview = self.server.get_port_overview()
        conflicted = [item for item in overview if item["conflict"]]
        if not conflicted:
            QMessageBox.information(self, "No Conflicts", "All configured government ports are clear with no conflicts!")
            return

        freed = []
        for item in conflicted:
            p = item["port"]
            ok, msg = self.server.free_and_claim_port(p)
            self._log_local(f"Free port {p}: {msg}")
            if ok:
                freed.append(str(p))

        self._refresh_ports_table()
        if freed:
            QMessageBox.information(
                self, "Ports Freed", f"Successfully cleared conflicts and claimed ports: {', '.join(freed)}"
            )

    def _toggle_server(self):
        if self.server.is_running():
            self.server.stop()
            self._log_local("Gateway service stopped by user.")
        else:
            ok = self.server.start()
            if ok:
                self._log_local(f"Gateway service resumed across configured ports.")
            else:
                QMessageBox.critical(self, "Server Error", "Failed to start any gateway listeners.")

        self._refresh_ports_table()

    def _on_server_log(self, msg: str):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.text_logs.appendPlainText(f"[{timestamp}] {msg}")

    def _log_local(self, msg: str):
        self._on_server_log(msg)

    def _clear_logs(self):
        self.text_logs.clear()

    def _copy_url(self):
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(f"http://{self.server.host}:{self.server.port}")
        self._log_local(f"Copied gateway URL http://{self.server.host}:{self.server.port} to clipboard.")

    def _trust_ssl(self):
        success, msg = self.server.trust_ssl_certificate()
        if success:
            QMessageBox.information(self, "SSL Trust Configured", f"Success:\n{msg}")
            self._log_local("Localhost SSL certificate trusted in Windows root store.")
        else:
            QMessageBox.warning(self, "SSL Trust Notice", f"Result:\n{msg}")

    def _open_browser_status(self):
        url = QUrl(f"http://{self.server.host}:{self.server.port}/status")
        QDesktopServices.openUrl(url)

    def _claim_embridge(self):
        running = check_embridge_service_running()
        if not running:
            self._log_local("No competing emBridge Windows service is running. Port 26769 is clear.")
            QMessageBox.information(
                self,
                "emBridge Port Status",
                "Official emBridge Windows service is NOT running.\nDhanyah Crypto Utility has control of port 26769.",
            )
            return

        ok, msg = stop_embridge_service()
        if ok:
            self._log_local("Stopped competing emBridge service. Re-binding port 26769...")
            self.server.free_and_claim_port(26769)
            self._refresh_ports_table()
            QMessageBox.information(
                self,
                "emBridge Port Claimed",
                "Successfully stopped conflicting emBridge service!\nDhanyah Crypto Utility is now actively serving Income Tax and MCA on port 26769.",
            )
        else:
            self._log_local(f"Could not stop emBridge service: {msg}")
            QMessageBox.warning(
                self,
                "Service Action Required",
                f"Could not stop emBridge service automatically:\n{msg}\n\nPlease run this utility as Administrator or run 'Stop-Service emBridge' in PowerShell.",
            )
