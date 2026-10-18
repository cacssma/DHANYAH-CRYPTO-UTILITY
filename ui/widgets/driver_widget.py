"""
Dhanyah Crypto Utility - Dynamic Driver Discovery & System Health Widget
Displays PKCS#11 validation status and Windows Smart Card / CAPI / Adobe / Browser integration.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QFrame,
    QScrollArea,
    QMessageBox,
)

from core.pkcs11_manager import PKCS11Manager
from core.smartcard_registrar import SmartCardRegistrar


class DriverWidget(QWidget):
    """Displays PKCS#11 middleware health and Windows Smart Card subsystem integration."""

    def __init__(self, pkcs11_mgr: PKCS11Manager, parent=None):
        super().__init__(parent)
        self.pkcs11_mgr = pkcs11_mgr
        self._init_ui()

    def _init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        # -------------------------------------------------------------
        # CARD 1: Windows Smart Card & Browser / Adobe Acrobat Integration
        # -------------------------------------------------------------
        win_card = QFrame()
        win_card.setProperty("class", "CardFrame")
        wc_layout = QVBoxLayout(win_card)
        wc_layout.setContentsMargins(18, 18, 18, 18)
        wc_layout.setSpacing(12)

        wc_top = QHBoxLayout()
        lbl_win_head = QLabel("WINDOWS SYSTEM, ADOBE ACROBAT & BROWSER INTEGRATION")
        lbl_win_head.setProperty("class", "SectionTitle")
        wc_top.addWidget(lbl_win_head)
        wc_top.addStretch()

        btn_repair = QPushButton("⚡ Auto-Configure & Repair Integration")
        btn_repair.clicked.connect(self._repair_windows_integration)
        wc_top.addWidget(btn_repair)

        btn_pulse = QPushButton("🔄 Sync Certificates to Windows")
        btn_pulse.clicked.connect(self._pulse_certificates)
        wc_top.addWidget(btn_pulse)

        wc_layout.addLayout(wc_top)

        lbl_win_desc = QLabel(
            "Enables native plug-and-play signing across Windows applications without installing separate proprietary vendor software. "
            "Registers Smart Card MiniDrivers and CSPs so Adobe Acrobat (Windows Digital ID), Google Chrome, Microsoft Edge, "
            "and government portals (MCA, GST, Income Tax, EPFO) automatically recognize all 4 tokens."
        )
        lbl_win_desc.setWordWrap(True)
        lbl_win_desc.setProperty("class", "SubText")
        wc_layout.addWidget(lbl_win_desc)

        self.win_grid_container = QVBoxLayout()
        self.win_grid_container.setSpacing(8)
        wc_layout.addLayout(self.win_grid_container)

        layout.addWidget(win_card)

        # -------------------------------------------------------------
        # CARD 2: PKCS#11 Middleware & Dynamic Discovery
        # -------------------------------------------------------------
        p11_card = QFrame()
        p11_card.setProperty("class", "CardFrame")
        c_layout = QVBoxLayout(p11_card)
        c_layout.setContentsMargins(18, 18, 18, 18)
        c_layout.setSpacing(12)

        top_row = QHBoxLayout()
        lbl_head = QLabel("PKCS#11 MIDDLEWARE & PORTABLE DRIVERS")
        lbl_head.setProperty("class", "SectionTitle")
        top_row.addWidget(lbl_head)
        top_row.addStretch()

        btn_rescan = QPushButton("Rescan Drivers")
        btn_rescan.clicked.connect(self._rescan_drivers)
        top_row.addWidget(btn_rescan)

        c_layout.addLayout(top_row)

        lbl_desc = QLabel(
            "Dhanyah Crypto Utility dynamically searches Windows System32, SysWOW64, vendor Program Files, "
            "and bundled portable drivers to auto-load the correct PKCS#11 dynamic library for any connected token."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setProperty("class", "SubText")
        c_layout.addWidget(lbl_desc)

        self.driver_container = QVBoxLayout()
        self.driver_container.setSpacing(10)
        c_layout.addLayout(self.driver_container)

        layout.addWidget(p11_card)
        layout.addStretch()

        scroll.setWidget(content)
        root_layout.addWidget(scroll)

        # Initial render
        self._render_windows_subsystem_card()
        self._render_driver_cards()

    def _render_windows_subsystem_card(self):
        while self.win_grid_container.count():
            item = self.win_grid_container.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        health = SmartCardRegistrar.check_subsystem_health()

        items = [
            ("HyperPKI HYP 2003 FIPS L3 (v3.3)", health["cards"].get("hyp2003_v33", {}).get("registered", False)),
            ("HyperPKI HYP 2003 Standard (v3.0)", health["cards"].get("hyp2003", {}).get("registered", False) or health["cards"].get("hyp2003_v2", {}).get("registered", False)),
            ("mToken Blue Classic MiniDriver (Longmai)", health["cards"].get("mtoken_blue", {}).get("registered", False)),
            ("mToken Purple FIPS F3 MiniDriver (Longmai)", health["cards"].get("mtoken_purple", {}).get("registered", False)),
            ("Watchdata ProxKey CSP / MiniDriver", health["cards"].get("proxkey", {}).get("registered", False)),
            ("Precision InnaITKey CSP / MiniDriver", health["cards"].get("innait", {}).get("registered", False)),
            ("Windows Certificate Propagation Service (CertPropSvc)", health["services"].get("CertPropSvc", False)),
            ("Smart Card Resource Manager Service (SCardSvr)", health["services"].get("SCardSvr", False)),
        ]

        sub_card = QFrame()
        sub_card.setProperty("class", "SubCardFrame")
        grid = QGridLayout(sub_card)
        grid.setVerticalSpacing(8)
        grid.setHorizontalSpacing(16)

        for i, (name, is_ok) in enumerate(items):
            row = i // 2
            col = (i % 2) * 2

            lbl_name = QLabel(f"●  {name}")
            lbl_name.setProperty("class", "FieldLabel")
            grid.addWidget(lbl_name, row, col)

            badge = QLabel("ACTIVE & REGISTERED" if is_ok else "NOT CONFIGURED")
            badge.setProperty("class", "BadgeValid" if is_ok else "BadgeExpired")
            grid.addWidget(badge, row, col + 1, Qt.AlignRight)

        self.win_grid_container.addWidget(sub_card)

    def _repair_windows_integration(self):
        success, msg = SmartCardRegistrar.register_windows_subsystem()
        if success:
            QMessageBox.information(
                self,
                "Windows Integration Successful",
                f"{msg}\n\nAdobe Acrobat, Google Chrome, and Microsoft Edge can now recognize your tokens natively!",
            )
        else:
            QMessageBox.warning(
                self,
                "Windows Integration Notice",
                f"{msg}\n\nPlease run Dhanyah Crypto Utility as Administrator to configure Windows system drivers.",
            )
        self._render_windows_subsystem_card()

    def _pulse_certificates(self):
        ok = SmartCardRegistrar.pulse_windows_certificates()
        if ok:
            QMessageBox.information(
                self,
                "Certificates Synced",
                "Successfully pulsed Windows Certificate Propagation Service!\n\n"
                "Inserted token certificates have been refreshed into Windows Personal Store (CurrentUser\\My).",
            )
        else:
            QMessageBox.warning(
                self,
                "Sync Notice",
                "Could not pulse certificates. Ensure the Smart Card service is running.",
            )
        self._render_windows_subsystem_card()

    def _rescan_drivers(self):
        self.pkcs11_mgr.refresh_drivers()
        self._render_driver_cards()
        self._render_windows_subsystem_card()

    def _render_driver_cards(self):
        while self.driver_container.count():
            item = self.driver_container.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

        statuses = self.pkcs11_mgr.get_all_driver_statuses()
        for d in statuses:
            d_card = QFrame()
            d_card.setProperty("class", "SubCardFrame")
            grid = QGridLayout(d_card)
            grid.setVerticalSpacing(4)
            grid.setHorizontalSpacing(12)

            lbl_name = QLabel(d.token_name)
            lbl_name.setProperty("class", "SectionTitle")
            grid.addWidget(lbl_name, 0, 0)

            badge = QLabel("VERIFIED & LOADABLE" if d.is_loadable else ("INSTALLED" if d.is_installed else "MISSING"))
            if d.is_loadable:
                badge.setProperty("class", "BadgeValid")
            elif d.is_installed:
                badge.setProperty("class", "BadgeWarning")
            else:
                badge.setProperty("class", "BadgeExpired")
            grid.addWidget(badge, 0, 1, Qt.AlignRight)

            lbl_vendor = QLabel(f"Vendor: {d.vendor}  |  Arch: {d.bitness}")
            lbl_vendor.setProperty("class", "SubText")
            grid.addWidget(lbl_vendor, 1, 0, 1, 2)

            path_str = d.dll_path or "No compatible DLL found"
            lbl_path = QLabel(f"Path: {path_str}")
            lbl_path.setProperty("class", "TechCode")
            lbl_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid.addWidget(lbl_path, 2, 0, 1, 2)

            if d.error_message:
                lbl_msg = QLabel(d.error_message)
                lbl_msg.setProperty("class", "SubText")
                grid.addWidget(lbl_msg, 3, 0, 1, 2)

            self.driver_container.addWidget(d_card)
