"""
Dhanyah Crypto Utility - X.509 Certificate List & Table Widget
"""

from typing import List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QPushButton,
    QLabel,
    QFrame,
)

from core.cert_manager import ParsedCertificate
from ui.cert_viewer_dialog import CertViewerDialog


class CertTableWidget(QFrame):
    """Table listing certificates with 30-day expiry badges and inspection."""

    cert_selected = Signal(object)  # Emits selected ParsedCertificate

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CardFrame")
        self._certificates: List[ParsedCertificate] = []
        self._init_ui()

    @property
    def certificates(self) -> List[ParsedCertificate]:
        return self._certificates

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header Row
        header_row = QHBoxLayout()
        lbl_head = QLabel("INSTALLED DIGITAL SIGNATURE CERTIFICATES (DSC)")
        lbl_head.setProperty("class", "CardTitle")
        header_row.addWidget(lbl_head)

        header_row.addStretch()

        self.btn_inspect = QPushButton("Inspect Details")
        self.btn_inspect.setProperty("class", "PrimaryButton")
        self.btn_inspect.setEnabled(False)
        self.btn_inspect.clicked.connect(self._inspect_selected)
        header_row.addWidget(self.btn_inspect)

        layout.addLayout(header_row)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Signer Name (CN)",
            "Device / Token",
            "Class",
            "PAN Number",
            "Issuing CA",
            "Valid Until",
            "Status",
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        self.table.doubleClicked.connect(self._inspect_selected)

        layout.addWidget(self.table)

        # Empty status placeholder
        self.lbl_empty = QLabel("No certificates available. Insert a crypto token or switch to Demo mode.")
        self.lbl_empty.setAlignment(Qt.AlignCenter)
        self.lbl_empty.setProperty("class", "EmptyPlaceholder")
        layout.addWidget(self.lbl_empty)

    def set_certificates(self, certs: List[ParsedCertificate]):
        """Populate the certificate table."""
        self._certificates = certs
        self.table.setRowCount(len(certs))

        if not certs:
            self.table.setVisible(False)
            self.lbl_empty.setVisible(True)
            self.btn_inspect.setEnabled(False)
            return

        self.table.setVisible(True)
        self.lbl_empty.setVisible(False)

        for row, cert in enumerate(certs):
            # CN
            item_cn = QTableWidgetItem(cert.common_name)
            item_cn.setFlags(item_cn.flags() ^ Qt.ItemIsEditable)
            self.table.setItem(row, 0, item_cn)

            # Device / Token
            dev_name = getattr(cert, "token_name", "") or cert.token_id
            item_dev = QTableWidgetItem(dev_name)
            item_dev.setFlags(item_dev.flags() ^ Qt.ItemIsEditable)
            self.table.setItem(row, 1, item_dev)

            # Class
            item_class = QTableWidgetItem(cert.cert_class)
            item_class.setTextAlignment(Qt.AlignCenter)
            item_class.setFlags(item_class.flags() ^ Qt.ItemIsEditable)
            self.table.setItem(row, 2, item_class)

            # PAN
            item_pan = QTableWidgetItem(cert.pan_number or "N/A")
            item_pan.setTextAlignment(Qt.AlignCenter)
            item_pan.setFlags(item_pan.flags() ^ Qt.ItemIsEditable)
            self.table.setItem(row, 3, item_pan)

            # Issuer
            item_issuer = QTableWidgetItem(cert.issuer_cn)
            item_issuer.setFlags(item_issuer.flags() ^ Qt.ItemIsEditable)
            self.table.setItem(row, 4, item_issuer)

            # Expiry
            item_exp = QTableWidgetItem(cert.valid_to.strftime("%d-%b-%Y"))
            item_exp.setTextAlignment(Qt.AlignCenter)
            item_exp.setFlags(item_exp.flags() ^ Qt.ItemIsEditable)
            self.table.setItem(row, 5, item_exp)

            # Status with Badge Widget
            badge = QLabel(cert.expiry_status_text)
            badge.setAlignment(Qt.AlignCenter)
            if cert.is_expired:
                badge.setProperty("class", "BadgeExpired")
            elif cert.is_expiring_soon:
                badge.setProperty("class", "BadgeWarning")
            else:
                badge.setProperty("class", "BadgeValid")

            cell_widget = QWidget()
            cw_layout = QHBoxLayout(cell_widget)
            cw_layout.setContentsMargins(4, 2, 4, 2)
            cw_layout.addWidget(badge)
            self.table.setCellWidget(row, 6, cell_widget)

        # Select first row by default
        if certs:
            self.table.selectRow(0)

    def get_selected_certificate(self) -> Optional[ParsedCertificate]:
        row = self.table.currentRow()
        if 0 <= row < len(self._certificates):
            return self._certificates[row]
        return None

    def _on_selection_changed(self):
        cert = self.get_selected_certificate()
        self.btn_inspect.setEnabled(cert is not None)
        if cert:
            self.cert_selected.emit(cert)

    def _inspect_selected(self):
        cert = self.get_selected_certificate()
        if cert:
            dialog = CertViewerDialog(cert, self)
            dialog.exec()
