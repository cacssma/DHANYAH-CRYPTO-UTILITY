"""
Dhanyah Crypto Utility - X.509 Certificate Details & CCA Inspector Dialog
"""

import os
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QFrame,
    QFileDialog,
    QMessageBox,
    QScrollArea,
    QWidget,
)

from core.cert_manager import ParsedCertificate


class CertViewerDialog(QDialog):
    """Detailed X.509 certificate inspector modal."""

    def __init__(self, cert: ParsedCertificate, parent=None):
        super().__init__(parent)
        self.cert = cert
        self.setWindowTitle(f"Certificate Details - {cert.common_name}")
        self.resize(650, 580)
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        # Header with Class Badge & Expiry Badge
        header_card = QFrame()
        header_card.setProperty("class", "CardFrame")
        h_layout = QVBoxLayout(header_card)

        top_row = QHBoxLayout()
        lbl_cn = QLabel(self.cert.common_name)
        lbl_cn.setStyleSheet("font-size: 18px; font-weight: 700; color: #ffffff;")
        top_row.addWidget(lbl_cn)
        top_row.addStretch()

        # Class badge
        lbl_class = QLabel(self.cert.cert_class)
        lbl_class.setProperty("class", "BadgeInfo")
        top_row.addWidget(lbl_class)

        # Expiry badge
        lbl_status = QLabel(self.cert.expiry_status_text)
        if self.cert.is_expired:
            lbl_status.setProperty("class", "BadgeExpired")
        elif self.cert.is_expiring_soon:
            lbl_status.setProperty("class", "BadgeWarning")
        else:
            lbl_status.setProperty("class", "BadgeValid")
        top_row.addWidget(lbl_status)

        h_layout.addLayout(top_row)

        lbl_issuer = QLabel(f"Issued by: {self.cert.issuer_cn} ({self.cert.issuer_o})")
        lbl_issuer.setStyleSheet("color: #94a3b8; font-size: 12px; margin-top: 4px;")
        h_layout.addWidget(lbl_issuer)

        main_layout.addWidget(header_card)

        # Scrollable area for details
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        content_w = QWidget()
        content_layout = QVBoxLayout(content_w)
        content_layout.setSpacing(12)

        # Section 1: Indian CCA Identity Fields
        cca_card = QFrame()
        cca_card.setProperty("class", "CardFrame")
        cca_grid = QGridLayout(cca_card)
        cca_grid.setVerticalSpacing(8)
        cca_grid.setHorizontalSpacing(16)

        lbl_cca_head = QLabel("INDIAN CCA DSC IDENTITY ATTRIBUTES")
        lbl_cca_head.setStyleSheet("color: #38bdf8; font-size: 11px; font-weight: 700;")
        cca_grid.addWidget(lbl_cca_head, 0, 0, 1, 2)

        self._add_row(cca_grid, 1, "PAN Number (OID 2.5.4.45):", self.cert.pan_number or "N/A (Individual non-PAN)")
        self._add_row(cca_grid, 2, "Organization (O):", self.cert.organization or "Individual DSC")
        self._add_row(cca_grid, 3, "Organizational Unit (OU):", self.cert.org_unit or "N/A")
        self._add_row(cca_grid, 4, "State & Postal Code:", f"{self.cert.state or 'N/A'}, {self.cert.postal_code or ''}")
        self._add_row(cca_grid, 5, "Country:", self.cert.country)

        content_layout.addWidget(cca_card)

        # Section 2: Validity & Cryptographic Specifications
        crypto_card = QFrame()
        crypto_card.setProperty("class", "CardFrame")
        c_grid = QGridLayout(crypto_card)
        c_grid.setVerticalSpacing(8)
        c_grid.setHorizontalSpacing(16)

        lbl_c_head = QLabel("VALIDITY & CRYPTOGRAPHIC PARAMETERS")
        lbl_c_head.setStyleSheet("color: #38bdf8; font-size: 11px; font-weight: 700;")
        c_grid.addWidget(lbl_c_head, 0, 0, 1, 2)

        self._add_row(c_grid, 1, "Valid From:", self.cert.valid_from.strftime("%d %b %Y, %H:%M:%S UTC"))
        self._add_row(c_grid, 2, "Valid Until (Expiry):", self.cert.valid_to.strftime("%d %b %Y, %H:%M:%S UTC"))
        self._add_row(c_grid, 3, "Serial Number:", self.cert.serial_number_hex)
        self._add_row(c_grid, 4, "Key Algorithm:", self.cert.key_algo)
        self._add_row(c_grid, 5, "Key Usage:", self.cert.key_usage_desc)

        content_layout.addWidget(crypto_card)

        # Section 3: Fingerprints
        fp_card = QFrame()
        fp_card.setProperty("class", "CardFrame")
        fp_grid = QGridLayout(fp_card)
        fp_grid.setVerticalSpacing(8)
        fp_grid.setHorizontalSpacing(16)

        lbl_fp_head = QLabel("CERTIFICATE FINGERPRINTS")
        lbl_fp_head.setStyleSheet("color: #38bdf8; font-size: 11px; font-weight: 700;")
        fp_grid.addWidget(lbl_fp_head, 0, 0, 1, 2)

        self._add_row(fp_grid, 1, "SHA-256 Fingerprint:", self.cert.fingerprint_sha256, is_mono=True)
        self._add_row(fp_grid, 2, "SHA-1 Fingerprint:", self.cert.fingerprint_sha1, is_mono=True)

        content_layout.addWidget(fp_card)

        scroll.setWidget(content_w)
        main_layout.addWidget(scroll)

        # Action Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        btn_export_der = QPushButton("Export DER (.cer)")
        btn_export_der.setToolTip("Export certificate as binary DER (.cer) format")
        btn_export_der.clicked.connect(self._export_der)
        btn_row.addWidget(btn_export_der)

        btn_export_pem = QPushButton("Export PEM (.pem)")
        btn_export_pem.setToolTip("Export certificate as ASCII Base64 PEM (.pem) format")
        btn_export_pem.clicked.connect(self._export_pem)
        btn_row.addWidget(btn_export_pem)

        btn_win_view = QPushButton("🪟 Windows Certificate Viewer")
        btn_win_view.setToolTip("Launch native Windows Certificate Properties inspector with full CA trust chain")
        btn_win_view.clicked.connect(self._open_in_windows_viewer)
        btn_row.addWidget(btn_win_view)

        btn_row.addStretch()

        btn_close = QPushButton("Close")
        btn_close.setProperty("class", "PrimaryButton")
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)

        main_layout.addLayout(btn_row)

    def _add_row(self, grid: QGridLayout, row: int, label: str, value: str, is_mono: bool = False):
        lbl = QLabel(label)
        lbl.setStyleSheet("color: #64748b; font-weight: 600;")
        grid.addWidget(lbl, row, 0)

        val = QLabel(value)
        if is_mono:
            val.setStyleSheet("color: #e2e8f0; font-family: monospace; font-size: 11px;")
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
        else:
            val.setStyleSheet("color: #e2e8f0; font-weight: 500;")
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
        grid.addWidget(val, row, 1)

    def _export_der(self):
        """Export certificate as binary DER (.cer)."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Certificate (DER)",
            f"{self.cert.common_name.replace(' ', '_')}.cer",
            "DER Certificate (*.cer);;All Files (*)",
        )
        if file_path:
            try:
                with open(file_path, "wb") as f:
                    f.write(self.cert.cert_der)
                QMessageBox.information(self, "Export Successful", f"DER Certificate saved to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to save certificate: {e}")

    def _export_pem(self):
        """Export certificate as Base64 PEM (.pem)."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Certificate (PEM)",
            f"{self.cert.common_name.replace(' ', '_')}.pem",
            "PEM Certificate (*.pem *.crt);;All Files (*)",
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(self.cert.cert_pem)
                QMessageBox.information(self, "Export Successful", f"PEM Certificate saved to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to save certificate: {e}")

    def _open_in_windows_viewer(self):
        """Open the certificate in the native Windows Crypto Shell Viewer."""
        try:
            import tempfile
            import subprocess
            temp_dir = tempfile.gettempdir()
            clean_cn = "".join(c for c in self.cert.common_name if c.isalnum() or c in (" ", "_", "-")).strip()
            temp_path = os.path.join(temp_dir, f"DSC_{clean_cn}_{self.cert.serial_number_hex[:8]}.cer")
            with open(temp_path, "wb") as f:
                f.write(self.cert.cert_der)

            if os.name == "nt":
                try:
                    os.startfile(temp_path)
                except Exception:
                    subprocess.Popen(["rundll32.exe", "cryptext.dll,CryptExtOpenCER", temp_path])
            else:
                QMessageBox.information(self, "Certificate Saved", f"Certificate written to:\n{temp_path}")
        except Exception as e:
            QMessageBox.critical(self, "Certificate Viewer", f"Failed to launch Windows Certificate Viewer: {e}")
