"""
Dhanyah Crypto Utility - PDF Document Signer Widget (PAdES Hardware Signing)
Supports Single PDF Signing with Visual Appearance Stamps & High-Volume Batch PDF Signing.
"""

import os
import subprocess
from typing import List, Optional
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QComboBox,
    QFileDialog,
    QFrame,
    QMessageBox,
    QProgressBar,
    QTabWidget,
    QCheckBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QGroupBox,
)

from core.cert_manager import ParsedCertificate
from core.signer import TokenSigner, SignResult, VisualSignatureConfig, BatchSignProgress


class PdfSignerWidget(QWidget):
    """PDF signing utility widget with single document and batch document processing."""

    def __init__(self, signer: TokenSigner, parent=None):
        super().__init__(parent)
        self.signer = signer
        self._certificates: List[ParsedCertificate] = []
        self._current_token_id = ""
        self._current_slot = 0
        self._is_simulated = False
        self._single_signed_path = ""
        self._batch_files: List[str] = []
        self._init_ui()

    def set_token_context(
        self,
        token_id: str,
        slot: int,
        certs: List[ParsedCertificate],
        is_simulated: bool = False,
    ):
        self._current_token_id = token_id
        self._current_slot = slot
        self._certificates = certs
        self._is_simulated = is_simulated

        # Update Single combo
        self.combo_certs.clear()
        self.combo_batch_certs.clear()

        for c in certs:
            pan_str = f" [PAN: {c.pan_number}]" if c.pan_number else ""
            label = f"{c.common_name} ({c.cert_class}){pan_str}"
            self.combo_certs.addItem(label, c)
            self.combo_batch_certs.addItem(label, c)

        has_certs = len(certs) > 0
        self.btn_sign_single.setEnabled(has_certs)
        self.btn_start_batch.setEnabled(has_certs and len(self._batch_files) > 0)

        if not has_certs:
            self.lbl_single_status.setText("No signing certificate available. Insert token or enable Demo mode.")
            self.lbl_single_status.setProperty("class", "BadgeWarning")
        else:
            self.lbl_single_status.setText(f"Ready to sign with {len(certs)} certificate(s) loaded.")
            self.lbl_single_status.setProperty("class", "BadgeValid")
        self.lbl_single_status.setStyleSheet("")

    def _init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(12)

        self.tabs = QTabWidget()

        # Tab 1: Single PDF Document Signer
        tab_single = QWidget()
        self._setup_single_tab(tab_single)
        self.tabs.addTab(tab_single, "✍️  Single PDF Document Signer")

        # Tab 2: Batch PDF Document Signer
        tab_batch = QWidget()
        self._setup_batch_tab(tab_batch)
        self.tabs.addTab(tab_batch, "⚡  Batch PDF Signer (Folder / Multi-File)")

        root_layout.addWidget(self.tabs)

    # -------------------------------------------------------------------------
    # TAB 1: Single PDF Signer
    # -------------------------------------------------------------------------
    def _setup_single_tab(self, parent: QWidget):
        layout = QVBoxLayout(parent)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        card = QFrame()
        card.setProperty("class", "CardFrame")
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(18, 16, 18, 16)
        c_layout.setSpacing(12)

        lbl_head = QLabel("PADES PDF DIGITAL SIGNER")
        lbl_head.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff;")
        c_layout.addWidget(lbl_head)

        lbl_desc = QLabel(
            "Cryptographically signs PDF documents using SHA-256 with the RSA private key "
            "stored onboard the FIPS Level 3 crypto token (PAdES / adbe.pkcs7.detached). "
            "Supports customizable visible signature stamps."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("color: #94a3b8; font-size: 12px;")
        c_layout.addWidget(lbl_desc)

        grid = QGridLayout()
        grid.setVerticalSpacing(8)
        grid.setHorizontalSpacing(14)

        # 1. Input PDF File
        lbl_pdf = QLabel("Input PDF File:")
        lbl_pdf.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        grid.addWidget(lbl_pdf, 0, 0)

        pdf_row = QHBoxLayout()
        self.edit_pdf_path = QLineEdit()
        self.edit_pdf_path.setPlaceholderText("Select or drop a PDF file to sign...")
        pdf_row.addWidget(self.edit_pdf_path)

        btn_browse = QPushButton("Browse...")
        btn_browse.clicked.connect(self._browse_pdf)
        pdf_row.addWidget(btn_browse)
        grid.addLayout(pdf_row, 0, 1)

        # 2. Certificate Selector
        lbl_cert = QLabel("Signing Certificate:")
        lbl_cert.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        grid.addWidget(lbl_cert, 1, 0)

        self.combo_certs = QComboBox()
        grid.addWidget(self.combo_certs, 1, 1)

        # 3. Token PIN
        lbl_pin = QLabel("Token User PIN:")
        lbl_pin.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        grid.addWidget(lbl_pin, 2, 0)

        pin_row = QHBoxLayout()
        self.edit_pin = QLineEdit()
        self.edit_pin.setEchoMode(QLineEdit.Password)
        self.edit_pin.setPlaceholderText("Enter token PIN to unlock hardware signing")
        pin_row.addWidget(self.edit_pin)
        grid.addLayout(pin_row, 2, 1)

        # 4. Reason
        lbl_reason = QLabel("Signing Reason:")
        lbl_reason.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        grid.addWidget(lbl_reason, 3, 0)

        self.combo_reason = QComboBox()
        self.combo_reason.setEditable(True)
        self.combo_reason.addItem("I have reviewed and approved this document")
        self.combo_reason.addItem("MCA / Registrar of Companies Filing")
        self.combo_reason.addItem("GST Return & Invoice Attestation")
        self.combo_reason.addItem("Income Tax Return e-Verification")
        self.combo_reason.addItem("Tender Submission / e-Procurement")
        self.combo_reason.addItem("General Document Verification")
        grid.addWidget(self.combo_reason, 3, 1)

        # 5. Location
        lbl_loc = QLabel("Signing Location:")
        lbl_loc.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        grid.addWidget(lbl_loc, 4, 0)

        self.edit_loc = QLineEdit("India")
        grid.addWidget(self.edit_loc, 4, 1)

        # 6. Output PDF File
        lbl_out = QLabel("Save Signed PDF To:")
        lbl_out.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        grid.addWidget(lbl_out, 5, 0)

        out_row = QHBoxLayout()
        self.edit_out_path = QLineEdit()
        self.edit_out_path.setPlaceholderText("Auto-generated: <filename>_signed.pdf")
        out_row.addWidget(self.edit_out_path)

        btn_browse_out = QPushButton("Change...")
        btn_browse_out.clicked.connect(self._browse_out)
        out_row.addWidget(btn_browse_out)
        grid.addLayout(out_row, 5, 1)

        c_layout.addLayout(grid)

        # Visual Appearance Options
        vis_box = QFrame()
        vis_box.setProperty("class", "SubCardFrame")
        vb_layout = QVBoxLayout(vis_box)
        vb_layout.setContentsMargins(12, 10, 12, 10)
        vb_layout.setSpacing(8)

        v_top = QHBoxLayout()
        self.chk_visible = QCheckBox("Add Visible Digital Signature Box (Visual Stamp)")
        self.chk_visible.setChecked(True)
        self.chk_visible.setStyleSheet("font-weight: 600; color: #38bdf8;")
        v_top.addWidget(self.chk_visible)
        v_top.addStretch()

        lbl_pos = QLabel("Position:")
        lbl_pos.setStyleSheet("color: #94a3b8;")
        v_top.addWidget(lbl_pos)
        self.combo_pos = QComboBox()
        self.combo_pos.addItem("Bottom-Right (Standard)", "bottom-right")
        self.combo_pos.addItem("Bottom-Left", "bottom-left")
        self.combo_pos.addItem("Top-Right", "top-right")
        self.combo_pos.addItem("Top-Left", "top-left")
        v_top.addWidget(self.combo_pos)

        lbl_pg = QLabel("Page:")
        lbl_pg.setStyleSheet("color: #94a3b8;")
        v_top.addWidget(lbl_pg)
        self.combo_page = QComboBox()
        self.combo_page.addItem("Last Page (Default)", "last")
        self.combo_page.addItem("First Page", "first")
        v_top.addWidget(self.combo_page)

        vb_layout.addLayout(v_top)

        opts_row = QHBoxLayout()
        self.chk_show_pan = QCheckBox("Show PAN on Stamp")
        self.chk_show_pan.setChecked(True)
        opts_row.addWidget(self.chk_show_pan)

        self.chk_show_date = QCheckBox("Show Timestamp")
        self.chk_show_date.setChecked(True)
        opts_row.addWidget(self.chk_show_date)

        self.chk_show_reason = QCheckBox("Show Reason / Location")
        self.chk_show_reason.setChecked(True)
        opts_row.addWidget(self.chk_show_reason)

        opts_row.addStretch()
        vb_layout.addLayout(opts_row)
        c_layout.addWidget(vis_box)

        # Action Button Row
        act_row = QHBoxLayout()
        self.btn_sign_single = QPushButton("Sign PDF Document")
        self.btn_sign_single.setProperty("class", "PrimaryButton")
        self.btn_sign_single.setMinimumHeight(38)
        self.btn_sign_single.clicked.connect(self._on_sign_single_clicked)
        act_row.addWidget(self.btn_sign_single)

        self.btn_open_signed = QPushButton("Open Signed PDF")
        self.btn_open_signed.setProperty("class", "SuccessButton")
        self.btn_open_signed.setMinimumHeight(38)
        self.btn_open_signed.setVisible(False)
        self.btn_open_signed.clicked.connect(self._open_signed_pdf)
        act_row.addWidget(self.btn_open_signed)

        c_layout.addLayout(act_row)

        self.lbl_single_status = QLabel("Select a PDF file and enter PIN to sign.")
        self.lbl_single_status.setProperty("class", "BadgeInfo")
        self.lbl_single_status.setWordWrap(True)
        c_layout.addWidget(self.lbl_single_status)

        layout.addWidget(card)

    # -------------------------------------------------------------------------
    # TAB 2: Batch PDF Signer
    # -------------------------------------------------------------------------
    def _setup_batch_tab(self, parent: QWidget):
        layout = QVBoxLayout(parent)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        card = QFrame()
        card.setProperty("class", "CardFrame")
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(18, 16, 18, 16)
        c_layout.setSpacing(12)

        lbl_head = QLabel("HIGH-VOLUME BATCH PDF SIGNER")
        lbl_head.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff;")
        c_layout.addWidget(lbl_head)

        lbl_desc = QLabel(
            "Sign tens or hundreds of invoices, tax forms, or reports in a single automated batch. "
            "The token session is authenticated once with your PIN so you do not have to re-enter it for every file."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("color: #94a3b8; font-size: 12px;")
        c_layout.addWidget(lbl_desc)

        # Batch Header Buttons
        btn_bar = QHBoxLayout()
        btn_add_files = QPushButton("➕ Add PDF Files...")
        btn_add_files.clicked.connect(self._batch_add_files)
        btn_bar.addWidget(btn_add_files)

        btn_add_folder = QPushButton("📁 Add Entire Folder...")
        btn_add_folder.clicked.connect(self._batch_add_folder)
        btn_bar.addWidget(btn_add_folder)

        btn_clear_batch = QPushButton("Clear List")
        btn_clear_batch.clicked.connect(self._batch_clear)
        btn_bar.addWidget(btn_clear_batch)

        btn_bar.addStretch()

        self.lbl_batch_count = QLabel("0 PDF files selected")
        self.lbl_batch_count.setProperty("class", "BadgeInfo")
        btn_bar.addWidget(self.lbl_batch_count)

        c_layout.addLayout(btn_bar)

        # Files Table
        self.batch_table = QTableWidget()
        self.batch_table.setColumnCount(3)
        self.batch_table.setHorizontalHeaderLabels(["Filename", "Size", "Status"])
        self.batch_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.batch_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.batch_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.batch_table.setMaximumHeight(160)
        c_layout.addWidget(self.batch_table)

        # Batch Config Grid
        b_grid = QGridLayout()
        b_grid.setVerticalSpacing(8)
        b_grid.setHorizontalSpacing(12)

        b_grid.addWidget(QLabel("Output Directory:"), 0, 0)
        out_box = QHBoxLayout()
        self.edit_batch_out_dir = QLineEdit()
        self.edit_batch_out_dir.setPlaceholderText("Select folder where signed PDFs will be saved...")
        out_box.addWidget(self.edit_batch_out_dir)

        btn_browse_b_out = QPushButton("Browse...")
        btn_browse_b_out.clicked.connect(self._batch_browse_out_dir)
        out_box.addWidget(btn_browse_b_out)
        b_grid.addLayout(out_box, 0, 1)

        b_grid.addWidget(QLabel("Signing Certificate:"), 1, 0)
        self.combo_batch_certs = QComboBox()
        b_grid.addWidget(self.combo_batch_certs, 1, 1)

        b_grid.addWidget(QLabel("Token PIN (Single Auth):"), 2, 0)
        self.edit_batch_pin = QLineEdit()
        self.edit_batch_pin.setEchoMode(QLineEdit.Password)
        self.edit_batch_pin.setPlaceholderText("Enter token PIN once for the entire batch")
        b_grid.addWidget(self.edit_batch_pin, 2, 1)

        c_layout.addLayout(b_grid)

        # Progress bar
        self.batch_progress = QProgressBar()
        self.batch_progress.setValue(0)
        self.batch_progress.setVisible(False)
        c_layout.addWidget(self.batch_progress)

        # Action Buttons
        b_act_row = QHBoxLayout()
        self.btn_start_batch = QPushButton("⚡ Start Batch Signing")
        self.btn_start_batch.setProperty("class", "PrimaryButton")
        self.btn_start_batch.setMinimumHeight(38)
        self.btn_start_batch.setEnabled(False)
        self.btn_start_batch.clicked.connect(self._on_start_batch_clicked)
        b_act_row.addWidget(self.btn_start_batch)

        self.btn_open_batch_dir = QPushButton("Open Output Folder")
        self.btn_open_batch_dir.setProperty("class", "SuccessButton")
        self.btn_open_batch_dir.setMinimumHeight(38)
        self.btn_open_batch_dir.setVisible(False)
        self.btn_open_batch_dir.clicked.connect(self._open_batch_folder)
        b_act_row.addWidget(self.btn_open_batch_dir)

        c_layout.addLayout(b_act_row)

        self.lbl_batch_status = QLabel("Add PDF files above and select output folder to begin.")
        self.lbl_batch_status.setProperty("class", "BadgeInfo")
        c_layout.addWidget(self.lbl_batch_status)

        layout.addWidget(card)

    # -------------------------------------------------------------------------
    # Single Signing Handlers
    # -------------------------------------------------------------------------
    def _browse_pdf(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select PDF to Sign",
            "",
            "PDF Documents (*.pdf);;All Files (*)",
        )
        if file_path:
            self.edit_pdf_path.setText(file_path)
            base, ext = os.path.splitext(file_path)
            self.edit_out_path.setText(f"{base}_signed{ext}")

    def _browse_out(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Signed PDF",
            self.edit_out_path.text() or "document_signed.pdf",
            "PDF Documents (*.pdf);;All Files (*)",
        )
        if file_path:
            self.edit_out_path.setText(file_path)

    def _on_sign_single_clicked(self):
        in_path = self.edit_pdf_path.text().strip()
        out_path = self.edit_out_path.text().strip()
        pin = self.edit_pin.text()
        cert: ParsedCertificate = self.combo_certs.currentData()

        if not in_path or not os.path.exists(in_path):
            QMessageBox.warning(self, "Invalid File", "Please select a valid input PDF file.")
            return

        if not out_path:
            base, ext = os.path.splitext(in_path)
            out_path = f"{base}_signed{ext}"
            self.edit_out_path.setText(out_path)

        if not cert:
            QMessageBox.warning(self, "No Certificate", "Please select a signing certificate.")
            return

        if not pin:
            QMessageBox.warning(self, "PIN Required", "Please enter the Token PIN to authorize hardware signing.")
            return

        vis_cfg = VisualSignatureConfig(
            visible=self.chk_visible.isChecked(),
            position=self.combo_pos.currentData() or "bottom-right",
            page=self.combo_page.currentData() or "last",
            show_pan=self.chk_show_pan.isChecked(),
            show_date=self.chk_show_date.isChecked(),
            show_reason=self.chk_show_reason.isChecked(),
        )

        self.btn_sign_single.setEnabled(False)
        self.lbl_single_status.setText("Connecting to crypto token and computing PAdES signature...")
        self.lbl_single_status.setProperty("class", "BadgeInfo")
        self.lbl_single_status.setStyleSheet("")

        try:
            res: SignResult = self.signer.sign_pdf(
                input_pdf_path=in_path,
                output_pdf_path=out_path,
                token_id=self._current_token_id or "SIMULATED",
                slot=self._current_slot,
                pin=pin,
                cert=cert,
                reason=self.combo_reason.currentText(),
                location=self.edit_loc.text(),
                is_simulated=self._is_simulated,
                visual_config=vis_cfg,
            )

            if res.success:
                self._single_signed_path = out_path
                self.lbl_single_status.setText(f"✓ PDF digitally signed successfully: {out_path}")
                self.lbl_single_status.setProperty("class", "BadgeValid")
                self.btn_open_signed.setVisible(True)
                QMessageBox.information(
                    self,
                    "Signing Complete",
                    f"Document successfully signed!\nSigner: {cert.common_name}\nOutput: {out_path}",
                )
            else:
                self.lbl_single_status.setText(f"Signing failed: {res.error_message}")
                self.lbl_single_status.setProperty("class", "BadgeExpired")
                QMessageBox.critical(self, "Signing Error", f"Failed to sign PDF:\n{res.error_message}")
        finally:
            self.btn_sign_single.setEnabled(True)
            self.lbl_single_status.setStyleSheet("")

    def _open_signed_pdf(self):
        if self._single_signed_path and os.path.exists(self._single_signed_path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(self._single_signed_path))

    # -------------------------------------------------------------------------
    # Batch Signing Handlers
    # -------------------------------------------------------------------------
    def _batch_add_files(self):
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select PDFs to Sign",
            "",
            "PDF Documents (*.pdf);;All Files (*)",
        )
        if files:
            for f in files:
                if f not in self._batch_files:
                    self._batch_files.append(f)
            self._refresh_batch_table()

    def _batch_add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder Containing PDFs")
        if folder:
            for root, _, files in os.walk(folder):
                for f in files:
                    if f.lower().endswith(".pdf"):
                        full_p = os.path.join(root, f)
                        if full_p not in self._batch_files:
                            self._batch_files.append(full_p)
            self._refresh_batch_table()

    def _batch_clear(self):
        self._batch_files.clear()
        self._refresh_batch_table()

    def _refresh_batch_table(self):
        self.batch_table.setRowCount(len(self._batch_files))
        for row, f_path in enumerate(self._batch_files):
            fname = os.path.basename(f_path)
            try:
                sz_kb = os.path.getsize(f_path) // 1024
                sz_str = f"{sz_kb} KB"
            except Exception:
                sz_str = "N/A"

            self.batch_table.setItem(row, 0, QTableWidgetItem(fname))
            self.batch_table.setItem(row, 1, QTableWidgetItem(sz_str))
            self.batch_table.setItem(row, 2, QTableWidgetItem("Queued"))

        self.lbl_batch_count.setText(f"{len(self._batch_files)} PDF file(s) queued")
        has_certs = len(self._certificates) > 0
        self.btn_start_batch.setEnabled(has_certs and len(self._batch_files) > 0)

        # Set default output dir if empty
        if self._batch_files and not self.edit_batch_out_dir.text():
            first_dir = os.path.dirname(self._batch_files[0])
            self.edit_batch_out_dir.setText(os.path.join(first_dir, "Signed_PDFs"))

    def _batch_browse_out_dir(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Directory for Signed Files")
        if folder:
            self.edit_batch_out_dir.setText(folder)

    def _on_start_batch_clicked(self):
        out_dir = self.edit_batch_out_dir.text().strip()
        pin = self.edit_batch_pin.text()
        cert: ParsedCertificate = self.combo_batch_certs.currentData()

        if not self._batch_files:
            QMessageBox.warning(self, "No Files", "Please add one or more PDF files to sign.")
            return

        if not out_dir:
            QMessageBox.warning(self, "Output Directory", "Please select an output directory.")
            return

        if not cert:
            QMessageBox.warning(self, "Certificate Required", "Please select a signing certificate.")
            return

        if not pin:
            QMessageBox.warning(self, "PIN Required", "Please enter the Token PIN to authorize batch signing.")
            return

        self.btn_start_batch.setEnabled(False)
        self.batch_progress.setVisible(True)
        self.batch_progress.setMaximum(len(self._batch_files))
        self.batch_progress.setValue(0)
        self.lbl_batch_status.setText("Initializing token hardware session...")

        vis_cfg = VisualSignatureConfig(
            visible=self.chk_visible.isChecked(),
            position=self.combo_pos.currentData() or "bottom-right",
            page=self.combo_page.currentData() or "last",
            show_pan=self.chk_show_pan.isChecked(),
            show_date=self.chk_show_date.isChecked(),
            show_reason=self.chk_show_reason.isChecked(),
        )

        def _on_progress(p: BatchSignProgress):
            self.batch_progress.setValue(p.current_index)
            self.lbl_batch_status.setText(
                f"Signing {p.current_index}/{p.total_files}: {os.path.basename(p.file_path)}..."
            )
            # Update row in table
            row = p.current_index - 1
            if row < self.batch_table.rowCount():
                status_item = QTableWidgetItem("✓ Signed" if p.success else "❌ Error")
                if p.success:
                    status_item.setForeground(Qt.green)
                else:
                    status_item.setForeground(Qt.red)
                self.batch_table.setItem(row, 2, status_item)

        try:
            results = self.signer.sign_pdf_batch(
                input_files=self._batch_files,
                output_dir=out_dir,
                token_id=self._current_token_id or "SIMULATED",
                slot=self._current_slot,
                pin=pin,
                cert=cert,
                reason=self.combo_reason.currentText(),
                location=self.edit_loc.text(),
                visual_config=vis_cfg,
                progress_cb=_on_progress,
                is_simulated=self._is_simulated,
            )

            success_cnt = sum(1 for r in results if r.success)
            fail_cnt = len(results) - success_cnt

            self.lbl_batch_status.setText(
                f"Batch Complete: {success_cnt} signed successfully, {fail_cnt} failed."
            )
            self.lbl_batch_status.setProperty("class", "BadgeValid" if fail_cnt == 0 else "BadgeWarning")
            self.lbl_batch_status.setStyleSheet("")
            self.btn_open_batch_dir.setVisible(True)

            QMessageBox.information(
                self,
                "Batch Signing Complete",
                f"Batch processing finished!\n\n"
                f"• Total files: {len(results)}\n"
                f"• Successfully signed: {success_cnt}\n"
                f"• Failed: {fail_cnt}\n\n"
                f"Output Folder: {out_dir}",
            )
        except Exception as e:
            QMessageBox.critical(self, "Batch Error", f"Batch signing encountered an error:\n{e}")
        finally:
            self.btn_start_batch.setEnabled(True)

    def _open_batch_folder(self):
        out_dir = self.edit_batch_out_dir.text().strip()
        if out_dir and os.path.exists(out_dir):
            QDesktopServices.openUrl(QUrl.fromLocalFile(out_dir))
