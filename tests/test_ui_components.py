"""
Unit tests for UI components: App Icon, Cert Viewer Dialog, and PDF Signer dual-tab widget.
"""

import unittest
from PySide6.QtWidgets import QApplication

# Ensure QApplication exists for UI tests
_app = QApplication.instance() or QApplication(["test", "-platform", "offscreen"])

from ui.main_window import create_app_icon
from ui.cert_viewer_dialog import CertViewerDialog
from ui.widgets.pdf_signer_widget import PdfSignerWidget
from core.cert_manager import CertManager
from core.signer import TokenSigner


class TestUIComponents(unittest.TestCase):

    def test_app_icon_creation(self):
        icon = create_app_icon()
        self.assertFalse(icon.isNull(), "App icon should not be null")
        sizes = icon.availableSizes()
        self.assertTrue(len(sizes) > 0)

    def test_cert_viewer_dialog(self):
        sim_cert = CertManager.generate_simulated_dsc(
            cn="TEST VIKRAM VERMA",
            pan="ABCDE1234F",
            org="VIKRAM LOGISTICS",
        )
        dialog = CertViewerDialog(sim_cert)
        self.assertIn("VIKRAM VERMA", dialog.windowTitle())
        # Check PEM property on cert
        self.assertTrue(sim_cert.cert_pem.startswith("-----BEGIN CERTIFICATE-----"))
        dialog.close()

    def test_pdf_signer_widget_dual_tabs(self):
        signer = TokenSigner()
        widget = PdfSignerWidget(signer)
        # Check dual tab interface
        self.assertEqual(widget.tabs.count(), 2)
        self.assertIn("Single PDF Document Signer", widget.tabs.tabText(0))
        self.assertIn("Batch PDF Signer", widget.tabs.tabText(1))
        # Check batch controls exist
        self.assertIsNotNone(widget.batch_table)
        self.assertIsNotNone(widget.batch_progress)
        self.assertIsNotNone(widget.btn_start_batch)
        widget.close()


if __name__ == "__main__":
    unittest.main()
