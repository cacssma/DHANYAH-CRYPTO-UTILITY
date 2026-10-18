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
    def test_theme_system_and_helpers(self):
        from ui.styles import get_theme_qss, get_log_console_style, get_status_pill_style, DARK_THEME_QSS, LIGHT_THEME_QSS
        from ui.widgets.token_banner import TokenBannerWidget
        from ui.widgets.server_widget import ServerWidget
        from server.loopback_server import LoopbackServer

        # Validate stylesheets are populated and contain key semantic classes
        dark_qss = get_theme_qss(is_dark_mode=True)
        light_qss = get_theme_qss(is_dark_mode=False)

        self.assertIn("HeaderTitle", dark_qss)
        self.assertIn("HeaderTitle", light_qss)
        self.assertIn("#f8fafc", light_qss) # Light background
        self.assertIn("#0f172a", dark_qss) # Dark background

        # Validate console & pill styles
        dark_console = get_log_console_style(True)
        light_console = get_log_console_style(False)
        self.assertIn("#0b1120", dark_console)
        self.assertIn("#ffffff", light_console)

        dark_pill = get_status_pill_style("active", is_dark_mode=True)
        light_pill = get_status_pill_style("active", is_dark_mode=False)
        self.assertIn("#16a34a", dark_pill)
        self.assertIn("#dcfce7", light_pill)

        # Test widget theme application
        banner = TokenBannerWidget()
        banner.apply_theme(False)
        banner.apply_theme(True)
        banner.close()

        server = LoopbackServer(None, None, None, None, None)
        server_widget = ServerWidget(server)
        server_widget.apply_theme(False)
        server_widget.apply_theme(True)
        server_widget.close()

    def test_lan_mesh_widget(self):
        from core.lan_mesh import LanMeshManager, LanPeer, LanCertificateInfo
        from ui.widgets.lan_mesh_widget import LanMeshWidget

        mesh_mgr = LanMeshManager(local_port=18200)
        widget = LanMeshWidget(mesh_mgr)
        self.assertIsNotNone(widget.chk_share)
        self.assertIsNotNone(widget.chk_prompt)
        self.assertFalse(widget.mount_banner.isVisible())

        # Render mock peer
        peer = LanPeer(
            peer_id="TEST_PEER_1",
            hostname="TEST-PEER",
            ip="192.168.1.55",
            has_token=True,
            token_name="HyperPKI HYP2003",
            token_id="HYP2003",
            certificates=[LanCertificateInfo(common_name="CA AKASH TEST", pan_number="ABCDE1234F")],
        )
        widget._render_peer_cards([peer])
        self.assertEqual(widget.peer_cards_container.count(), 1)
        widget.close()


if __name__ == "__main__":
    unittest.main()
