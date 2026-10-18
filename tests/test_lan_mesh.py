"""
Unit tests for Local Network (LAN) DSC Mesh Subsystem.
Tests peer discovery data models, virtual token mounting, remote signing protocol,
and loopback server proxy routing.
"""

import base64
import json
import time
import unittest
import urllib.request
from unittest.mock import patch, MagicMock

from core.constants import DEFAULT_LOOPBACK_PORT, APP_VERSION, TOKEN_HYP2003
from core.lan_mesh import LanCertificateInfo, LanPeer, LanMeshManager, LAN_BEACON_MAGIC
from core.cert_manager import CertManager
from core.signer import TokenSigner
from core.token_detector import TokenDetector
from core.pkcs11_manager import PKCS11Manager
from core.pin_manager import PinManager
from server.loopback_server import LoopbackServer


class TestLanMesh(unittest.TestCase):

    def test_lan_certificate_info(self):
        """Test LanCertificateInfo serialization, deserialization, and duck-typing."""
        cert_info = LanCertificateInfo(
            common_name="AKASH BHAYANI",
            pan_number="ABCDE1234F",
            cert_class="Class 3",
            issuer="eMudhra Sub CA",
            valid_from="2024-01-01T00:00:00",
            valid_to="2026-01-01T00:00:00",
            serial_hex="1A2B3C",
        )
        d = cert_info.to_dict()
        self.assertEqual(d["common_name"], "AKASH BHAYANI")
        self.assertEqual(d["pan_number"], "ABCDE1234F")

        # Round-trip from dict
        reconstructed = LanCertificateInfo.from_dict(d)
        self.assertEqual(reconstructed.common_name, "AKASH BHAYANI")
        self.assertEqual(reconstructed.pan_number, "ABCDE1234F")

        # Convert to ParsedCertificate
        parsed = reconstructed.to_parsed_certificate()
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.common_name, "AKASH BHAYANI")
        self.assertEqual(parsed.pan_number, "ABCDE1234F")

    def test_lan_peer(self):
        """Test LanPeer state, online detection, and display naming."""
        cert_info = LanCertificateInfo(common_name="CA AKASH")
        peer = LanPeer(
            peer_id="WORKSTATION_1_192.168.1.105",
            hostname="WORKSTATION-1",
            ip="192.168.1.105",
            port=18200,
            has_token=True,
            token_name="HyperPKI HYP2003",
            token_id=TOKEN_HYP2003,
            certificates=[cert_info],
            last_seen=time.time(),
        )

        self.assertTrue(peer.is_online)
        self.assertIn("WORKSTATION-1", peer.display_name)
        self.assertIn("192.168.1.105", peer.display_name)

        # Expired peer
        peer.last_seen = time.time() - 30.0
        self.assertFalse(peer.is_online)

        # Dictionary serialization
        pd = peer.to_dict()
        self.assertEqual(pd["peer_id"], "WORKSTATION_1_192.168.1.105")
        self.assertEqual(len(pd["certificates"]), 1)

    def test_lan_mesh_manager_lifecycle(self):
        """Test LanMeshManager start, stop, peer tracking, mount, and unmount."""
        mgr = LanMeshManager(local_port=18200, broadcast_port=18209)
        mgr.set_sharing_enabled(True)
        self.assertTrue(mgr.is_sharing_enabled)
        mgr.set_require_prompt(True)
        self.assertTrue(mgr.require_prompt_before_sign)

        # Mock peers
        p1 = LanPeer(
            peer_id="PC_AUDIT_192.168.1.50",
            hostname="PC-AUDIT",
            ip="192.168.1.50",
            port=18200,
            has_token=True,
            token_name="Watchdata PROXKey",
            token_id="PROXKEY",
            certificates=[LanCertificateInfo(common_name="RAHUL SHARMA", pan_number="XYZAB5678C")],
            last_seen=time.time(),
        )

        with mgr._peers_lock:
            mgr._peers[p1.peer_id] = p1

        peers = mgr.get_peers()
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0].hostname, "PC-AUDIT")

        # Mount remote peer
        success = mgr.mount_remote_peer("PC_AUDIT_192.168.1.50", cert_index=0)
        self.assertTrue(success)
        self.assertIsNotNone(mgr.mounted_peer)
        self.assertEqual(mgr.mounted_peer.hostname, "PC-AUDIT")
        self.assertIsNotNone(mgr.mounted_cert)
        self.assertEqual(mgr.mounted_cert.common_name, "RAHUL SHARMA")

        # Unmount
        mgr.unmount_remote_peer()
        self.assertIsNone(mgr.mounted_peer)
        self.assertIsNone(mgr.mounted_cert)

    def test_signer_remote_lan_delegation(self):
        """Test TokenSigner routing to lan_mesh_mgr when token_id == REMOTE_LAN."""
        mgr = LanMeshManager(local_port=18200)
        p = LanPeer(
            peer_id="PC_TAX_192.168.1.60",
            hostname="PC-TAX",
            ip="192.168.1.60",
            port=18200,
            has_token=True,
            token_name="mToken CryptoID",
            token_id="MTOKEN",
            last_seen=time.time(),
        )
        with mgr._peers_lock:
            mgr._peers[p.peer_id] = p
        mgr.mounted_peer = p

        signer = TokenSigner()
        signer.lan_mesh_mgr = mgr

        # Mock sign_remote_hash return
        fake_sig = b"\x41\x42\x43\x44" * 64
        with patch.object(
            mgr,
            "sign_remote_hash",
            return_value={"success": True, "signature_hex": fake_sig.hex()},
        ) as mock_sign:
            sig = signer.sign_hash_hardware(
                token_id="REMOTE_LAN",
                slot=0,
                pin="12345678",
                data_hash=b"\x00" * 32,
            )
            self.assertEqual(sig, fake_sig)
            mock_sign.assert_called_once()

    def test_loopback_server_lan_routes(self):
        """Test LoopbackServer /api/lan/info and /api/lan/sign endpoints."""
        detector = TokenDetector()
        detector.set_simulation_mode(TOKEN_HYP2003)
        pkcs11_mgr = PKCS11Manager()
        cert_mgr = CertManager(pkcs11_mgr)
        pin_mgr = PinManager(pkcs11_mgr)
        signer = TokenSigner(pkcs11_mgr)

        port = 18208
        mesh_mgr = LanMeshManager(local_port=port)
        server = LoopbackServer(
            token_detector=detector,
            pkcs11_mgr=pkcs11_mgr,
            cert_manager=cert_mgr,
            pin_manager=pin_mgr,
            signer=signer,
            port=port,
            lan_mesh_mgr=mesh_mgr,
        )
        server.start()
        time.sleep(0.5)

        try:
            # 1. Test GET /api/lan/info
            url_info = f"http://127.0.0.1:{port}/api/lan/info"
            req = urllib.request.Request(url_info)
            with urllib.request.urlopen(req, timeout=3) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data["app"], "DhanyahCryptoUtility")
                self.assertTrue(data["has_token"])
                self.assertEqual(data["token_id"], TOKEN_HYP2003)
                self.assertTrue(len(data["certificates"]) >= 1)

            # 2. Test POST /api/lan/sign
            url_sign = f"http://127.0.0.1:{port}/api/lan/sign"
            payload = json.dumps({
                "pin": "12345678",
                "hash_hex": "AA" * 32,
                "slot": 0,
            }).encode("utf-8")
            req = urllib.request.Request(url_sign, data=payload, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                self.assertEqual(resp.status, 200)
                sdata = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(sdata["success"])
                self.assertIn("signature_hex", sdata)
                self.assertIn("signature_b64", sdata)

            # 3. Test virtual token mounting reflection on /status
            remote_peer = LanPeer(
                peer_id="REMOTE_HOST_192.168.1.99",
                hostname="REMOTE-HOST",
                ip="192.168.1.99",
                port=18200,
                has_token=True,
                token_name="Simulated Remote Token",
                token_id="MTOKEN",
                certificates=[LanCertificateInfo(common_name="REMOTE SIGNER", pan_number="DEFGH5678K")],
                last_seen=time.time(),
            )
            # Clear local physical token simulation to test remote mount
            detector.set_simulation_mode(None)
            mesh_mgr.mounted_peer = remote_peer

            url_status = f"http://127.0.0.1:{port}/status"
            req = urllib.request.Request(url_status)
            with urllib.request.urlopen(req, timeout=3) as resp:
                status_data = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(status_data["token_connected"])
                self.assertTrue(status_data["is_remote_lan_token"])
                self.assertIn("REMOTE-HOST", status_data["remote_peer"])
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
