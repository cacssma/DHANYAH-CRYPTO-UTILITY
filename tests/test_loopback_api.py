"""
Unit tests for Local Loopback HTTP REST Gateway (Port 18200).
"""

import json
import time
import unittest
import urllib.request
from core.token_detector import TokenDetector
from core.pkcs11_manager import PKCS11Manager
from core.cert_manager import CertManager
from core.pin_manager import PinManager
from core.signer import TokenSigner
from core.constants import TOKEN_HYP2003
from server.loopback_server import LoopbackServer


class TestLoopbackServer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.detector = TokenDetector()
        cls.pkcs11_mgr = PKCS11Manager()
        cls.cert_mgr = CertManager(cls.pkcs11_mgr)
        cls.pin_mgr = PinManager(cls.pkcs11_mgr)
        cls.signer = TokenSigner(cls.pkcs11_mgr)

        # Test on port 18201 to avoid potential conflicts
        cls.server = LoopbackServer(
            token_detector=cls.detector,
            pkcs11_mgr=cls.pkcs11_mgr,
            cert_manager=cls.cert_mgr,
            pin_manager=cls.pin_mgr,
            signer=cls.signer,
            port=18201,
        )
        cls.server.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_status_endpoint(self):
        url = "http://127.0.0.1:18201/status"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "online")
            self.assertEqual(data["port"], 18201)
            self.assertIn("drivers", data)
            self.assertTrue(len(data["drivers"]) >= 4)
            self.assertIn("port_protocols", data)
            self.assertIn("https_enabled", data)

    def test_cors_preflight(self):
        url = "http://127.0.0.1:18201/status"
        req = urllib.request.Request(url, method="OPTIONS")
        with urllib.request.urlopen(req, timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("Access-Control-Allow-Origin"), "*")

    def test_ssl_cert_generation(self):
        from server.loopback_server import ensure_localhost_ssl_cert
        import os
        crt, key = ensure_localhost_ssl_cert()
        self.assertTrue(os.path.exists(crt))
        self.assertTrue(os.path.exists(key))

    def test_sign_hash_flow_with_simulation(self):
        # Enable simulation token
        self.detector.set_simulation_mode(TOKEN_HYP2003)

        # Test certificates endpoint
        url_certs = "http://127.0.0.1:18201/certificates"
        with urllib.request.urlopen(url_certs, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(len(data["certificates"]) > 0)
            cert = data["certificates"][0]
            self.assertEqual(cert["cert_class"], "Class 3")

        # Test /verify/pin
        url_pin = "http://127.0.0.1:18201/verify/pin"
        pin_payload = json.dumps({"pin": "12345678"}).encode("utf-8")
        req_pin = urllib.request.Request(url_pin, data=pin_payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req_pin, timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            res = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(res["success"])

        # Test /sign/hash
        url_sign = "http://127.0.0.1:18201/sign/hash"
        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # SHA-256 of empty str
        sign_payload = json.dumps({"pin": "12345678", "hash_hex": test_hash}).encode("utf-8")
        req_sign = urllib.request.Request(url_sign, data=sign_payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req_sign, timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            res = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(res["success"])
            self.assertIn("signature_hex", res)
            self.assertTrue(len(res["signature_hex"]) > 0)

        # Clear simulation
        self.detector.set_simulation_mode(None)


if __name__ == "__main__":
    unittest.main()
