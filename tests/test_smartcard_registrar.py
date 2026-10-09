"""
Unit tests for Windows Smart Card & MiniDriver Registrar.
"""

import unittest
from core.smartcard_registrar import SmartCardRegistrar, CARD_DEFINITIONS


class TestSmartCardRegistrar(unittest.TestCase):

    def test_definitions_completeness(self):
        for expected in ["hyp2003", "hyp2003_v33", "mtoken_blue", "mtoken_purple", "proxkey", "innait"]:
            self.assertIn(expected, CARD_DEFINITIONS)
            cfg = CARD_DEFINITIONS[expected]
            self.assertIn("name", cfg)
            self.assertIn("atr", cfg)
            self.assertIn("atr_mask", cfg)
            self.assertIn("crypto_provider", cfg)
            self.assertTrue(len(cfg["atr"]) > 0)
            self.assertTrue(len(cfg["atr_mask"]) > 0)

    def test_health_check(self):
        health = SmartCardRegistrar.check_subsystem_health()
        self.assertIn("cards", health)
        self.assertIn("services", health)
        self.assertIn("is_admin", health)
        self.assertIn("mtoken_blue", health["cards"])
        self.assertIn("mtoken_purple", health["cards"])
        self.assertIn("hyp2003_v33", health["cards"])
        self.assertIn("proxkey", health["cards"])
        self.assertIn("innait", health["cards"])

    def test_architecture_paths(self):
        # Verify 32-bit and 64-bit image paths exist
        for key in ["hyp2003", "hyp2003_v33", "mtoken_blue", "mtoken_purple", "proxkey", "innait"]:
            cfg = CARD_DEFINITIONS[key]
            self.assertIn("csp_image_64", cfg)
            self.assertIn("csp_image_32", cfg)
            if key in ["hyp2003", "hyp2003_v33"]:
                self.assertIn("System32", cfg["csp_image_64"])
                self.assertIn("SysWOW64", cfg["csp_image_32"])
            elif key == "proxkey":
                self.assertIn("System32", cfg["csp_image_64"])
                self.assertIn("SysWOW64", cfg["csp_image_32"])

    def test_sync_token_certificates_to_store(self):
        from core.cert_manager import CertManager
        # Empty list handling
        count, msg = SmartCardRegistrar.sync_token_certificates_to_store("hyp2003_v33", [])
        self.assertEqual(count, 0)

        # Simulated cert sync (should succeed and return 1)
        sim_cert = CertManager.generate_simulated_dsc()
        count, msg = SmartCardRegistrar.sync_token_certificates_to_store("hyp2003_v33", [sim_cert])
        self.assertEqual(count, 1)
        self.assertIn("Successfully synchronized", msg)

        # Clean up synced simulated cert
        import subprocess
        subprocess.run(["certutil", "-user", "-delstore", "My", sim_cert.fingerprint_sha1], capture_output=True)

    def test_is_admin_and_elevation_interface(self):
        is_adm = SmartCardRegistrar.is_admin()
        self.assertIsInstance(is_adm, bool)
        self.assertTrue(callable(SmartCardRegistrar.elevate_process))


if __name__ == "__main__":
    unittest.main()
