"""
Unit tests for X.509 Certificate Parser, CCA India OIDs, and Expiry Warnings.
"""

import datetime
import unittest
from core.cert_manager import CertManager, ParsedCertificate


class TestCertParser(unittest.TestCase):

    def test_simulated_dsc_metadata(self):
        cert = CertManager.generate_simulated_dsc(
            cn="SUNIL KUMAR AGARWAL",
            pan="AAAPA1234K",
            issuer="eMudhra Sub CA for Class 3 Individual 2022",
            org="AGARWAL ENTERPRISES",
            days_valid=365,
        )

        self.assertEqual(cert.common_name, "SUNIL KUMAR AGARWAL")
        self.assertEqual(cert.pan_number, "AAAPA1234K")
        self.assertEqual(cert.organization, "AGARWAL ENTERPRISES")
        self.assertEqual(cert.cert_class, "Class 3")
        self.assertEqual(cert.expiry_status, "VALID")
        self.assertFalse(cert.is_expiring_soon)
        self.assertFalse(cert.is_expired)
        self.assertIn("RSA 2048", cert.key_algo)
        self.assertTrue(len(cert.fingerprint_sha256) > 0)

    def test_pem_export_and_dict(self):
        cert = CertManager.generate_simulated_dsc(
            cn="TEST USER",
            pan="ABCDE1234F",
        )
        pem = cert.cert_pem
        self.assertTrue(pem.startswith("-----BEGIN CERTIFICATE-----"))
        self.assertTrue(pem.strip().endswith("-----END CERTIFICATE-----"))

        d = cert.to_dict()
        self.assertEqual(d["common_name"], "TEST USER")
        self.assertIn("cert_pem", d)
        self.assertEqual(d["cert_pem"], pem)

    def test_expiring_soon_threshold_30_days(self):
        # 15 days validity remaining
        cert_soon = CertManager.generate_simulated_dsc(
            cn="PRIYA SHARMA",
            pan="ABCDE5678G",
            days_valid=15,
        )
        self.assertTrue(cert_soon.is_expiring_soon)
        self.assertEqual(cert_soon.expiry_status, "EXPIRING_SOON")
        self.assertIn("Expires in", cert_soon.expiry_status_text)

        # Expired certificate
        cert_expired = CertManager.generate_simulated_dsc(
            cn="RAJESH PATEL",
            pan="XYZPA9999Z",
            days_valid=-5,
        )
        self.assertTrue(cert_expired.is_expired)
        self.assertEqual(cert_expired.expiry_status, "EXPIRED")
        self.assertIn("Expired", cert_expired.expiry_status_text)


if __name__ == "__main__":
    unittest.main()
