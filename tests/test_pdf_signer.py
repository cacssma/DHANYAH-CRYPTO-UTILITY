"""
Unit test for PDF PAdES signing engine.
"""

import os
import tempfile
import unittest
from core.cert_manager import CertManager
from core.signer import TokenSigner


class TestPdfSigner(unittest.TestCase):

    def test_pdf_signing(self):
        # Create a minimal valid PDF 1.4 document
        minimal_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n"
            b"4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 12 Tf 72 712 Td (Hello Indian DSC) Tj ET\nendstream\nendobj\n"
            b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000206 00000 n \n"
            b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n300\n%%EOF\n"
        )

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as in_f:
            in_f.write(minimal_pdf)
            in_path = in_f.name

        out_path = in_path + ".signed.pdf"

        cert = CertManager.generate_simulated_dsc(
            cn="TEST SIGNER",
            pan="AAAPZ1111A",
        )

        signer = TokenSigner()
        result = signer.sign_pdf(
            input_pdf_path=in_path,
            output_pdf_path=out_path,
            token_id="SIMULATED",
            slot=0,
            pin="12345678",
            cert=cert,
            reason="Income Tax Return Verification",
            location="Chennai",
            is_simulated=True,
        )

        self.assertTrue(result.success)
        self.assertTrue(os.path.exists(out_path))

        with open(out_path, "rb") as f:
            signed_data = f.read()

        # Check signature dictionary elements in signed PDF
        self.assertIn(b"/Type /Sig", signed_data)
        self.assertIn(b"/Filter /Adobe.PPKLite", signed_data)
        self.assertIn(b"/SubFilter /adbe.pkcs7.detached", signed_data)
        self.assertIn(b"/ByteRange", signed_data)
        self.assertIn(b"TEST SIGNER", signed_data)
        self.assertIn(b"Income Tax Return Verification", signed_data)

        # Cleanup
        try:
            os.remove(in_path)
            os.remove(out_path)
        except Exception:
            pass

    def test_pdf_visual_signing(self):
        minimal_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n"
            b"4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 12 Tf 72 712 Td (Visual Stamp Test) Tj ET\nendstream\nendobj\n"
            b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000206 00000 n \n"
            b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n300\n%%EOF\n"
        )
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as in_f:
            in_f.write(minimal_pdf)
            in_path = in_f.name

        out_path = in_path + ".visual_signed.pdf"
        cert = CertManager.generate_simulated_dsc(cn="CA AKASH BHAYANI", pan="AAAPZ1234F")

        from core.signer import VisualSignatureConfig
        signer = TokenSigner()
        vis_cfg = VisualSignatureConfig(
            visible=True,
            position="bottom-right",
            show_pan=True,
            show_name=True,
            show_date=True,
        )
        result = signer.sign_pdf(
            input_pdf_path=in_path,
            output_pdf_path=out_path,
            token_id="SIMULATED",
            slot=0,
            pin="12345678",
            cert=cert,
            reason="Audited Balance Sheet",
            location="Mumbai",
            visual_config=vis_cfg,
            is_simulated=True,
        )

        self.assertTrue(result.success)
        self.assertTrue(os.path.exists(out_path))

        with open(out_path, "rb") as f:
            data = f.read()

        self.assertIn(b"/Type /Sig", data)
        self.assertIn(b"/Type /Annot", data)
        self.assertIn(b"/Subtype /Widget", data)
        self.assertIn(b"/Type /XObject", data)
        self.assertIn(b"/Subtype /Form", data)
        self.assertIn(b"Digitally Signed By:", data)
        self.assertIn(b"CA AKASH BHAYANI", data)
        self.assertIn(b"PAN: AAAPZ1234F", data)

        try:
            os.remove(in_path)
            os.remove(out_path)
        except Exception:
            pass

    def test_pdf_batch_signing(self):
        minimal_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n"
            b"4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 12 Tf 72 712 Td (Batch Document) Tj ET\nendstream\nendobj\n"
            b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000206 00000 n \n"
            b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n300\n%%EOF\n"
        )
        in_files = []
        for i in range(3):
            with tempfile.NamedTemporaryFile(suffix=f"_{i}.pdf", delete=False) as f:
                f.write(minimal_pdf)
                in_files.append(f.name)

        out_dir = tempfile.mkdtemp()
        cert = CertManager.generate_simulated_dsc(cn="BATCH SIGNER", pan="BBBPZ9999K")
        signer = TokenSigner()

        progress_events = []
        def _on_prog(p):
            progress_events.append(p)

        results = signer.sign_pdf_batch(
            input_files=in_files,
            output_dir=out_dir,
            token_id="SIMULATED",
            slot=0,
            pin="12345678",
            cert=cert,
            progress_cb=_on_prog,
            is_simulated=True,
        )

        self.assertEqual(len(results), 3)
        self.assertTrue(all(r.success for r in results))
        self.assertEqual(len(progress_events), 3)
        self.assertEqual(progress_events[-1].current_index, 3)

        # Cleanup
        import shutil
        for p in in_files:
            try:
                os.remove(p)
            except Exception:
                pass
        try:
            shutil.rmtree(out_dir, ignore_errors=True)
        except Exception:
            pass


if __name__ == "__main__":
    unittest.main()
