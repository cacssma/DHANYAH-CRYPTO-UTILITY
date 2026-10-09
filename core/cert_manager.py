"""
Dhanyah Crypto Utility - X.509 Certificate Parser & Indian CCA Inspector
Extracts CKO_CERTIFICATE objects and parses Indian DSC metadata:
- Common Name (CN), Serial Number, Issuer (eMudhra, Capricorn, etc.)
- Validity, 30-day Expiry Alert Badge
- Certificate Class (Class 3 / Class 2 / DGFT / DocSigner)
- PAN Number, Organization, State, Country
"""

import datetime
import logging
from typing import Dict, List, Optional, Tuple, Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtensionOID

from core.constants import CCA_OIDS, INDIAN_CAS

logger = logging.getLogger("DhanyahCrypto.Cert")


class ParsedCertificate:
    """Encapsulates all extracted metadata and CCA India fields of a DSC."""

    def __init__(
        self,
        cert_der: bytes,
        label: str = "DSC Certificate",
        token_id: str = "UNKNOWN",
        ck_id: bytes = b"",
    ):
        self.cert_der = cert_der
        self.label = label
        self.token_id = token_id
        self.ck_id = ck_id

        # Parse X.509
        self.x509_obj = x509.load_der_x509_certificate(cert_der, default_backend())

        # Subject DN
        self.common_name = self._get_attr_str(self.x509_obj.subject, NameOID.COMMON_NAME) or label
        self.organization = self._get_attr_str(self.x509_obj.subject, NameOID.ORGANIZATION_NAME)
        self.org_unit = self._get_attr_str(self.x509_obj.subject, NameOID.ORGANIZATIONAL_UNIT_NAME)
        self.country = self._get_attr_str(self.x509_obj.subject, NameOID.COUNTRY_NAME) or "IN"
        self.state = self._get_attr_str(self.x509_obj.subject, NameOID.STATE_OR_PROVINCE_NAME)
        self.postal_code = self._get_attr_str(self.x509_obj.subject, NameOID.POSTAL_CODE)
        self.serial_number_attr = self._get_attr_str(self.x509_obj.subject, NameOID.SERIAL_NUMBER)

        # Indian CCA Specific Attribute: PAN / Unique ID (OID: 2.5.4.45)
        self.pan_number = self._extract_pan_number()

        # Issuer DN
        self.issuer_cn = self._get_attr_str(self.x509_obj.issuer, NameOID.COMMON_NAME) or "Unknown CA"
        self.issuer_o = self._get_attr_str(self.x509_obj.issuer, NameOID.ORGANIZATION_NAME) or self.issuer_cn

        # Certificate Serial Number
        self.serial_number_hex = f"{self.x509_obj.serial_number:X}"

        # Validity Dates (timezone-aware UTC)
        try:
            self.valid_from = self.x509_obj.not_valid_before_utc
            self.valid_to = self.x509_obj.not_valid_after_utc
        except AttributeError:
            self.valid_from = self.x509_obj.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            self.valid_to = self.x509_obj.not_valid_after.replace(tzinfo=datetime.timezone.utc)

        # Expiry Analysis & Warnings
        now = datetime.datetime.now(datetime.timezone.utc)
        self.is_expired = now > self.valid_to
        self.days_to_expiry = (self.valid_to - now).days
        self.is_expiring_soon = (0 <= self.days_to_expiry <= 30) and not self.is_expired

        if self.is_expired:
            self.expiry_status = "EXPIRED"
            self.expiry_status_text = f"Expired {abs(self.days_to_expiry)} days ago"
        elif self.is_expiring_soon:
            self.expiry_status = "EXPIRING_SOON"
            self.expiry_status_text = f"Expires in {self.days_to_expiry} days!"
        else:
            self.expiry_status = "VALID"
            self.expiry_status_text = f"Valid ({self.days_to_expiry} days remaining)"

        # Certificate Class (Class 3 / Class 2 / DGFT)
        self.cert_class = self._determine_cert_class()

        # Key Specs
        pub_key = self.x509_obj.public_key()
        self.key_size = getattr(pub_key, "key_size", 2048)
        self.key_algo = f"RSA {self.key_size}-bit"

        # Fingerprints
        self.fingerprint_sha256 = self.x509_obj.fingerprint(
            hashes.SHA256()
        ).hex().upper()
        self.fingerprint_sha1 = self.x509_obj.fingerprint(
            hashes.SHA1()
        ).hex().upper()

        # Key Usage
        self.key_usage_desc = self._get_key_usage_description()

    @property
    def cert_pem(self) -> str:
        """Returns PEM formatted certificate string."""
        return self.x509_obj.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def _get_attr_str(self, rdn, oid) -> Optional[str]:
        try:
            attrs = rdn.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else None
        except Exception:
            return None

    def _extract_pan_number(self) -> Optional[str]:
        """Extract PAN from OID 2.5.4.45 (Unique Identifier) or Subject attributes."""
        try:
            # Check uniqueIdentifier OID: 2.5.4.45
            for attr in self.x509_obj.subject:
                if attr.oid.dotted_string == "2.5.4.45":
                    val = str(attr.value).strip()
                    # Often prefixed or formatted in Indian DSCs
                    return val
                # Fallback to serialNumber attribute if length 10 alphanumeric (standard PAN format)
                if attr.oid == NameOID.SERIAL_NUMBER:
                    val = str(attr.value).strip()
                    if len(val) == 10 and val[:5].isalpha() and val[5:9].isdigit() and val[9].isalpha():
                        return val
        except Exception:
            pass
        return None

    def _determine_cert_class(self) -> str:
        """Determine Indian CCA Class (Class 3 / Class 2 / DGFT / Document Signer)."""
        combined = f"{self.common_name} {self.issuer_cn} {self.org_unit or ''} {self.organization or ''}".lower()

        # Inspect Certificate Policies extension for CCA OIDs
        try:
            policies_ext = self.x509_obj.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            for policy in policies_ext.value:
                oid_str = policy.policy_identifier.dotted_string
                if oid_str == "2.16.356.100.1.3":
                    return "Class 3"
                elif oid_str == "2.16.356.100.1.2":
                    return "Class 2"
                elif oid_str == "2.16.356.100.1.4":
                    return "DGFT"
                elif oid_str == "2.16.356.100.1.5":
                    return "Document Signer"
        except Exception:
            pass

        # Textual heuristics
        if "class 3" in combined:
            return "Class 3"
        elif "class 2" in combined:
            return "Class 2"
        elif "dgft" in combined:
            return "DGFT"
        elif "document signer" in combined:
            return "Document Signer"

        return "Class 3"  # Indian default standard for modern DSC

    def _get_key_usage_description(self) -> str:
        usages = []
        try:
            ku_ext = self.x509_obj.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            val = ku_ext.value
            if val.digital_signature:
                usages.append("Digital Signature")
            if val.content_commitment:
                usages.append("Non-Repudiation")
            if val.key_encipherment:
                usages.append("Key Encipherment")
            if val.data_encipherment:
                usages.append("Data Encipherment")
        except Exception:
            usages.append("Digital Signature")
        return ", ".join(usages) if usages else "Digital Signature"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "token_id": self.token_id,
            "common_name": self.common_name,
            "issuer_cn": self.issuer_cn,
            "issuer_o": self.issuer_o,
            "organization": self.organization,
            "org_unit": self.org_unit,
            "country": self.country,
            "state": self.state,
            "postal_code": self.postal_code,
            "pan_number": self.pan_number,
            "serial_number_hex": self.serial_number_hex,
            "valid_from": self.valid_from.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "valid_to": self.valid_to.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "days_to_expiry": self.days_to_expiry,
            "is_expiring_soon": self.is_expiring_soon,
            "is_expired": self.is_expired,
            "expiry_status": self.expiry_status,
            "expiry_status_text": self.expiry_status_text,
            "cert_class": self.cert_class,
            "key_algo": self.key_algo,
            "fingerprint_sha256": self.fingerprint_sha256,
            "fingerprint_sha1": self.fingerprint_sha1,
            "key_usage": self.key_usage_desc,
            "cert_pem": self.cert_pem,
        }


class CertManager:
    """Manages extraction and parsing of certificates from PKCS#11 sessions or simulation."""

    def __init__(self, pkcs11_mgr=None):
        self.pkcs11_mgr = pkcs11_mgr
        self._cached_certs: List[ParsedCertificate] = []

    def get_token_certificates(self, token_id: str, slot: Optional[int] = None) -> List[ParsedCertificate]:
        """
        Extract CKO_CERTIFICATE objects from PKCS#11 token session.
        Read-only; does NOT require or expose private keys.
        Auto-resolves slot with hardware token present.
        """
        if not self.pkcs11_mgr:
            return []

        import PyKCS11
        from PyKCS11 import CKO_CERTIFICATE, CKA_CLASS, CKA_VALUE, CKA_LABEL, CKA_ID

        certs: List[ParsedCertificate] = []
        try:
            lib = self.pkcs11_mgr.get_pkcs11_lib(token_id)

            # Auto-resolve active slot(s)
            slots_to_check = []
            if slot is not None:
                slots_to_check = [slot]
            else:
                if hasattr(self.pkcs11_mgr, "get_slots_with_token"):
                    active_slots = self.pkcs11_mgr.get_slots_with_token(token_id)
                    if active_slots:
                        slots_to_check = list(active_slots)

                if not slots_to_check:
                    try:
                        present_slots = lib.getSlotList(tokenPresent=True)
                        if present_slots:
                            slots_to_check = list(present_slots)
                        else:
                            all_slots = lib.getSlotList(tokenPresent=False)
                            slots_to_check = list(all_slots) if all_slots else [0]
                    except Exception:
                        slots_to_check = [0]

            for s in slots_to_check:
                try:
                    session = lib.openSession(s, PyKCS11.CKF_SERIAL_SESSION)
                except Exception as ex:
                    logger.debug(f"Could not open session on slot {s} of {token_id}: {ex}")
                    continue

                try:
                    # Query all certificate objects
                    objects = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])
                    for obj in objects:
                        try:
                            attrs = session.getAttributeValue(obj, [CKA_VALUE, CKA_LABEL, CKA_ID])
                            raw_val, raw_label, raw_id = attrs[0], attrs[1], attrs[2]

                            # CKA_VALUE -> bytes
                            if isinstance(raw_val, (tuple, list)):
                                val = bytes(raw_val)
                            elif isinstance(raw_val, str):
                                val = raw_val.encode("latin-1")
                            else:
                                val = bytes(raw_val) if raw_val else b""

                            # CKA_LABEL -> str
                            if isinstance(raw_label, str):
                                label = raw_label.strip()
                            elif isinstance(raw_label, (tuple, list)):
                                label = "".join(chr(c) for c in raw_label if 32 <= c <= 126).strip()
                            else:
                                label = str(raw_label).strip() if raw_label else "DSC Certificate"

                            # CKA_ID -> bytes
                            if isinstance(raw_id, (tuple, list)):
                                ck_id = bytes(raw_id)
                            elif isinstance(raw_id, str):
                                ck_id = raw_id.encode("latin-1")
                            else:
                                ck_id = bytes(raw_id) if raw_id else b""

                            if val:
                                parsed = ParsedCertificate(
                                    cert_der=val,
                                    label=label or "DSC Certificate",
                                    token_id=token_id,
                                    ck_id=ck_id,
                                )
                                # Avoid duplicates by fingerprint
                                if not any(c.fingerprint_sha256 == parsed.fingerprint_sha256 for c in certs):
                                    certs.append(parsed)
                        except Exception as e:
                            logger.warning(f"Error parsing cert object: {e}")
                finally:
                    session.closeSession()
        except Exception as e:
            logger.error(f"Failed to extract certificates from {token_id}: {e}")

        self._cached_certs = certs
        return certs

    @staticmethod
    def generate_simulated_dsc(
        cn: str = "RAMESH SHARMA",
        pan: str = "ABCDE1234F",
        issuer: str = "Capricorn CA 2022",
        org: str = "DHANYAH FINANCIAL SERVICES PVT LTD",
        days_valid: int = 365,
    ) -> ParsedCertificate:
        """
        Generates an authentic-looking Indian Class 3 DSC in-memory
        for simulation and demonstration when physical token is not present.
        """
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes

        # Generate RSA keypair
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        now = datetime.datetime.now(datetime.timezone.utc)
        if days_valid < 0:
            not_before = now + datetime.timedelta(days=days_valid - 365)
            valid_until = now + datetime.timedelta(days=days_valid)
        else:
            not_before = now
            valid_until = now + datetime.timedelta(days=days_valid)

        # Subject DN with CCA standard fields
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tamil Nadu"),
                x509.NameAttribute(NameOID.POSTAL_CODE, "600001"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authorized Signatory"),
                x509.NameAttribute(x509.ObjectIdentifier("2.5.4.45"), pan),
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ]
        )

        issuer_dn = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Capricorn Identity Services Pvt. Ltd."),
                x509.NameAttribute(NameOID.COMMON_NAME, issuer),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_dn)
            .public_key(priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(valid_until)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.CertificatePolicies(
                    [
                        x509.PolicyInformation(
                            policy_identifier=x509.ObjectIdentifier("2.16.356.100.1.3"),  # CCA Class 3
                            policy_qualifiers=None,
                        )
                    ]
                ),
                critical=False,
            )
            .sign(priv, hashes.SHA256(), default_backend())
        )

        from cryptography.hazmat.primitives.serialization import Encoding
        cert_der = cert.public_bytes(Encoding.DER)
        return ParsedCertificate(cert_der=cert_der, label=f"{cn} (Class 3 DSC)", token_id="SIMULATED")
