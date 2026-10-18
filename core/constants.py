"""
Dhanyah Crypto Utility - Hardware, PKCS#11 & PKI Constants
Specialized for Indian FIPS 140-2/3 Level 3 Crypto USB Tokens:
- HyperPKI / HYP 2003 FIPS L3
- mToken CryptoID
- Watchdata ProxKey
- Precision InnaITKey
"""

import sys
import subprocess
from typing import Dict, List, Any, Optional

# Application Version
APP_VERSION = "1.1.4"

# Loopback HTTP / WebSocket default configuration
DEFAULT_LOOPBACK_PORT = 18200
DEFAULT_LOOPBACK_HOST = "0.0.0.0"

# Token identifiers enum-like keys
TOKEN_HYP2003 = "HYP2003"
TOKEN_MTOKEN = "MTOKEN"
TOKEN_PROXKEY = "PROXKEY"
TOKEN_INNAIT = "INNAIT"
TOKEN_UNKNOWN = "UNKNOWN"

# Token Profiles and Hardware Metadata
TOKEN_PROFILES: Dict[str, Dict[str, Any]] = {
    TOKEN_HYP2003: {
        "id": TOKEN_HYP2003,
        "name": "HyperPKI / HYP 2003 FIPS L3",
        "vendor": "Feitian Technologies / HyperPKI",
        "description": "FIPS 140-2 Level 3 Cryptographic USB Token for DSC",
        "fips_level": "FIPS 140-2 Level 3",
        "default_pin_length": (4, 16),
        "default_user_pin": "12345678",
        # Smart Card ATR prefixes (hex uppercase without spaces)
        "atrs": [
            "3B9F958131FE9F006646530510113171DF0000860000B5",  # HYP2003 FIPS L3 active ATR
            "3B9F958131FE9F006646530500000071DF000086000000",  # HYP2003IND_33 (FIPS Level 3)
            "3B9F958131FE9F006646530500000071DF000006000000",  # HYP2003IND / HYP2003v2
            "3B9F958131FE9F0066465305",                        # HYP2003 prefix
            "3B9F958131FE9F006646530500000071DF",              # HYP2003 prefix
            "3B9F958131FE9F0065465305300671DF00000080",
            "3B9F958131FE9F0065465305300671DF00000081",
            "3B9F958131FE9F0065465305300671DF",
            "3B6F000080318065B085020120120F",
        ],
        "usb_ids": [
            ("096e", "0807"),  # Feitian ePass2003 / HYP2003
            ("096e", "0808"),
            ("096e", "0809"),
            ("096e", "080a"),
            ("096e", "0401"),
        ],
        "reader_name_keywords": ["hyper", "hyp", "epass2003", "feitian", "enterpke"],
        "registry_csp": [
            "HyperPKI HYP2003 CSP India v3.3",
            "HyperPKI HYP2003 CSP India v3.0",
            "EnterSafe ePass2003 CSP v1.0",
        ],
        # Driver filenames in order of preference (eps2003csp11v2 is the verified non-blocking 64-bit driver)
        "dll_names_64": [
            "eps2003csp11v2.dll",
            "HYP2003csp11IND.dll",
            "eps2003csp11v2_s.dll",
            "HYP2003csp11IND_s.dll",
            "ep11_nsp.dll",
            "hyp2003csp.dll",
            "HS2003-pkcs11.dll",
        ],
        "dll_names_32": [
            "HYP2003csp11IND.dll",
            "HYP2003csp11IND.x86.dll",
            "eps2003csp11v2.dll",
            "HYP2003csp11IND_s.dll",
            "eps2003csp11v2_s.dll",
            "ep11_nsp.dll",
            "hyp2003csp.dll",
            "HS2003-pkcs11.dll",
        ],
        "install_paths": [
            r"C:\Program Files (x86)\HyperPKI\HyperPKI_HYP2003",
            r"C:\Program Files\HyperPKI\HyperPKI_HYP2003",
            r"C:\Program Files (x86)\HyperPKI",
            r"C:\Program Files (x86)\IDSign CA\IDSignTokensUtility",
        ],
    },
    TOKEN_MTOKEN: {
        "id": TOKEN_MTOKEN,
        "name": "mToken CryptoID",
        "vendor": "Beijing Longmai Technology / CryptoID",
        "description": "FIPS 140-2 Level 3 Secure Smart Card Token",
        "fips_level": "FIPS 140-2 Level 3",
        "default_pin_length": (4, 16),
        "default_user_pin": "12345678",
        "atrs": [
            "3B9F118131FE9F006A6D546F6B656E2D5000058190006A",  # mToken Blue (mToken-P) full ATR
            "3B9F118131FE9F006A6D546F6B656E2D50",              # mToken Blue prefix
            "3B9F118131FE9F006A6D546F6B656E2D4500008190007A",  # mToken Purple (mToken-E / F3) full ATR
            "3B9F118131FE9F006A6D546F6B656E2D45",              # mToken Purple prefix
            "3B9F118131FE9F006A6D546F6B656E",                  # Generic mToken prefix
            "3B7D94000057445300000000000000000000",
            "3B7D9400005744530000",
            "3B7D940000574453",
            "3B7F96000080318065B0850300EF1200",
            "3BD5180081313A7D8073C8211030",
        ],
        "usb_ids": [
            ("4c4d", "8b15"),  # Longmai mToken CryptoID
            ("4c4d", "8b16"),
            ("4c4d", "8b17"),
            ("4c4d", "8b18"),
        ],
        "reader_name_keywords": ["mtoken", "cryptoid", "longmai", "k9"],
        "registry_csp": [
            "mToken CryptoID CSP",
            "mToken CryptoID CSP v2.0",
        ],
        "dll_names_64": [
            "cryptoida_pkcs11.dll",
            "cryptoida_pkcs11_f3.dll",
            "cryptoida_pkcs11_f2.dll",
            "mtoken_pkcs11.dll",
            "opensc_pkcs11.dll",
        ],
        "dll_names_32": [
            "cryptoida_pkcs11.dll",
            "cryptoida_pkcs11_f3.dll",
            "cryptoida_pkcs11_f2.dll",
            "mtoken_pkcs11.dll",
            "opensc_pkcs11.dll",
        ],
        "install_paths": [
            r"C:\Program Files (x86)\CryptoID",
            r"C:\Program Files\CryptoID",
            r"C:\Program Files (x86)\CryptoID\CryptoIDCertUtilityF3",
        ],
    },
    TOKEN_PROXKEY: {
        "id": TOKEN_PROXKEY,
        "name": "Watchdata ProxKey",
        "vendor": "Watchdata Technologies",
        "description": "FIPS 140-2/3 Level 3 Dual Interface Crypto Token",
        "fips_level": "FIPS 140-2 Level 3",
        "default_pin_length": (4, 16),
        "default_user_pin": "12345678",
        "atrs": [
            "3B6D000057443641018693000000000000",  # Standard ProxKey WD6A full ATR
            "3B6D000057443641",                      # Standard ProxKey WD6A prefix
            "3B6D00005744",                          # Watchdata WD prefix
            "3B6D",
            "3B6E000080318066B08412016E0183009000",
            "3B6E000080318066B08412016E",
            "3B6E000080318066",
            "3B6E",
            "3B7F1800000031C0739E010B",
            "3B169420020100000D0D",
        ],
        "usb_ids": [
            ("163c", "080a"),  # Watchdata PROXKey
            ("163c", "080b"),
            ("163c", "080c"),
            ("163c", "0810"),
            ("2ccf", "080a"),  # Common Indian CCID repackaging
        ],
        "reader_name_keywords": ["proxkey", "watchdata", "wdind", "wd", "prox", "wdprox"],
        "registry_csp": [
            "PROXKey CSP India V3.0",
            "PROXKey CSP India V2.0",
            "PROXKey CSP India V1.0",
            "Watchdata CSP v1.0",
        ],
        "dll_names_64": [
            r"Watchdata\PROXKey CSP India V3.0\WDPKCS.dll",
            r"Watchdata\PROXKey CSP India V2.0\WDPKCS.dll",
            "WDPKCS.dll",
            "SignatureP11.dll",
            "wdsafe3.dll",
            "TokenMgr.dll",
        ],
        "dll_names_32": [
            r"Watchdata\PROXKey CSP India V3.0\WDPKCS.dll",
            r"Watchdata\PROXKey CSP India V2.0\WDPKCS.dll",
            "WDPKCS.dll",
            "SignatureP11.dll",
            "wdsafe3.dll",
            "TokenMgr.dll",
        ],
        "install_paths": [
            r"C:\Program Files (x86)\Watchdata\WD PROXKey",
            r"C:\Program Files\Watchdata\WD PROXKey",
            r"C:\Windows\System32\Watchdata\PROXKey CSP India V3.0",
            r"C:\Windows\SysWOW64\Watchdata\PROXKey CSP India V3.0",
            r"C:\Windows\System32\Watchdata\PROXKey CSP India V2.0",
            r"C:\Windows\SysWOW64\Watchdata\PROXKey CSP India V2.0",
        ],
    },
    TOKEN_INNAIT: {
        "id": TOKEN_INNAIT,
        "name": "Precision InnaITKey",
        "vendor": "Precision Biometric India",
        "description": "FIPS 140-3 Level 3 Hardware Security Token",
        "fips_level": "FIPS 140-3 Level 3",
        "default_pin_length": (4, 16),
        "default_user_pin": "12345678",
        "atrs": [
            "3B8E8001504B035858585F4453435F4B45594C",          # Precision InnaITKey DSC KeyL ATR
            "3B8E8001",                                        # InnaITKey prefix
            "3B8880012000000001000000",
            "3B888001200000",
            "3B8F8001804F0CA000000306030001000000006A",
            "3B80800101",
        ],
        "usb_ids": [
            ("2ccf", "080a"),  # Precision InnaITKey / USB CCID
            ("2ccf", "080b"),
            ("2ccf", "0801"),
            ("2ccf", "0802"),
        ],
        "reader_name_keywords": ["innait", "precision", "innaitkey", "pk12", "pk31"],
        "registry_csp": [
            "InnaIT Cryptographic Provider",
            "InnaIT Cryptographic Provider CSP",
        ],
        "dll_names_64": [
            "InnaITPKCS11Driver.dll",
            "InnaITCSP.dll",
            "InnaITKey_p11.dll",
            "InnaIT_pkcs11.dll",
            "InnaITDSCLibrary.dll",
        ],
        "dll_names_32": [
            "InnaITPKCS11Driver.dll",
            "InnaITCSP.dll",
            "InnaITKey_p11.dll",
            "InnaIT_pkcs11.dll",
            "InnaITDSCLibrary.dll",
        ],
        "install_paths": [
            r"C:\Program Files (x86)\Precision Biometric\InnaIT\InnaITDSC",
            r"C:\Program Files\Precision Biometric\InnaIT\InnaITDSC",
            r"C:\Program Files (x86)\Precision Biometric",
        ],
    },
}

# Indian CCA (Controller of Certifying Authorities) Specific X.509 OIDs
CCA_OIDS = {
    # Subject Identification
    "2.5.4.45": "Unique Identifier (PAN / Aadhaar hash)",
    "2.5.4.4": "Surname",
    "2.5.4.42": "Given Name",
    "2.5.4.3": "Common Name (CN)",
    "2.5.4.10": "Organization (O)",
    "2.5.4.11": "Organizational Unit (OU)",
    "2.5.4.6": "Country (C)",
    "2.5.4.8": "State / Province (ST)",
    "2.5.4.17": "Postal Code",
    "2.5.4.5": "Device Serial Number",
    "2.5.4.20": "Telephone Number",
    "2.5.4.65": "Pseudonym",
    # CCA India Certificate Classes (OID: 2.16.356.100.1.*)
    "2.16.356.100.1.1": "Class 1 Certificate (Individual/Identity)",
    "2.16.356.100.1.2": "Class 2 Certificate (Standard Commercial)",
    "2.16.356.100.1.3": "Class 3 Certificate (High Assurance / Tenders / MCA / GST)",
    "2.16.356.100.1.4": "DGFT Certificate (Foreign Trade / IEC)",
    "2.16.356.100.1.5": "Document Signer Certificate (Automated System DSC)",
    # CCA Identity / Policy OIDs
    "2.16.356.100.1.10.1": "Individual Certificate",
    "2.16.356.100.1.10.2": "Organization Certificate",
    "2.16.356.100.1.10.3": "Foreign National Certificate",
}

# Recognized Indian Certifying Authorities (CAs)
INDIAN_CAS = [
    "eMudhra",
    "Capricorn",
    "IDSign",
    "VSign",
    "Pantasign",
    "ProdigiSign",
    "SafeScrypt",
    "nCode",
    "RajComp",
    "NIC",
    "Verasys",
    "XtraTrust",
    "CCA India",
    "IDRBT",
]

# PKCS#11 Standard Error Messages
PKCS11_ERRORS = {
    0x00000000: ("CKR_OK", "Success"),
    0x00000003: ("CKR_SLOT_ID_INVALID", "Specified Smart Card reader slot ID is invalid."),
    0x00000005: ("CKR_GENERAL_ERROR", "Token returned a general hardware error."),
    0x00000006: ("CKR_FUNCTION_FAILED", "Cryptographic function failed."),
    0x00000007: ("CKR_ARGUMENTS_BAD", "Bad arguments passed to PKCS#11 module."),
    0x00000030: ("CKR_DEVICE_ERROR", "Smart Card device communication error."),
    0x00000032: ("CKR_DEVICE_REMOVED", "Token was disconnected during operation."),
    0x000000A0: ("CKR_PIN_INCORRECT", "Incorrect Token PIN entered."),
    0x000000A1: ("CKR_PIN_INVALID", "Token PIN character format is invalid."),
    0x000000A2: ("CKR_PIN_LEN_RANGE", "Token PIN length is out of acceptable bounds (typically 4-16 chars)."),
    0x000000A3: ("CKR_PIN_EXPIRED", "Token PIN has expired. Please update PIN."),
    0x000000A4: ("CKR_PIN_LOCKED", "Token is BLOCKED/LOCKED due to too many incorrect attempts."),
    0x000000B0: ("CKR_SESSION_CLOSED", "PKCS#11 cryptographic session was closed."),
    0x000000B1: ("CKR_SESSION_COUNT", "Maximum number of simultaneous token sessions reached."),
    0x000000E0: ("CKR_TOKEN_NOT_PRESENT", "No crypto token inserted in this reader slot."),
    0x000000E1: ("CKR_TOKEN_NOT_RECOGNIZED", "The inserted smart card is not recognized by this driver."),
    0x00000100: ("CKR_USER_NOT_LOGGED_IN", "Token PIN has not been authenticated yet."),
    0x00000101: ("CKR_USER_ALREADY_LOGGED_IN", "User is already authenticated on this token session."),
    0x00000102: ("CKR_USER_ANOTHER_ALREADY_LOGGED_IN", "Another user type is already logged in."),
    0x00000150: ("CKR_OBJECT_HANDLE_INVALID", "Certificate or private key handle is no longer valid."),
    0x00000190: ("CKR_MECHANISM_INVALID", "Requested cryptographic mechanism is not supported by token hardware."),
    0x00000191: ("CKR_MECHANISM_PARAM_INVALID", "Invalid parameter for mechanism."),
}


def get_silent_subprocess_kwargs() -> Dict[str, Any]:
    """
    Returns creationflags and startupinfo to ensure NO black command prompt / conhost
    window ever flashes on screen during background checks on Windows.
    """
    kwargs: Dict[str, Any] = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
        kwargs["startupinfo"] = si
    return kwargs


def run_silent_cmd(cmd: List[str], timeout: float = 5.0) -> subprocess.CompletedProcess:
    """Safely and silently executes a system command with CREATE_NO_WINDOW and SW_HIDE."""
    kwargs = get_silent_subprocess_kwargs()
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        **kwargs,
    )

