"""
Dhanyah Crypto Utility - Dynamic PKCS#11 Middleware Discovery & Session Manager
Locates, validates and interfaces with PKCS#11 dynamic libraries for:
- HyperPKI / HYP 2003
- mToken CryptoID
- Watchdata ProxKey
- Precision InnaITKey
"""

import logging
import os
import platform
import struct
import sys
import winreg
from typing import Dict, List, Optional, Tuple, Any

from core.constants import (
    TOKEN_PROFILES,
    TOKEN_HYP2003,
    TOKEN_MTOKEN,
    TOKEN_PROXKEY,
    TOKEN_INNAIT,
    PKCS11_ERRORS,
)

logger = logging.getLogger("DhanyahCrypto.PKCS11")

IS_64BIT = struct.calcsize("P") * 8 == 64


class DriverStatus:
    """Represents the detection status and health of a vendor PKCS#11 driver."""

    def __init__(
        self,
        token_id: str,
        token_name: str,
        vendor: str,
        dll_path: Optional[str],
        is_installed: bool,
        is_loadable: bool = False,
        error_message: str = "",
        bitness: str = "64-bit" if IS_64BIT else "32-bit",
    ):
        self.token_id = token_id
        self.token_name = token_name
        self.vendor = vendor
        self.dll_path = dll_path
        self.is_installed = is_installed
        self.is_loadable = is_loadable
        self.error_message = error_message
        self.bitness = bitness

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "token_name": self.token_name,
            "vendor": self.vendor,
            "dll_path": self.dll_path,
            "is_installed": self.is_installed,
            "is_loadable": self.is_loadable,
            "error_message": self.error_message,
            "bitness": self.bitness,
        }

    def __repr__(self) -> str:
        status = "LOADABLE" if self.is_loadable else ("FOUND" if self.is_installed else "MISSING")
        return f"<DriverStatus {self.token_name} [{status}] -> {self.dll_path}>"


class PKCS11Manager:
    """
    Dynamic discovery, loading, and slot management for PKCS#11 drivers.
    """

    def __init__(self):
        self._loaded_libs: Dict[str, Any] = {}  # token_id -> PyKCS11Lib instance
        self._driver_statuses: Dict[str, DriverStatus] = {}
        self.refresh_drivers()

    def refresh_drivers(self) -> Dict[str, DriverStatus]:
        """Scan system and registry to discover all installed token drivers."""
        statuses: Dict[str, DriverStatus] = {}

        for token_id, profile in TOKEN_PROFILES.items():
            dll_path = self._locate_driver_for_token(token_id, profile)
            if dll_path and os.path.exists(dll_path):
                is_installed = True
                is_loadable, err = self._test_driver_loadable(dll_path)
            else:
                is_installed = False
                is_loadable = False
                err = "Driver DLL not found in system or vendor directories"

            status = DriverStatus(
                token_id=token_id,
                token_name=profile["name"],
                vendor=profile["vendor"],
                dll_path=dll_path if is_installed else None,
                is_installed=is_installed,
                is_loadable=is_loadable,
                error_message=err,
            )
            statuses[token_id] = status
            logger.info(f"Driver scan: {status}")

        self._driver_statuses = statuses
        return statuses

    def get_driver_status(self, token_id: str) -> Optional[DriverStatus]:
        """Get discovery status for a specific token ID."""
        return self._driver_statuses.get(token_id)

    def get_all_driver_statuses(self) -> List[DriverStatus]:
        """Get list of discovery statuses for all 4 tokens."""
        return list(self._driver_statuses.values())

    def _locate_driver_for_token(self, token_id: str, profile: Dict[str, Any]) -> Optional[str]:
        """Search Registry, System directories, and Program Files for token DLL."""
        candidates: List[str] = []

        # 0. Check application's bundled portable drivers first (Zero-Install support)
        search_roots = []
        if getattr(sys, "frozen", False):
            if hasattr(sys, "_MEIPASS"):
                search_roots.append(sys._MEIPASS)
            search_roots.append(os.path.dirname(sys.executable))
            search_roots.append(os.path.join(os.path.dirname(sys.executable), "_internal"))
        else:
            search_roots.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        for root in search_roots:
            hyp_cand = os.path.join(root, "drivers", "hyp2003", "HYP2003csp11IND.dll" if IS_64BIT else "HYP2003csp11IND.x86.dll")
            if not os.path.exists(hyp_cand):
                hyp_cand = os.path.join(root, "drivers", "hyp2003", "HYP2003csp11IND.dll")
            if not os.path.exists(hyp_cand):
                hyp_cand = os.path.join(root, "drivers", "hyp2003", "eps2003csp11v2.dll")

            bundled_map = {
                TOKEN_HYP2003: hyp_cand,
                TOKEN_MTOKEN: os.path.join(root, "drivers", "mtoken", "cryptoida_pkcs11.dll"),
                TOKEN_PROXKEY: os.path.join(root, "drivers", "proxkey", "WDPKCS.dll"),
                TOKEN_INNAIT: os.path.join(root, "drivers", "innait", "InnaITPKCS11Driver.dll"),
            }
            bundled_dll = bundled_map.get(token_id)
            if bundled_dll and os.path.exists(bundled_dll) and bundled_dll not in candidates:
                candidates.append(bundled_dll)

        # 1. Direct checks for known paths discovered on Indian Windows systems
        if token_id == TOKEN_HYP2003:
            candidates.extend([
                r"C:\Windows\System32\HYP2003csp11IND.dll",
                r"C:\Windows\System32\eps2003csp11v2.dll",
                r"C:\Windows\SysWOW64\HYP2003csp11IND.dll",
                r"C:\Windows\SysWOW64\eps2003csp11v2.dll",
                r"C:\Program Files (x86)\IDSign CA\IDSignTokensUtility\HS2003-pkcs11.dll",
                r"C:\Windows\System32\HYP2003csp11IND_s.dll",
                r"C:\Windows\System32\eps2003csp11v2_s.dll",
            ])
        elif token_id == TOKEN_MTOKEN:
            candidates.extend([
                r"C:\Windows\System32\cryptoida_pkcs11.dll",
                r"C:\Windows\System32\cryptoida_pkcs11_f3.dll",
                r"C:\Windows\SysWOW64\cryptoida_pkcs11.dll",
                r"C:\Program Files (x86)\CryptoID\cryptoida_pkcs11.dll",
                r"C:\Program Files (x86)\CryptoID\CryptoIDCertUtilityF3\cryptoida_pkcs11_f3.dll",
            ])
        elif token_id == TOKEN_PROXKEY:
            candidates.extend([
                r"C:\Windows\System32\Watchdata\PROXKey CSP India V3.0\WDPKCS.dll",
                r"C:\Windows\SysWOW64\Watchdata\PROXKey CSP India V3.0\WDPKCS.dll",
                r"C:\Program Files (x86)\Watchdata\WD PROXKey\SignatureP11.dll",
            ])
        elif token_id == TOKEN_INNAIT:
            candidates.extend([
                r"C:\Windows\System32\InnaITPKCS11Driver.dll",
                r"C:\Windows\SysWOW64\InnaITPKCS11Driver.dll",
                r"C:\Program Files (x86)\Precision Biometric\InnaIT\InnaITDSC\InnaIT_pkcs11.dll",
            ])

        # 2. Check Candidate DLL names for current architecture in search dirs
        dll_names = profile.get("dll_names_64" if IS_64BIT else "dll_names_32", [])
        search_dirs: List[str] = []
        if IS_64BIT:
            search_dirs.append(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32"))
            search_dirs.append(r"C:\Windows\System32")
        else:
            search_dirs.append(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "SysWOW64"))
            search_dirs.append(r"C:\Windows\SysWOW64")
            search_dirs.append(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32"))
        search_dirs.extend(profile.get("install_paths", []))

        for dll_name in dll_names:
            for sdir in search_dirs:
                candidate = os.path.normpath(os.path.join(sdir, dll_name))
                if candidate not in candidates:
                    candidates.append(candidate)

        # 3. Check Windows Registry CSP Image Path
        csp_names = profile.get("registry_csp", [])
        for csp_name in csp_names:
            reg_path = self._query_registry_csp(csp_name)
            if reg_path and reg_path not in candidates:
                candidates.append(reg_path)

        # Prioritize candidates: first existing candidate compatible with process bitness
        for cand in candidates:
            if cand and os.path.exists(cand) and self._is_dll_bitness_compatible(cand):
                return cand

        # Fallback to any existing candidate if none matched bitness
        for cand in candidates:
            if cand and os.path.exists(cand):
                return cand

        return None

    @staticmethod
    def _is_dll_bitness_compatible(dll_path: str) -> bool:
        """Check if DLL machine architecture matches current Python process bitness in <0.1ms."""
        try:
            with open(dll_path, "rb") as f:
                header = f.read(1024)
            if len(header) < 64:
                return False
            pe_offset = int.from_bytes(header[0x3C:0x40], "little")
            if len(header) < pe_offset + 6:
                return False
            machine = int.from_bytes(header[pe_offset + 4 : pe_offset + 6], "little")
            # 0x8664 = AMD64 (64-bit), 0x14C = I386 (32-bit)
            if IS_64BIT:
                return machine == 0x8664
            else:
                return machine == 0x14C
        except Exception:
            return True

    def _query_registry_csp(self, csp_name: str) -> Optional[str]:
        """Query registry for CSP Image Path."""
        reg_keys = [
            (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Microsoft\Cryptography\Defaults\Provider\{csp_name}"),
            (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider\{csp_name}"),
        ]
        for root, subkey in reg_keys:
            try:
                with winreg.OpenKey(root, subkey) as key:
                    image_path, _ = winreg.QueryValueEx(key, "Image Path")
                    if image_path:
                        # Expand %SystemRoot%
                        expanded = os.path.expandvars(image_path)
                        if os.path.exists(expanded):
                            return expanded
            except (FileNotFoundError, OSError, WindowsError):
                continue
        return None

    def _test_driver_loadable(self, dll_path: str) -> Tuple[bool, str]:
        """Test if the DLL is a valid, loadable PKCS#11 module without executing unmanaged vendor DllMain code during passive scans."""
        if not hasattr(self, "_loadable_cache"):
            self._loadable_cache = {}
        if dll_path in self._loadable_cache:
            return self._loadable_cache[dll_path]

        # 1. Fast bitness check first (<0.1ms)
        if not self._is_dll_bitness_compatible(dll_path):
            res = (False, "Architecture mismatch: DLL bitness does not match Python process.")
            self._loadable_cache[dll_path] = res
            return res

        # 2. Verify valid PE file and PKCS#11 C_GetFunctionList export signature without executing foreign vendor DllMain
        try:
            with open(dll_path, "rb") as f:
                content = f.read()

            # Verify PE MZ signature
            if len(content) < 64 or content[:2] != b"MZ":
                res = (False, "Invalid Windows executable: missing MZ signature.")
                self._loadable_cache[dll_path] = res
                return res

            if b"C_GetFunctionList" in content:
                res = (True, "PKCS#11 module verified and loadable.")
            else:
                res = (False, "DLL does not export standard PKCS#11 C_GetFunctionList symbol.")
            self._loadable_cache[dll_path] = res
            return res
        except Exception as e:
            res = (False, f"Error inspecting driver binary: {e}")
            self._loadable_cache[dll_path] = res
            return res

    def get_pkcs11_lib(self, token_id: str) -> Any:
        """Get or initialize PyKCS11 library instance for given token."""
        if token_id in self._loaded_libs:
            return self._loaded_libs[token_id]

        status = self.get_driver_status(token_id)
        if not status or not status.dll_path or not status.is_loadable:
            raise RuntimeError(
                f"Driver for token '{token_id}' is not loadable: {status.error_message if status else 'Not found'}"
            )

        if "innait" in status.dll_path.lower():
            dll_dir = os.path.dirname(os.path.abspath(status.dll_path))
            dsc_lib = os.path.join(dll_dir, "InnaITDSCLibrary.dll")
            if os.path.exists(dsc_lib):
                try:
                    import ctypes
                    ctypes.windll.kernel32.LoadLibraryExW(dsc_lib, 0, 8)
                except Exception:
                    pass

        import PyKCS11
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(status.dll_path)
        self._loaded_libs[token_id] = pkcs11
        return pkcs11

    def get_slots_with_token(self, token_id: str) -> List[int]:
        """Get list of slot numbers that currently have a token inserted."""
        try:
            lib = self.get_pkcs11_lib(token_id)
            slots = lib.getSlotList(tokenPresent=True)
            return list(slots)
        except Exception as e:
            logger.warning(f"Error querying slots for {token_id}: {e}")
            return []

    def get_token_info(self, token_id: str, slot: int) -> Dict[str, Any]:
        """Query CK_TOKEN_INFO structure for given slot."""
        lib = self.get_pkcs11_lib(token_id)
        info = lib.getTokenInfo(slot)
        return {
            "label": info.label.strip(),
            "manufacturer": info.manufacturerID.strip(),
            "model": info.model.strip(),
            "serial": info.serialNumber.strip(),
            "flags": info.flags,
            "ulMaxPinLen": info.ulMaxPinLen,
            "ulMinPinLen": info.ulMinPinLen,
            "hardwareVersion": f"{info.hardwareVersion.major}.{info.hardwareVersion.minor}",
            "firmwareVersion": f"{info.firmwareVersion.major}.{info.firmwareVersion.minor}",
        }

    def map_pkcs11_error(self, code: int) -> str:
        """Convert PKCS#11 error code into friendly human message."""
        if code in PKCS11_ERRORS:
            name, desc = PKCS11_ERRORS[code]
            return f"[{name}] {desc}"
        return f"[CKR_0x{code:08X}] Cryptoki hardware operation returned error code 0x{code:X}."
