"""
Dhanyah Crypto Utility - Windows Smart Card Subsystem & MiniDriver Registrar
Enables zero-install plug-and-play support across Windows, Adobe Acrobat,
Chrome, Edge, and browser web portals (MCA, GST, Income Tax, EPFO).
"""

import ctypes
import logging
import os
import shutil
import subprocess
import sys
import winreg
from typing import Dict, Tuple, Any, Optional

logger = logging.getLogger("DhanyahCrypto.Registrar")

SMARTCARD_REG_ROOTS = [
    r"SOFTWARE\Microsoft\Cryptography\Calais\SmartCards",
    r"SOFTWARE\WOW6432Node\Microsoft\Cryptography\Calais\SmartCards",
]

CSP_REG_ROOTS = [
    r"SOFTWARE\Microsoft\Cryptography\Defaults\Provider",
    r"SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider",
]

CARD_DEFINITIONS = {
    "mtoken_blue": {
        "name": "Longmai mToken SmartCard",
        "label": "mToken Blue (CryptoID Classic)",
        "atr": bytes.fromhex("3b9f118131fe9f006a6d546f6b656e2d50000081900000"),
        "atr_mask": bytes.fromhex("ffffffffffffffffffffffffffffffffff0000ffffff00"),
        "crypto_provider": "Microsoft Base Smart Card Crypto Provider",
        "ksp": "Microsoft Smart Card Key Storage Provider",
        "minidriver_64": "mTokenMiniDrv.x64.dll",
        "minidriver_32": "mTokenMiniDrv.dll",
        "csp_name": "mToken CryptoID CSP",
        "csp_image": "basecsp.dll",
        "csp_image_64": "basecsp.dll",
        "csp_image_32": "basecsp.dll",
        "csp_type": 1,
    },
    "mtoken_purple": {
        "name": "Longmai mToken CryptoFIPS",
        "label": "mToken Purple (CryptoID FIPS F3)",
        "atr": bytes.fromhex("3b9f118131fe9f006a6d546f6b656e2d45000081900000"),
        "atr_mask": bytes.fromhex("ffffffffffffffffffffffffffffffffff0000ffffff00"),
        "crypto_provider": "Microsoft Base Smart Card Crypto Provider",
        "ksp": "Microsoft Smart Card Key Storage Provider",
        "minidriver_64": "mTokenMiniDrvF3.x64.dll",
        "minidriver_32": "mTokenMiniDrvF3.dll",
        "csp_name": "mToken CryptoID CSP",
        "csp_image": "basecsp.dll",
        "csp_image_64": "basecsp.dll",
        "csp_image_32": "basecsp.dll",
        "csp_type": 1,
    },
    "hyp2003_v33": {
        "name": "HYP2003IND_33",
        "label": "HyperPKI HYP 2003 (FIPS Level 3 v3.3)",
        "atr": bytes.fromhex("3b9f958131fe9f006646530500000071df000086000000"),
        "atr_mask": bytes.fromhex("ffffffffffffffffffffffff000000ffffffffffffff00"),
        "crypto_provider": "HyperPKI HYP2003 CSP India v3.3",
        "ksp": "Microsoft Smart Card Key Storage Provider",
        "csp_name": "HyperPKI HYP2003 CSP India v3.3",
        "csp_image": r"C:\Windows\system32\HYP2003csp11IND_s.dll",
        "csp_image_64": r"C:\Windows\System32\HYP2003csp11IND_s.dll",
        "csp_image_32": r"C:\Windows\SysWOW64\HYP2003csp11IND_s.dll",
        "csp_type": 1,
        "csp_sig_64": bytes.fromhex(
            "c7fb3de5eb42b9070e36bd0ff58deaaac3b17a8f72bfe032add566136280b5c931e7df471f773f3824ecc436942d0c749f44"
            "f674db0503ace83009eceded524d2f03e5d32c71d4de2fffae50e7e95fc43785204a18d10688f676f0a4b357224b5bfd73c2"
            "3e37511064c51ff731ad8dc4ff5845567ec13ef33f864855b3a5e41a0000000000000000"
        ),
        "csp_sig_32": bytes.fromhex(
            "661ffec8524565568b3aa1d7c494e366c0217c935f092f8f2daec2f7de27b553382188fe6742f2739ea02db1f8878f7b0667"
            "fdfff5d42ae98d46d056ba49b6d035ea766a171681b12b424ae91809799d897e3cc445d4d93adb3f2e0a30fdc330b2d3a245"
            "e2e86edf252cbde61a46b4240b680309ddae65bc80d184dc641550130000000000000000"
        ),
    },
    "hyp2003_ind": {
        "name": "HYP2003IND",
        "label": "HyperPKI HYP 2003 (India Standard)",
        "atr": bytes.fromhex("3b9f958131fe9f006646530500000071df000006000000"),
        "atr_mask": bytes.fromhex("ffffffffffffffffffffffff000000ffffffffffffff00"),
        "crypto_provider": "HyperPKI HYP2003 CSP India v3.3",
        "ksp": "Microsoft Smart Card Key Storage Provider",
        "csp_name": "HyperPKI HYP2003 CSP India v3.3",
        "csp_image": r"C:\Windows\system32\HYP2003csp11IND_s.dll",
        "csp_image_64": r"C:\Windows\System32\HYP2003csp11IND_s.dll",
        "csp_image_32": r"C:\Windows\SysWOW64\HYP2003csp11IND_s.dll",
        "csp_type": 1,
        "csp_sig_64": bytes.fromhex(
            "c7fb3de5eb42b9070e36bd0ff58deaaac3b17a8f72bfe032add566136280b5c931e7df471f773f3824ecc436942d0c749f44"
            "f674db0503ace83009eceded524d2f03e5d32c71d4de2fffae50e7e95fc43785204a18d10688f676f0a4b357224b5bfd73c2"
            "3e37511064c51ff731ad8dc4ff5845567ec13ef33f864855b3a5e41a0000000000000000"
        ),
        "csp_sig_32": bytes.fromhex(
            "661ffec8524565568b3aa1d7c494e366c0217c935f092f8f2daec2f7de27b553382188fe6742f2739ea02db1f8878f7b0667"
            "fdfff5d42ae98d46d056ba49b6d035ea766a171681b12b424ae91809799d897e3cc445d4d93adb3f2e0a30fdc330b2d3a245"
            "e2e86edf252cbde61a46b4240b680309ddae65bc80d184dc641550130000000000000000"
        ),
    },
    "hyp2003": {
        "name": "HYP2003v2",
        "label": "HyperPKI HYP 2003 (Classic v3.0)",
        "atr": bytes.fromhex("3b9f958131fe9f006646530500000071df000006000000"),
        "atr_mask": bytes.fromhex("ffffffffffffffffffffffff000000ffffffffffffff00"),
        "crypto_provider": "HyperPKI HYP2003 CSP India v3.0",
        "ksp": "Microsoft Smart Card Key Storage Provider",
        "csp_name": "HyperPKI HYP2003 CSP India v3.0",
        "csp_image": r"C:\Windows\system32\HYP2003csp11IND_s.dll",
        "csp_image_64": r"C:\Windows\System32\HYP2003csp11IND_s.dll",
        "csp_image_32": r"C:\Windows\SysWOW64\HYP2003csp11IND_s.dll",
        "csp_type": 1,
        "csp_sig_64": bytes.fromhex(
            "c7fb3de5eb42b9070e36bd0ff58deaaac3b17a8f72bfe032add566136280b5c931e7df471f773f3824ecc436942d0c749f44"
            "f674db0503ace83009eceded524d2f03e5d32c71d4de2fffae50e7e95fc43785204a18d10688f676f0a4b357224b5bfd73c2"
            "3e37511064c51ff731ad8dc4ff5845567ec13ef33f864855b3a5e41a0000000000000000"
        ),
        "csp_sig_32": bytes.fromhex(
            "661ffec8524565568b3aa1d7c494e366c0217c935f092f8f2daec2f7de27b553382188fe6742f2739ea02db1f8878f7b0667"
            "fdfff5d42ae98d46d056ba49b6d035ea766a171681b12b424ae91809799d897e3cc445d4d93adb3f2e0a30fdc330b2d3a245"
            "e2e86edf252cbde61a46b4240b680309ddae65bc80d184dc641550130000000000000000"
        ),
    },
    "proxkey": {
        "name": "WD_Ultimate Key Minidriver",
        "atr": bytes.fromhex("3b6d000057443641018693000000000000"),
        "atr_mask": bytes.fromhex("ffffffffffffffffffffff000000000000"),
        "crypto_provider": "PROXKey CSP India V3.0",
        "ksp": "Microsoft Smart Card Key Storage Provider",
        "csp_name": "PROXKey CSP India V3.0",
        "csp_image": r"C:\Windows\system32\Watchdata\PROXKey CSP India V3.0\wdsafe3.dll",
        "csp_image_64": r"C:\Windows\System32\Watchdata\PROXKey CSP India V3.0\wdsafe3.dll",
        "csp_image_32": r"C:\Windows\SysWOW64\Watchdata\PROXKey CSP India V3.0\wdsafe3.dll",
        "csp_type": 1,
    },
    "proxkey_v2": {
        "name": "WD_Ultimate Key Minidriver V2",
        "atr": bytes.fromhex("3b6d000057443641018693000000000000"),
        "atr_mask": bytes.fromhex("ffffffffffffffffffffff000000000000"),
        "crypto_provider": "PROXKey CSP India V2.0",
        "ksp": "Microsoft Smart Card Key Storage Provider",
        "csp_name": "PROXKey CSP India V2.0",
        "csp_image": r"C:\Windows\system32\Watchdata\PROXKey CSP India V3.0\wdsafe3.dll",
        "csp_image_64": r"C:\Windows\System32\Watchdata\PROXKey CSP India V3.0\wdsafe3.dll",
        "csp_image_32": r"C:\Windows\SysWOW64\Watchdata\PROXKey CSP India V3.0\wdsafe3.dll",
        "csp_type": 1,
    },
    "proxkey_v1": {
        "name": "WD_Ultimate Key Minidriver V1",
        "atr": bytes.fromhex("3b6d000057443641018693000000000000"),
        "atr_mask": bytes.fromhex("ffffffffffffffffffffff000000000000"),
        "crypto_provider": "PROXKey CSP India V1.0",
        "ksp": "Microsoft Smart Card Key Storage Provider",
        "csp_name": "PROXKey CSP India V1.0",
        "csp_image": r"C:\Windows\system32\Watchdata\PROXKey CSP India V3.0\wdsafe3.dll",
        "csp_image_64": r"C:\Windows\System32\Watchdata\PROXKey CSP India V3.0\wdsafe3.dll",
        "csp_image_32": r"C:\Windows\SysWOW64\Watchdata\PROXKey CSP India V3.0\wdsafe3.dll",
        "csp_type": 1,
    },
    "innait": {
        "name": "InnaIT SmartCard",
        "atr": bytes.fromhex("3b8e8001504b035858585f4453435f4b45594c"),
        "atr_mask": bytes.fromhex("ffffffffffffffffffffffffffffffffff"),
        "crypto_provider": "InnaIT Cryptographic Provider CSP",
        "ksp": "Microsoft Smart Card Key Storage Provider",
        "csp_name": "InnaIT Cryptographic Provider CSP",
        "csp_image": r"C:\Windows\system32\InnaITCSP.dll",
        "csp_image_64": r"C:\Windows\System32\InnaITCSP.dll",
        "csp_image_32": r"C:\Windows\SysWOW64\InnaITPKCS11Driver.dll",
        "csp_type": 1,
    },
}


class SmartCardRegistrar:
    """Manages Windows Smart Card subsystem registration and certificate propagation."""

    @staticmethod
    def is_admin() -> bool:
        """Check if current process has Administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    @staticmethod
    def elevate_process() -> bool:
        """Relaunches the current process with Windows Administrator (UAC) privileges."""
        try:
            if sys.platform != "win32":
                return False
            if SmartCardRegistrar.is_admin():
                return True

            if getattr(sys, "frozen", False):
                executable = sys.executable
                params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            else:
                executable = sys.executable
                script = os.path.abspath(sys.argv[0])
                args = [f'"{script}"'] + [f'"{arg}"' for arg in sys.argv[1:]]
                params = " ".join(args)

            ret = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                executable,
                params,
                None,
                1,  # SW_SHOWNORMAL
            )
            return ret > 32
        except Exception as e:
            logger.error(f"UAC elevation failed: {e}")
            return False

    @staticmethod
    def check_subsystem_health() -> Dict[str, Any]:
        """Inspects registry and service state for all 4 vendor tokens."""
        status = {
            "is_admin": SmartCardRegistrar.is_admin(),
            "cards": {},
            "services": {
                "CertPropSvc": False,
                "SCardSvr": False,
            },
        }

        # Check Calais SmartCard definitions
        for token_key, cfg in CARD_DEFINITIONS.items():
            card_name = cfg["name"]
            is_reg_64 = False
            is_reg_32 = False

            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    f"SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards\\{card_name}",
                ):
                    is_reg_64 = True
            except OSError:
                pass

            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    f"SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Calais\\SmartCards\\{card_name}",
                ):
                    is_reg_32 = True
            except OSError:
                pass

            status["cards"][token_key] = {
                "name": card_name,
                "registered": is_reg_64 or is_reg_32,
                "registered_64": is_reg_64,
                "registered_32": is_reg_32,
            }

        # Check Windows Services
        for svc_name in ["CertPropSvc", "SCardSvr"]:
            try:
                res = subprocess.run(
                    ["sc", "query", svc_name],
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                if "RUNNING" in res.stdout:
                    status["services"][svc_name] = True
            except Exception:
                pass

        return status

    @staticmethod
    def pulse_windows_certificates() -> bool:
        """
        Triggers Windows Certificate Propagation Service to refresh all connected
        smart card tokens and publish their certificates into CurrentUser\My.
        """
        try:
            logger.info("Pulsing Windows Certificate Propagation Service (certutil -user -pulse)...")
            res = subprocess.run(
                ["certutil", "-user", "-pulse"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return res.returncode == 0
        except Exception as e:
            logger.warning(f"Failed to pulse certificates via certutil: {e}")
            return False

    @staticmethod
    def register_windows_subsystem(drivers_source_dir: Optional[str] = None) -> Tuple[bool, str]:
        """
        Registers all 4 Smart Card MiniDrivers, Calais SmartCard registry entries,
        and CSP providers into Windows so Adobe Acrobat and Browsers recognize tokens.
        """
        if not SmartCardRegistrar.is_admin():
            return False, "Administrator privileges are required to configure Windows Smart Card drivers."

        if not drivers_source_dir:
            if getattr(sys, "frozen", False):
                base_dir = os.path.dirname(sys.executable)
                candidates = [
                    os.path.join(base_dir, "drivers"),
                    os.path.join(base_dir, "_internal", "drivers"),
                ]
            else:
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                candidates = [os.path.join(base_dir, "drivers")]

            for c in candidates:
                if os.path.isdir(c):
                    drivers_source_dir = c
                    break

        if not drivers_source_dir or not os.path.isdir(drivers_source_dir):
            return False, f"Bundled drivers directory not found: {drivers_source_dir}"

        system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
        syswow64 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "SysWOW64")
        has_wow64 = os.path.isdir(syswow64)

        def _safe_copy(src: str, dst: str):
            """Safely copy driver binary without failing if destination file is locked/in-use."""
            try:
                if not os.path.exists(dst):
                    shutil.copy2(src, dst)
                else:
                    try:
                        shutil.copy2(src, dst)
                    except PermissionError:
                        logger.debug(f"Destination {dst} in use; skipping overwrite.")
            except Exception as ex:
                logger.debug(f"Error copying {src} -> {dst}: {ex}")

        try:
            # 1. Copy MiniDriver & CSP DLLs
            logger.info(f"Deploying MiniDriver and CSP binaries from {drivers_source_dir}...")

            # mToken MiniDrivers (Both Blue & Purple F3)
            mtoken_src = os.path.join(drivers_source_dir, "mtoken")
            if os.path.isdir(mtoken_src):
                # Blue Classic
                m_x64 = os.path.join(mtoken_src, "mTokenMiniDrv.x64.dll")
                m_32 = os.path.join(mtoken_src, "mTokenMiniDrv.dll")
                p11_blue = os.path.join(mtoken_src, "cryptoida_pkcs11.dll")

                if os.path.isfile(m_x64):
                    _safe_copy(m_x64, os.path.join(system32, "mTokenMiniDrv.x64.dll"))
                if os.path.isfile(m_32):
                    _safe_copy(m_32, os.path.join(system32, "mTokenMiniDrv.dll"))
                    if has_wow64:
                        _safe_copy(m_32, os.path.join(syswow64, "mTokenMiniDrv.dll"))
                if os.path.isfile(p11_blue):
                    _safe_copy(p11_blue, os.path.join(system32, "cryptoida_pkcs11.dll"))
                    if has_wow64:
                        _safe_copy(p11_blue, os.path.join(syswow64, "cryptoida_pkcs11.dll"))

                # Purple FIPS F3
                mf3_x64 = os.path.join(mtoken_src, "mTokenMiniDrvF3.x64.dll")
                mf3_32 = os.path.join(mtoken_src, "mTokenMiniDrvF3.dll")
                p11_purple = os.path.join(mtoken_src, "cryptoida_pkcs11_f3.dll")

                if os.path.isfile(mf3_x64):
                    _safe_copy(mf3_x64, os.path.join(system32, "mTokenMiniDrvF3.x64.dll"))
                if os.path.isfile(mf3_32):
                    _safe_copy(mf3_32, os.path.join(system32, "mTokenMiniDrvF3.dll"))
                    if has_wow64:
                        _safe_copy(mf3_32, os.path.join(syswow64, "mTokenMiniDrvF3.dll"))
                if os.path.isfile(p11_purple):
                    _safe_copy(p11_purple, os.path.join(system32, "cryptoida_pkcs11_f3.dll"))
                    if has_wow64:
                        _safe_copy(p11_purple, os.path.join(syswow64, "cryptoida_pkcs11_f3.dll"))

            # HyperPKI CSP & PKCS#11 files (Both FIPS Level 3 and Classic)
            hyp_src = os.path.join(drivers_source_dir, "hyp2003")
            if os.path.isdir(hyp_src):
                # 1. New FIPS Level 3 binaries
                h_ind_64 = os.path.join(hyp_src, "HYP2003csp11IND.dll")
                h_ind_32 = os.path.join(hyp_src, "HYP2003csp11IND.x86.dll")
                h_inds_64 = os.path.join(hyp_src, "HYP2003csp11IND_s.dll")
                h_inds_32 = os.path.join(hyp_src, "HYP2003csp11IND_s.x86.dll")
                h_sig = os.path.join(hyp_src, "HYP2003csp11IND.sig")

                if os.path.isfile(h_ind_64):
                    _safe_copy(h_ind_64, os.path.join(system32, "HYP2003csp11IND.dll"))
                if os.path.isfile(h_ind_32):
                    if has_wow64:
                        _safe_copy(h_ind_32, os.path.join(syswow64, "HYP2003csp11IND.dll"))
                    else:
                        _safe_copy(h_ind_32, os.path.join(system32, "HYP2003csp11IND.dll"))
                elif os.path.isfile(h_ind_64) and not has_wow64:
                    _safe_copy(h_ind_64, os.path.join(system32, "HYP2003csp11IND.dll"))

                if os.path.isfile(h_inds_64):
                    _safe_copy(h_inds_64, os.path.join(system32, "HYP2003csp11IND_s.dll"))
                if os.path.isfile(h_inds_32):
                    if has_wow64:
                        _safe_copy(h_inds_32, os.path.join(syswow64, "HYP2003csp11IND_s.dll"))
                        _safe_copy(h_inds_32, os.path.join(syswow64, "eps2003csp11v2_s.dll"))
                    else:
                        _safe_copy(h_inds_32, os.path.join(system32, "HYP2003csp11IND_s.dll"))

                if os.path.isfile(h_ind_64):
                    _safe_copy(h_ind_64, os.path.join(system32, "HYP2003csp11IND.dll"))
                if os.path.isfile(h_ind_32):
                    if has_wow64:
                        _safe_copy(h_ind_32, os.path.join(syswow64, "HYP2003csp11IND.dll"))
                        _safe_copy(h_ind_32, os.path.join(syswow64, "eps2003csp11v2.dll"))
                    else:
                        _safe_copy(h_ind_32, os.path.join(system32, "HYP2003csp11IND.dll"))
                elif os.path.isfile(h_ind_64) and not has_wow64:
                    _safe_copy(h_ind_64, os.path.join(system32, "HYP2003csp11IND.dll"))

                if os.path.isfile(h_sig):
                    _safe_copy(h_sig, os.path.join(system32, "HYP2003csp11IND.sig"))
                    _safe_copy(h_sig, os.path.join(system32, "eps2003csp11v2.sig"))
                    if has_wow64:
                        _safe_copy(h_sig, os.path.join(syswow64, "HYP2003csp11IND.sig"))
                        _safe_copy(h_sig, os.path.join(syswow64, "eps2003csp11v2.sig"))

                # 2. Classic HYP2003 binaries
                for f in ["eps2003csp11v2_s.dll", "eps2003csp11v2.sig", "eps2003csp11v2.dll"]:
                    fp = os.path.join(hyp_src, f)
                    if os.path.isfile(fp):
                        _safe_copy(fp, os.path.join(system32, f))

            # ProxKey files
            prox_src = os.path.join(drivers_source_dir, "proxkey")
            if os.path.isdir(prox_src):
                prox_dest = os.path.join(system32, "Watchdata", "PROXKey CSP India V3.0")
                os.makedirs(prox_dest, exist_ok=True)
                for f in os.listdir(prox_src):
                    fp = os.path.join(prox_src, f)
                    if os.path.isfile(fp):
                        _safe_copy(fp, os.path.join(prox_dest, f))
                # Direct WDPKCS.dll in System32 for 64-bit apps
                if os.path.isfile(os.path.join(prox_src, "WDPKCS.dll")):
                    _safe_copy(os.path.join(prox_src, "WDPKCS.dll"), os.path.join(system32, "WDPKCS.dll"))

                if has_wow64:
                    prox_dest_32 = os.path.join(syswow64, "Watchdata", "PROXKey CSP India V3.0")
                    os.makedirs(prox_dest_32, exist_ok=True)
                    prox_src_32 = os.path.join(prox_src, "x86")
                    src_dir_32 = prox_src_32 if os.path.isdir(prox_src_32) else prox_src
                    for f in os.listdir(src_dir_32):
                        fp = os.path.join(src_dir_32, f)
                        if os.path.isfile(fp):
                            _safe_copy(fp, os.path.join(prox_dest_32, f))
                    # Direct 32-bit WDPKCS.dll in SysWOW64 for 32-bit emBridge and emSigner
                    if os.path.isfile(os.path.join(src_dir_32, "WDPKCS.dll")):
                        _safe_copy(os.path.join(src_dir_32, "WDPKCS.dll"), os.path.join(syswow64, "WDPKCS.dll"))

            # InnaIT files (64-bit only)
            innait_src = os.path.join(drivers_source_dir, "innait")
            if os.path.isdir(innait_src):
                for f in os.listdir(innait_src):
                    fp = os.path.join(innait_src, f)
                    if os.path.isfile(fp):
                        _safe_copy(fp, os.path.join(system32, f))

            # 2. Register Calais SmartCards in Registry
            for root_path in SMARTCARD_REG_ROOTS:
                for token_key, cfg in CARD_DEFINITIONS.items():
                    if token_key == "innait" and "WOW6432Node" in root_path:
                        continue  # Avoid 64-bit InnaIT crashing 32-bit WOW64 processes
                    card_name = cfg["name"]
                    key_path = f"{root_path}\\{card_name}"
                    try:
                        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
                            winreg.SetValueEx(k, "ATR", 0, winreg.REG_BINARY, cfg["atr"])
                            winreg.SetValueEx(k, "ATRMask", 0, winreg.REG_BINARY, cfg["atr_mask"])
                            winreg.SetValueEx(k, "Crypto Provider", 0, winreg.REG_SZ, cfg["crypto_provider"])
                            if "ksp" in cfg:
                                winreg.SetValueEx(k, "Smart Card Key Storage Provider", 0, winreg.REG_SZ, cfg["ksp"])
                            if "minidriver_64" in cfg:
                                mini_dll = cfg["minidriver_32"] if "WOW6432Node" in root_path else cfg["minidriver_64"]
                                winreg.SetValueEx(k, "80000001", 0, winreg.REG_SZ, mini_dll)
                    except Exception as e:
                        logger.warning(f"Error registering Calais SmartCard key {key_path}: {e}")

            # 3. Register CSP Providers
            for root_path in CSP_REG_ROOTS:
                is_wow = "WOW6432Node" in root_path
                for token_key, cfg in CARD_DEFINITIONS.items():
                    if token_key == "innait" and is_wow:
                        continue  # Avoid 64-bit InnaIT crashing 32-bit WOW64 processes
                    if "csp_name" in cfg:
                        csp_name = cfg["csp_name"]
                        key_path = f"{root_path}\\{csp_name}"
                        img_path = cfg.get("csp_image_32" if is_wow else "csp_image_64", cfg["csp_image"])
                        try:
                            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
                                winreg.SetValueEx(k, "Image Path", 0, winreg.REG_SZ, img_path)
                                winreg.SetValueEx(k, "Type", 0, winreg.REG_DWORD, cfg.get("csp_type", 1))
                                sig_bytes = cfg.get("csp_sig_32" if is_wow else "csp_sig_64")
                                if sig_bytes:
                                    winreg.SetValueEx(k, "Signature", 0, winreg.REG_BINARY, sig_bytes)
                                else:
                                    winreg.SetValueEx(k, "SigInFile", 0, winreg.REG_DWORD, 0)
                        except Exception as e:
                            logger.warning(f"Error registering CSP provider key {key_path}: {e}")

            # 4. Start / Enable Services
            for svc in ["SCardSvr", "CertPropSvc"]:
                try:
                    subprocess.run(["sc", "config", svc, "start=", "auto"], capture_output=True, timeout=2)
                    subprocess.run(["sc", "start", svc], capture_output=True, timeout=2)
                except Exception:
                    pass

            # 5. Pulse Certificate Propagation
            SmartCardRegistrar.pulse_windows_certificates()

            logger.info("Successfully registered Windows Smart Card subsystem for all 4 tokens.")
            return True, "Windows Smart Card subsystem and MiniDrivers registered successfully for all 4 tokens."

        except Exception as e:
            logger.exception("Failed to register Windows Smart Card subsystem")
            return False, f"Registration error: {e}"

    @staticmethod
    def sync_token_certificates_to_store(token_id: str, certs: list) -> Tuple[int, str]:
        """
        Injects token certificates into Windows Personal store (CurrentUser\\My)
        and explicitly binds CERT_KEY_PROV_INFO_PROP_ID so Adobe Acrobat, Chrome,
        Edge, and Windows Certificate Manager display the private key badge.
        """
        import ctypes
        from ctypes import wintypes

        if not certs:
            return 0, "No certificates provided to synchronize."

        # Map token_id to appropriate CSP provider
        tid_lower = (token_id or "").lower()
        if "hyp" in tid_lower or "2003" in tid_lower:
            csp_name = "HyperPKI HYP2003 CSP India v3.3"
        elif "mtoken" in tid_lower or "longmai" in tid_lower:
            csp_name = "mToken CryptoID CSP"
        elif "prox" in tid_lower or "watchdata" in tid_lower:
            csp_name = "PROXKey CSP India V3.0"
        elif "innait" in tid_lower:
            csp_name = "InnaIT Cryptographic Provider CSP"
        else:
            csp_name = "Microsoft Base Smart Card Crypto Provider"

        class CRYPT_KEY_PROV_INFO(ctypes.Structure):
            _fields_ = [
                ("pwszContainerName", wintypes.LPWSTR),
                ("pwszProvName", wintypes.LPWSTR),
                ("dwProvType", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("cProvParam", wintypes.DWORD),
                ("rgProvParam", ctypes.c_void_p),
                ("dwKeySpec", wintypes.DWORD),
            ]

        try:
            crypt32 = ctypes.windll.crypt32

            # Setup prototypes
            crypt32.CertOpenStore.argtypes = [
                ctypes.c_void_p, wintypes.DWORD, wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p
            ]
            crypt32.CertOpenStore.restype = wintypes.HANDLE

            crypt32.CertCreateCertificateContext.argtypes = [
                wintypes.DWORD, ctypes.c_char_p, wintypes.DWORD
            ]
            crypt32.CertCreateCertificateContext.restype = ctypes.c_void_p

            crypt32.CertSetCertificateContextProperty.argtypes = [
                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p
            ]
            crypt32.CertSetCertificateContextProperty.restype = wintypes.BOOL

            crypt32.CertAddCertificateContextToStore.argtypes = [
                wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p
            ]
            crypt32.CertAddCertificateContextToStore.restype = wintypes.BOOL

            crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
            crypt32.CertFreeCertificateContext.restype = wintypes.BOOL

            crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            crypt32.CertCloseStore.restype = wintypes.BOOL

            CERT_STORE_PROV_SYSTEM_W = 10
            CERT_SYSTEM_STORE_CURRENT_USER = 1 << 16
            CERT_STORE_ADD_REPLACE_EXISTING = 3
            CERT_KEY_PROV_INFO_PROP_ID = 2
            X509_ASN_ENCODING = 0x00000001
            PKCS_7_ASN_ENCODING = 0x00010000

            hStore = crypt32.CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                0,
                None,
                CERT_SYSTEM_STORE_CURRENT_USER,
                ctypes.c_wchar_p("MY"),
            )
            if not hStore:
                return 0, "Failed to open CurrentUser\\My certificate store."

            synced_count = 0
            try:
                for cert in certs:
                    der = getattr(cert, "cert_der", None)
                    if not der:
                        continue

                    container_name = getattr(cert, "common_name", None) or getattr(cert, "label", "DSC Certificate")

                    pContext = crypt32.CertCreateCertificateContext(
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        der,
                        len(der),
                    )
                    if not pContext:
                        continue

                    try:
                        prov_info = CRYPT_KEY_PROV_INFO()
                        prov_info.pwszContainerName = container_name
                        prov_info.pwszProvName = csp_name
                        prov_info.dwProvType = 1  # PROV_RSA_FULL
                        prov_info.dwFlags = 0
                        prov_info.cProvParam = 0
                        prov_info.rgProvParam = None
                        prov_info.dwKeySpec = 2  # AT_SIGNATURE

                        crypt32.CertSetCertificateContextProperty(
                            pContext,
                            CERT_KEY_PROV_INFO_PROP_ID,
                            0,
                            ctypes.byref(prov_info),
                        )

                        if crypt32.CertAddCertificateContextToStore(
                            hStore,
                            pContext,
                            CERT_STORE_ADD_REPLACE_EXISTING,
                            None,
                        ):
                            synced_count += 1
                    finally:
                        crypt32.CertFreeCertificateContext(pContext)
            finally:
                crypt32.CertCloseStore(hStore, 0)

            SmartCardRegistrar.pulse_windows_certificates()

            logger.info(f"Synchronized and key-linked {synced_count} certificates into Windows Personal Store.")
            return synced_count, f"Successfully synchronized and key-linked {synced_count} certificates into Windows Store."

        except Exception as e:
            logger.exception("Failed to sync certificates to Windows Store")
            return 0, f"Sync error: {e}"
