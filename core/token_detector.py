"""
Dhanyah Crypto Utility - Hardware Token & Smart Card Detector
Monitors PC/SC Readers, ATR Signatures, and USB Hotplug Events.
"""

import logging
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple, Any

from core.constants import (
    TOKEN_PROFILES,
    TOKEN_HYP2003,
    TOKEN_MTOKEN,
    TOKEN_PROXKEY,
    TOKEN_INNAIT,
    TOKEN_UNKNOWN,
)

logger = logging.getLogger("DhanyahCrypto.Detector")


class DetectedToken:
    """Represents a detected cryptographic hardware token."""

    def __init__(
        self,
        token_id: str,
        name: str,
        vendor: str,
        reader_name: str,
        atr: str,
        fips_level: str = "FIPS 140-2 Level 3",
        serial_number: Optional[str] = None,
        is_simulated: bool = False,
    ):
        self.token_id = token_id
        self.name = name
        self.vendor = vendor
        self.reader_name = reader_name
        self.atr = atr.upper().replace(" ", "")
        self.fips_level = fips_level
        self.serial_number = serial_number or "N/A"
        self.is_simulated = is_simulated
        self.connected_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "name": self.name,
            "vendor": self.vendor,
            "reader_name": self.reader_name,
            "atr": self.atr,
            "fips_level": self.fips_level,
            "serial_number": self.serial_number,
            "is_simulated": self.is_simulated,
            "connected_at": self.connected_at,
        }

    def __repr__(self) -> str:
        return f"<DetectedToken {self.name} on '{self.reader_name}' (ATR: {self.atr[:16]}...)>"


def identify_token_by_atr(atr_hex: str) -> Optional[Dict[str, Any]]:
    """Match ATR string to known Indian FIPS Level 3 tokens."""
    if not atr_hex:
        return None
    clean_atr = atr_hex.upper().replace(" ", "").replace(":", "")

    for token_key, profile in TOKEN_PROFILES.items():
        for known_atr in profile.get("atrs", []):
            clean_known = known_atr.upper().replace(" ", "").replace(":", "")
            if clean_atr.startswith(clean_known) or clean_known.startswith(clean_atr):
                res_profile = dict(profile)
                if token_key == TOKEN_MTOKEN:
                    if "6A6D546F6B656E2D50" in clean_atr:  # jmToken-P (Blue)
                        res_profile["name"] = "mToken CryptoID (Blue)"
                        res_profile["model"] = "mToken Blue"
                    elif "6A6D546F6B656E2D45" in clean_atr:  # jmToken-E (Purple)
                        res_profile["name"] = "mToken CryptoID (Purple / F3)"
                        res_profile["model"] = "mToken Purple"
                elif token_key == TOKEN_HYP2003:
                    if "000086000000" in clean_atr:
                        res_profile["name"] = "HyperPKI HYP 2003 (FIPS Level 3 v3.3)"
                        res_profile["model"] = "HYP 2003 FIPS L3"
                    elif "000006000000" in clean_atr or "66465305" in clean_atr:
                        res_profile["name"] = "HyperPKI HYP 2003 (Standard v3.0)"
                        res_profile["model"] = "HYP 2003 Standard"
                elif token_key == TOKEN_PROXKEY:
                    res_profile["name"] = "Watchdata ProxKey"
                    res_profile["model"] = "ProxKey WD6A / USB CCID"
                return res_profile

    return None


def identify_token_by_reader_name(reader_name: str) -> Optional[Dict[str, Any]]:
    """Match Smart Card reader name to known vendor keywords."""
    if not reader_name:
        return None
    lower_reader = reader_name.lower()

    for token_key, profile in TOKEN_PROFILES.items():
        for kw in profile.get("reader_name_keywords", []):
            if kw.lower() in lower_reader:
                return profile

    return None


class TokenDetector:
    """
    PC/SC Smart Card Hotplug Monitor.
    Runs a non-blocking background thread that polls winscard / pyscard.
    """

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks_insert: List[Callable[[DetectedToken], None]] = []
        self._callbacks_remove: List[Callable[[str], None]] = []
        self._current_tokens: Dict[str, DetectedToken] = {}  # reader_name -> DetectedToken
        self._simulated_token: Optional[DetectedToken] = None
        self._pkcs11_mgr: Any = None
        self._lock = threading.RLock()

    def set_pkcs11_manager(self, pkcs11_mgr: Any):
        """Register PKCS11Manager as secondary detection engine."""
        self._pkcs11_mgr = pkcs11_mgr

    def register_insertion_callback(self, cb: Callable[[DetectedToken], None]):
        """Register callback for token insertion event."""
        self._callbacks_insert.append(cb)

    # Alias for flexibility
    register_insert_callback = register_insertion_callback

    def register_removal_callback(self, cb: Callable[[str], None]):
        """Register callback for token removal event."""
        self._callbacks_remove.append(cb)

    # Alias for flexibility
    register_remove_callback = register_removal_callback

    def start(self):
        """Start background polling thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="TokenDetectorThread")
        self._thread.start()
        logger.info("Hardware Token Detector started.")

    def stop(self):
        """Stop background polling thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("Hardware Token Detector stopped.")

    def get_connected_tokens(self) -> List[DetectedToken]:
        """Return list of currently active tokens (physical or simulated)."""
        with self._lock:
            tokens = list(self._current_tokens.values())
            if self._simulated_token and not tokens:
                tokens.append(self._simulated_token)
            return tokens

    def get_primary_token(self) -> Optional[DetectedToken]:
        """Return primary active token, or None if no token is plugged in."""
        tokens = self.get_connected_tokens()
        return tokens[0] if tokens else None

    def set_simulation_mode(self, token_id: Optional[str] = None):
        """
        Enable/Disable simulated token for testing when hardware USB token is not present.
        token_id can be HYP2003, MTOKEN, PROXKEY, INNAIT, or None to clear.
        """
        with self._lock:
            if not token_id:
                old = self._simulated_token
                self._simulated_token = None
                if old:
                    for cb in self._callbacks_remove:
                        try:
                            cb(old.reader_name)
                        except Exception as e:
                            logger.error(f"Error in removal callback: {e}")
                return

            profile = TOKEN_PROFILES.get(token_id)
            if not profile:
                raise ValueError(f"Unknown token profile ID: {token_id}")

            mock_atr = profile["atrs"][0] if profile.get("atrs") else "3B9F958131FE9F0065465305300671DF00000080"
            mock_reader = f"Simulated {profile['name']} Reader 0"
            token = DetectedToken(
                token_id=profile["id"],
                name=profile["name"],
                vendor=profile["vendor"],
                reader_name=mock_reader,
                atr=mock_atr,
                fips_level=profile["fips_level"],
                serial_number="DH-SIM-2026-FIPS3",
                is_simulated=True,
            )
            self._simulated_token = token
            logger.info(f"Simulation mode enabled: {token}")

        for cb in self._callbacks_insert:
            try:
                cb(token)
            except Exception as e:
                logger.error(f"Error in insertion callback: {e}")

    def _monitor_loop(self):
        """Background loop reading PC/SC smartcard status."""
        while self._running:
            try:
                self._poll_pcsc()
            except Exception as e:
                logger.debug(f"PC/SC Poll notice: {e}")
            time.sleep(1.2)

    def _poll_pcsc(self):
        """Poll smart card readers via pyscard or ctypes fallback."""
        detected_this_cycle: Dict[str, DetectedToken] = {}

        try:
            from smartcard.System import readers
            from smartcard.util import toHexString

            available_readers = readers()
            for r in available_readers:
                reader_name = str(r)
                try:
                    conn = r.createConnection()
                    conn.connect()
                    atr_bytes = conn.getATR()
                    conn.disconnect()

                    if atr_bytes:
                        atr_hex = toHexString(atr_bytes).replace(" ", "")
                        profile = identify_token_by_atr(atr_hex) or identify_token_by_reader_name(reader_name)

                        if profile:
                            token_id = profile["id"]
                            token_name = profile["name"]
                            vendor = profile["vendor"]
                            fips = profile["fips_level"]
                        else:
                            token_id = TOKEN_UNKNOWN
                            token_name = f"SmartCard ({reader_name})"
                            vendor = "Generic Smart Card / CCID"
                            fips = "Unknown"

                        detected_this_cycle[reader_name] = DetectedToken(
                            token_id=token_id,
                            name=token_name,
                            vendor=vendor,
                            reader_name=reader_name,
                            atr=atr_hex,
                            fips_level=fips,
                            is_simulated=False,
                        )
                except Exception as card_err:
                    # Reader exists but card busy, locked by SCardSvr/CertPropSvc, or unpowered
                    logger.debug(f"Reader {reader_name} connect exception: {card_err}")
                    # Resilient fallback: For USB crypto dongles, presence of the reader indicates the token hardware is inserted
                    profile = identify_token_by_reader_name(reader_name)
                    if profile:
                        detected_this_cycle[reader_name] = DetectedToken(
                            token_id=profile["id"],
                            name=profile["name"],
                            vendor=profile["vendor"],
                            reader_name=reader_name,
                            atr="",
                            fips_level=profile["fips_level"],
                            is_simulated=False,
                        )

        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"pyscard polling error: {e}")

        # Fallback 1: Try WinSCard native ctypes if no tokens discovered via pyscard
        if not detected_this_cycle and sys.platform == "win32":
            try:
                self._poll_winscard_ctypes(detected_this_cycle)
            except Exception as e_win:
                logger.debug(f"WinSCard fallback error: {e_win}")

        # Fallback 2: Direct PKCS#11 hardware check if PC/SC service does not report readers
        if not detected_this_cycle and self._pkcs11_mgr:
            try:
                self._poll_pkcs11(detected_this_cycle)
            except Exception as e_p11:
                logger.debug(f"PKCS#11 fallback error: {e_p11}")

        newly_inserted = []
        removed_readers_list = []

        # Reconcile inserted tokens under lock
        with self._lock:
            for reader_name, token in detected_this_cycle.items():
                if reader_name not in self._current_tokens:
                    if self._simulated_token:
                        logger.info("Physical hardware token detected; auto-disabling simulation mode.")
                        self._simulated_token = None
                    self._current_tokens[reader_name] = token
                    newly_inserted.append(token)

            removed_readers = [r for r in self._current_tokens if r not in detected_this_cycle]
            for reader_name in removed_readers:
                del self._current_tokens[reader_name]
                removed_readers_list.append(reader_name)

            insert_callbacks = list(self._callbacks_insert)
            remove_callbacks = list(self._callbacks_remove)

        # Fire callbacks safely outside the lock to prevent deadlock
        for token in newly_inserted:
            logger.info(f"Hardware Token Inserted: {token}")
            for cb in insert_callbacks:
                try:
                    cb(token)
                except Exception as e:
                    logger.error(f"Error in insertion callback: {e}")

        for reader_name in removed_readers_list:
            logger.info(f"Token Removed from reader: {reader_name}")
            for cb in remove_callbacks:
                try:
                    cb(reader_name)
                except Exception as e:
                    logger.error(f"Error in removal callback: {e}")

    def _poll_winscard_ctypes(self, out_tokens: Dict[str, DetectedToken]):
        """Direct WinSCard API fallback via ctypes for Windows (checks both User & System scopes)."""
        import ctypes
        from ctypes import wintypes

        try:
            winscard = ctypes.windll.winscard
            for scope in [0, 2]:  # SCARD_SCOPE_USER, SCARD_SCOPE_SYSTEM
                hContext = wintypes.HANDLE()
                res = winscard.SCardEstablishContext(scope, None, None, ctypes.byref(hContext))
                if res != 0:
                    continue

                cchReaders = wintypes.DWORD(0)
                res_check = winscard.SCardListReadersA(hContext, None, None, ctypes.byref(cchReaders))
                if res_check == 0 and cchReaders.value > 1:
                    readers_buf = ctypes.create_string_buffer(cchReaders.value)
                    res = winscard.SCardListReadersA(hContext, None, readers_buf, ctypes.byref(cchReaders))
                    if res == 0:
                        raw_readers = readers_buf.raw.split(b"\x00")
                        for r in raw_readers:
                            if not r:
                                continue
                            r_str = r.decode("latin-1", errors="ignore")
                            profile = identify_token_by_reader_name(r_str)
                            if profile and r_str not in out_tokens:
                                out_tokens[r_str] = DetectedToken(
                                    token_id=profile["id"],
                                    name=profile["name"],
                                    vendor=profile["vendor"],
                                    reader_name=r_str,
                                    atr="",
                                    fips_level=profile["fips_level"],
                                    is_simulated=False,
                                )

                winscard.SCardReleaseContext(hContext)
                if out_tokens:
                    break
        except Exception as e:
            logger.debug(f"WinSCard ctypes error: {e}")

    def _poll_pkcs11(self, out_tokens: Dict[str, DetectedToken]):
        """Direct vendor PKCS#11 driver fallback if PC/SC service has not registered a smartcard reader slot."""
        if not self._pkcs11_mgr:
            return
        for token_id, profile in TOKEN_PROFILES.items():
            status = self._pkcs11_mgr.get_driver_status(token_id)
            if status and status.is_loadable:
                try:
                    slots = self._pkcs11_mgr.get_slots_with_token(token_id)
                    if slots:
                        reader_tag = f"{profile['name']} (PKCS#11 Slot {slots[0]})"
                        if reader_tag not in out_tokens:
                            out_tokens[reader_tag] = DetectedToken(
                                token_id=profile["id"],
                                name=profile["name"],
                                vendor=profile["vendor"],
                                reader_name=reader_tag,
                                atr="",
                                fips_level=profile["fips_level"],
                                is_simulated=False,
                            )
                except Exception as ex:
                    logger.debug(f"PKCS#11 slot check error for {token_id}: {ex}")

