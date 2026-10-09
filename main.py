"""
Dhanyah Crypto Utility - Application Entry Point
Unified FIPS 140-2/3 Level 3 Token Management & Cryptographic Signing Suite
"""

import argparse
import logging
import os
import sys

# Ensure UTF-8 output encoding for console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Configure logging safely for both console and windowed GUI
log_handlers = []
if sys.stdout is not None:
    log_handlers.append(logging.StreamHandler(sys.stdout))

try:
    if getattr(sys, "frozen", False):
        appdata_dir = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "DhanyahCryptoUtility")
        os.makedirs(appdata_dir, exist_ok=True)
        log_file = os.path.join(appdata_dir, "dhanyah_crypto.log")
    else:
        log_dir = os.path.dirname(os.path.abspath(__file__))
        log_file = os.path.join(log_dir, "dhanyah_crypto.log")
    log_handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
except Exception:
    try:
        import tempfile
        log_file = os.path.join(tempfile.gettempdir(), "dhanyah_crypto.log")
        log_handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    except Exception:
        pass

if not log_handlers:
    log_handlers.append(logging.NullHandler())

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=log_handlers,
)
logger = logging.getLogger("DhanyahCrypto.Main")

from core.token_detector import TokenDetector
from core.pkcs11_manager import PKCS11Manager
from core.cert_manager import CertManager
from core.pin_manager import PinManager
from core.signer import TokenSigner
from server.loopback_server import LoopbackServer
from core.constants import DEFAULT_LOOPBACK_PORT, DEFAULT_LOOPBACK_HOST


def run_headless(args, detector, pkcs11_mgr, cert_mgr, pin_mgr, signer):
    """Run in headless service mode without launching GUI."""
    logger.info("Running Dhanyah Crypto Utility in HEADLESS service mode...")
    detector.start()

    if args.sim:
        detector.set_simulation_mode(args.sim.upper())

    server = LoopbackServer(
        token_detector=detector,
        pkcs11_mgr=pkcs11_mgr,
        cert_manager=cert_mgr,
        pin_manager=pin_mgr,
        signer=signer,
        host=DEFAULT_LOOPBACK_HOST,
        port=args.port,
    )
    server.start()
    logger.info(f"Gateway listening on http://{DEFAULT_LOOPBACK_HOST}:{args.port}")
    logger.info("Press Ctrl+C to terminate.")

    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down headless service...")
        server.stop()
        detector.stop()


def run_gui(args, detector, pkcs11_mgr, cert_mgr, pin_mgr, signer):
    """Run the modern PySide6 desktop GUI."""
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication

    # Set High-DPI attributes before creating QApplication
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("Dhanyah Crypto Utility")
    app.setOrganizationName("Dhanyah")
    app.setQuitOnLastWindowClosed(False)

    from ui.main_window import MainWindow, create_app_icon
    app.setWindowIcon(create_app_icon())

    from core.smartcard_registrar import SmartCardRegistrar

    # Auto-register Windows Smart Card subsystem for all 4 tokens in background if elevated
    if SmartCardRegistrar.is_admin():
        import threading
        def _reg_bg():
            try:
                SmartCardRegistrar.register_windows_subsystem()
            except Exception as e:
                logger.warning(f"Auto-registration of Smart Card subsystem: {e}")
        threading.Thread(target=_reg_bg, daemon=True, name="RegistrarBgThread").start()

    # Auto-pulse Windows certificate propagation when hardware token is inserted
    def _on_token_inserted_pulse(token):
        if not getattr(token, "is_simulated", False):
            SmartCardRegistrar.pulse_windows_certificates()

    detector.register_insertion_callback(_on_token_inserted_pulse)

    # Start hardware token hotplug monitor
    detector.start()

    # Pre-set simulation if passed via CLI
    if args.sim:
        detector.set_simulation_mode(args.sim.upper())

    # Start loopback server
    server = LoopbackServer(
        token_detector=detector,
        pkcs11_mgr=pkcs11_mgr,
        cert_manager=cert_mgr,
        pin_manager=pin_mgr,
        signer=signer,
        host=DEFAULT_LOOPBACK_HOST,
        port=args.port,
    )
    server.start()

    window = MainWindow(
        detector=detector,
        pkcs11_mgr=pkcs11_mgr,
        cert_mgr=cert_mgr,
        pin_mgr=pin_mgr,
        signer=signer,
        server=server,
    )
    window.show()

    exit_code = app.exec()
    detector.stop()
    server.stop()
    sys.exit(exit_code)


def main():
    parser = argparse.ArgumentParser(
        description="Dhanyah Crypto Utility - Unified Token Management & PKI Signing Suite"
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run as a headless background loopback service without GUI",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_LOOPBACK_PORT,
        help=f"Loopback HTTP server port (default: {DEFAULT_LOOPBACK_PORT})",
    )
    parser.add_argument(
        "--sim",
        type=str,
        choices=["HYP2003", "MTOKEN", "PROXKEY", "INNAIT"],
        help="Pre-activate simulation mode with a specific token profile",
    )
    args = parser.parse_args()

    # Initialize Core Subsystems
    logger.info("Initializing Core Cryptographic Subsystems...")
    detector = TokenDetector()
    pkcs11_mgr = PKCS11Manager()
    cert_mgr = CertManager(pkcs11_mgr)
    pin_mgr = PinManager(pkcs11_mgr)
    signer = TokenSigner(pkcs11_mgr)

    if args.headless:
        run_headless(args, detector, pkcs11_mgr, cert_mgr, pin_mgr, signer)
    else:
        run_gui(args, detector, pkcs11_mgr, cert_mgr, pin_mgr, signer)


if __name__ == "__main__":
    main()
