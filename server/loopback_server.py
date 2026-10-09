"""
Dhanyah Crypto Utility - Local Loopback Gateway Server (Port 18200)
Provides REST & JSON endpoints with CORS support for:
- Web portals (MCA, GST, EPFO, Income Tax, Tenders)
- Accounting tools (Tally, SAP, ERPs)
- Browser DSC signer extensions
"""

import base64
import json
import logging
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, List, Optional, Any, Tuple

from core.constants import DEFAULT_LOOPBACK_HOST, DEFAULT_LOOPBACK_PORT

logger = logging.getLogger("DhanyahCrypto.Loopback")


def ensure_localhost_ssl_cert(force_recreate: bool = False) -> Tuple[str, str]:
    """Generates self-signed localhost SSL cert & key with localhost.emudhra.com SAN for browser portal HTTPS loopback."""
    ssl_dir = os.path.join(
        os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
        "DhanyahCryptoUtility",
        "ssl",
    )
    os.makedirs(ssl_dir, exist_ok=True)
    crt_path = os.path.join(ssl_dir, "localhost.crt")
    key_path = os.path.join(ssl_dir, "localhost.key")

    if not force_recreate and os.path.exists(crt_path) and os.path.exists(key_path):
        try:
            with open(crt_path, "rb") as f:
                content = f.read()
            if b"localhost.emudhra.com" in content:
                return crt_path, key_path
        except Exception:
            pass

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        import ipaddress

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost.emudhra.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dhanyah Crypto Gateway"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("localhost.emudhra.com"),
                    x509.DNSName("*.emudhra.com"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(crt_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        logger.info(f"Generated localhost SSL certificate (with localhost.emudhra.com SAN) at {crt_path}")
    except Exception as e:
        logger.warning(f"Failed to generate localhost SSL certificate: {e}")

    return crt_path, key_path


def check_embridge_service_running() -> bool:
    """Checks if official eMudhra emBridge background Windows service is currently running."""
    import subprocess
    try:
        res = subprocess.run(
            ["sc", "query", "emBridge"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return "RUNNING" in res.stdout
    except Exception:
        return False


def stop_embridge_service() -> Tuple[bool, str]:
    """Stops the official eMudhra emBridge Windows service if requested by user."""
    import subprocess
    try:
        res = subprocess.run(
            ["net", "stop", "emBridge"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            logger.info("Official emBridge Windows service stopped.")
            return True, "Official emBridge service stopped successfully."
        res2 = subprocess.run(
            ["sc", "stop", "emBridge"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res2.returncode == 0:
            return True, "Official emBridge service stopped."
        return False, res2.stderr or res2.stdout or res.stdout
    except Exception as e:
        logger.warning(f"Could not stop emBridge service: {e}")
        return False, str(e)


def start_embridge_service() -> Tuple[bool, str]:
    """Starts the official eMudhra emBridge Windows service if it was stopped."""
    import subprocess
    try:
        res = subprocess.run(
            ["net", "start", "emBridge"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            logger.info("Official emBridge Windows service started.")
            return True, "Official emBridge service started successfully."
        res2 = subprocess.run(
            ["sc", "start", "emBridge"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res2.returncode == 0:
            return True, "Official emBridge service started."
        return False, res2.stderr or res2.stdout or res.stdout
    except Exception as e:
        logger.warning(f"Could not start emBridge service: {e}")
        return False, str(e)


def install_localhost_root_ca() -> Tuple[bool, str]:
    """Adds the localhost certificate to Windows Trusted Root store."""
    crt_path, _ = ensure_localhost_ssl_cert()
    if not os.path.exists(crt_path):
        return False, "Certificate file not found."

    import subprocess
    try:
        # Use certutil -f -addstore Root for silent machine root trust
        res = subprocess.run(
            ["certutil", "-f", "-addstore", "Root", crt_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode == 0:
            logger.info("Localhost SSL certificate successfully added to Windows Root store.")
            return True, "Localhost SSL certificate successfully trusted in Windows Root store."

        # Fallback to User Root
        res2 = subprocess.run(
            ["certutil", "-f", "-addstore", "-user", "Root", crt_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res2.returncode == 0:
            return True, "Localhost SSL certificate successfully trusted in User Root store."
        return False, f"Certutil error ({res.returncode}): {res.stderr or res.stdout}"
    except Exception as e:
        return False, f"Could not install certificate: {e}"


# Default Indian Government Portal & Accounting Gateway Ports
DEFAULT_GOVT_PORTS = [
    {
        "port": 18200,
        "protocol": "http",
        "name": "Dhanyah Native REST Gateway",
        "portal": "Local REST / Desktop Client",
        "enabled": True,
        "builtin": True,
    },
    {
        "port": 15085,
        "protocol": "http",
        "name": "GST / MCA / TRACES Alternative (emSigner)",
        "portal": "GST Offline & Online / MCA / TRACES",
        "enabled": True,
        "builtin": True,
    },
    {
        "port": 1585,
        "protocol": "http",
        "name": "GST / MCA V2 / TRACES Primary (emSigner)",
        "portal": "GST Portal / MCA V2 / TRACES",
        "enabled": True,
        "builtin": True,
    },
    {
        "port": 26769,
        "protocol": "https",
        "name": "Income Tax / MCA V3 Primary (emBridge)",
        "portal": "Income Tax & MCA V3 (Delegated to official emBridge)",
        "enabled": False,  # Disabled by default so Dhanyah never clashes with official emBridge
        "builtin": True,
    },
    {
        "port": 26770,
        "protocol": "https",
        "name": "Income Tax / MCA V3 Alternative (emBridge)",
        "portal": "Income Tax & MCA V3 Secondary (Delegated to official emBridge)",
        "enabled": False,  # Disabled by default so Dhanyah never clashes with official emBridge
        "builtin": True,
    },
    {
        "port": 26443,
        "protocol": "https",
        "name": "GST Portal Secure / TRACES (HTTPS)",
        "portal": "GST Secure Gateway & TRACES",
        "enabled": True,
        "builtin": True,
    },
    {
        "port": 16443,
        "protocol": "https",
        "name": "Commercial Taxes / State Govt Secure (HTTPS)",
        "portal": "State VAT, Commercial Taxes, e-Procurement",
        "enabled": True,
        "builtin": True,
    },
    {
        "port": 8080,
        "protocol": "http",
        "name": "TRACES / EPFO / e-Procurement (HTTP)",
        "portal": "EPFO Unified Portal, GeM, TRACES",
        "enabled": True,
        "builtin": True,
    },
]


def get_gateway_ports_config_path() -> str:
    appdata_dir = os.path.join(
        os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
        "DhanyahCryptoUtility",
    )
    os.makedirs(appdata_dir, exist_ok=True)
    return os.path.join(appdata_dir, "gateway_ports.json")


def load_gateway_ports_config() -> List[Dict[str, Any]]:
    path = get_gateway_ports_config_path()
    configured_ports: List[Dict[str, Any]] = []
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    configured_ports = data
        except Exception as e:
            logger.warning(f"Failed to read gateway_ports.json: {e}")

    existing_ports = {c.get("port") for c in configured_ports if isinstance(c, dict)}
    merged = list(configured_ports)
    for default in DEFAULT_GOVT_PORTS:
        if default["port"] not in existing_ports:
            merged.append(dict(default))

    # If official emBridge service is present/running, keep 26769 & 26770 disabled
    # to guarantee zero port clash and prevent emBridge services from failing
    if check_embridge_service_running():
        for c in merged:
            if c.get("port") in (26769, 26770):
                c["enabled"] = False

    return merged


def save_gateway_ports_config(ports_list: List[Dict[str, Any]]) -> bool:
    path = get_gateway_ports_config_path()
    try:
        # Do not persist temporary ad-hoc primary test ports
        clean_list = [p for p in ports_list if p.get("name") != "Configured Primary Port"]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(clean_list, f, indent=2)
        return True
    except Exception as e:
        logger.warning(f"Failed to save gateway_ports.json: {e}")
        return False


def find_process_on_port(port: int) -> Optional[Tuple[int, str]]:
    """Returns (pid, proc_name) if port is currently occupied by an external process."""
    import subprocess
    try:
        output = subprocess.check_output(
            ["netstat", "-ano", "-p", "tcp"],
            text=True,
            timeout=2,
        )
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 5 and "LISTENING" in parts:
                local_addr = parts[1]
                if local_addr.endswith(f":{port}"):
                    pid = int(parts[-1])
                    try:
                        proc_out = subprocess.check_output(
                            ["tasklist", "/fi", f"PID eq {pid}", "/fo", "csv", "/nh"],
                            text=True,
                            timeout=1,
                        )
                        name = proc_out.split(",")[0].replace('"', "").strip() if proc_out else f"PID {pid}"
                    except Exception:
                        name = f"PID {pid}"
                    return (pid, name)
    except Exception:
        pass
    return None


def kill_process_on_port(port: int) -> Tuple[bool, str]:
    """Terminates process occupying the port so Dhanyah can claim it."""
    info = find_process_on_port(port)
    if not info:
        return True, f"Port {port} is not occupied."
    pid, name = info
    if pid == os.getpid():
        return False, f"Port {port} is held by this application."
    try:
        import subprocess
        res = subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            logger.info(f"Terminated conflicting process {name} (PID {pid}) on port {port}.")
            return True, f"Terminated {name} (PID {pid}) to free port {port}."
        return False, f"Could not terminate PID {pid}: {res.stderr or res.stdout}"
    except Exception as e:
        return False, f"Failed to kill process on port {port}: {e}"


def test_port_connectivity(port: int, protocol: str = "http", timeout: float = 2.0) -> Tuple[bool, str]:
    """Performs loopback ping test on port."""
    import urllib.request
    import ssl
    candidates = [
        f"{protocol}://127.0.0.1:{port}/status",
        f"{protocol}://127.0.0.1:{port}/DSC/Version",
        f"{protocol}://127.0.0.1:{port}/getCertificate",
        f"{protocol}://127.0.0.1:{port}/",
    ]
    ctx = ssl._create_unverified_context() if protocol == "https" else None
    last_err = ""
    for url in candidates:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DhanyahPortTester/1.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return True, f"Port {port} ({protocol.upper()}) is ACTIVE & responding (HTTP {resp.status})."
        except Exception as e:
            last_err = str(e)
    return False, f"Port {port} failed to respond: {last_err}"


class LoopbackRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests with full CORS headers and JSON responses."""

    server_app = None  # Reference to parent LoopbackServer

    def _set_cors_headers(self, status_code: int = 200, content_type: str = "application/json"):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        self.end_headers()

    def do_OPTIONS(self):
        """Handle preflight CORS requests."""
        self._set_cors_headers(200)

    def do_GET(self):
        """Handle GET requests."""
        self._log_request()
        path = self.path.split("?")[0]

        # emBridge Endpoints (Income Tax / MCA V3)
        if path == "/DSC/Version":
            self._handle_embridge_version()
        elif path == "/DSC/ListToken":
            self._handle_embridge_list_token()
        elif path == "/DSC/ListCertificate":
            self._handle_embridge_list_certificate()
        elif path == "/DSC/Initialize":
            self._send_json(200, {"status": 1, "message": "Success"})
        # emSigner Endpoints (GST Portal / Traces)
        elif path in ["/getCertificate", "/getCertificates"]:
            self._handle_emsigner_certificates()
        # Dhanyah Native Endpoints & Portal Health Checks
        elif path in ["/", "/status", "/health", "/checkServer", "/isServiceRunning", "/ping"]:
            self._handle_status()
        elif path in ["/certificates", "/certs"]:
            self._handle_certificates()
        elif path == "/drivers":
            self._handle_drivers()
        elif path in ["/ports", "/gateway/ports"]:
            self._handle_ports_overview()
        else:
            self._send_json(404, {"error": "Endpoint not found", "path": path})

    def do_POST(self):
        """Handle POST requests."""
        self._log_request()
        path = self.path.split("?")[0]

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 50 * 1024 * 1024:  # 50MB limit
            self._send_json(413, {"error": "Payload too large"})
            return

        body = self.rfile.read(content_length)
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            payload = {}

        # emBridge Endpoints
        if path == "/DSC/Version":
            self._handle_embridge_version()
        elif path == "/DSC/ListToken":
            self._handle_embridge_list_token()
        elif path == "/DSC/ListCertificate":
            self._handle_embridge_list_certificate()
        elif path == "/DSC/PKCSSign":
            self._handle_embridge_pkcs_sign(payload)
        elif path == "/DSC/Initialize":
            self._send_json(200, {"status": 1, "message": "Success"})
        # emSigner Endpoints
        elif path in ["/getCertificate", "/getCertificates"]:
            self._handle_emsigner_certificates()
        elif path in ["/sign", "/signData", "/getSign"]:
            self._handle_emsigner_sign(payload)
        # Dhanyah Native Endpoints
        elif path in ["/verify/pin", "/pin/verify"]:
            self._handle_verify_pin(payload)
        elif path in ["/sign/hash", "/hash/sign"]:
            self._handle_sign_hash(payload)
        elif path in ["/sign/pdf", "/pdf/sign"]:
            self._handle_sign_pdf(payload)
        elif path in ["/ports", "/gateway/ports"]:
            self._handle_ports_overview()
        elif path == "/":
            action = str(payload.get("action", "")).lower()
            if "cert" in action:
                self._handle_emsigner_certificates()
            elif "sign" in action:
                self._handle_emsigner_sign(payload)
            else:
                self._handle_status()
        else:
            self._send_json(404, {"error": "Endpoint not found", "path": path})

    def _handle_ports_overview(self):
        app = self.server_app
        overview = app.get_port_overview() if app and hasattr(app, "get_port_overview") else []
        self._send_json(200, {"status": "success", "ports": overview})

    def _handle_status(self):
        app = self.server_app
        token = app.get_primary_token()
        drivers = app.get_driver_statuses()

        data = {
            "status": "online",
            "service": "Dhanyah Crypto Utility Gateway",
            "port": app.port,
            "active_ports": app.active_ports,
            "port_protocols": getattr(app, "port_protocols", {}),
            "ports_overview": app.get_port_overview() if hasattr(app, "get_port_overview") else [],
            "https_enabled": any(proto == "https" for proto in getattr(app, "port_protocols", {}).values()),
            "token_connected": token is not None,
            "token": token.to_dict() if token else None,
            "drivers": [d.to_dict() for d in drivers],
        }
        self._send_json(200, data)

    def _handle_drivers(self):
        app = self.server_app
        drivers = app.get_driver_statuses()
        self._send_json(200, {"drivers": [d.to_dict() for d in drivers]})

    def _handle_certificates(self):
        app = self.server_app
        certs = app.get_certificates()
        self._send_json(200, {"certificates": [c.to_dict() for c in certs]})

    def _handle_verify_pin(self, payload: Dict[str, Any]):
        app = self.server_app
        pin = payload.get("pin", "")
        token = app.get_primary_token()
        if not token:
            self._send_json(400, {"success": False, "error": "No crypto token inserted."})
            return

        res = app.pin_manager.verify_pin(
            token_id=token.token_id,
            slot=payload.get("slot", None),
            pin=pin,
            is_simulated=token.is_simulated,
        )
        self._send_json(200 if res.success else 401, res.to_dict())

    def _handle_sign_hash(self, payload: Dict[str, Any]):
        app = self.server_app
        pin = payload.get("pin", "")
        hash_hex = payload.get("hash_hex")
        hash_b64 = payload.get("hash_b64")

        token = app.get_primary_token()
        if not token:
            self._send_json(400, {"success": False, "error": "No crypto token inserted."})
            return

        if not pin:
            self._send_json(400, {"success": False, "error": "PIN is required."})
            return

        # Decode hash
        if hash_hex:
            try:
                data_hash = bytes.fromhex(hash_hex)
            except ValueError:
                self._send_json(400, {"success": False, "error": "Invalid hash_hex."})
                return
        elif hash_b64:
            try:
                data_hash = base64.b64decode(hash_b64)
            except Exception:
                self._send_json(400, {"success": False, "error": "Invalid hash_b64."})
                return
        else:
            self._send_json(400, {"success": False, "error": "hash_hex or hash_b64 is required."})
            return

        try:
            raw_sig = app.signer.sign_hash_hardware(
                token_id=token.token_id,
                slot=payload.get("slot", None),
                pin=pin,
                data_hash=data_hash,
                is_simulated=token.is_simulated,
            )
            self._send_json(
                200,
                {
                    "success": True,
                    "signature_hex": raw_sig.hex().upper(),
                    "signature_b64": base64.b64encode(raw_sig).decode("ascii"),
                },
            )
        except Exception as e:
            self._send_json(500, {"success": False, "error": str(e)})

    def _handle_sign_pdf(self, payload: Dict[str, Any]):
        app = self.server_app
        pdf_b64 = payload.get("pdf_base64", "")
        pin = payload.get("pin", "")
        reason = payload.get("reason", "Digitally Signed via Dhanyah Crypto Utility")
        location = payload.get("location", "India")

        token = app.get_primary_token()
        if not token:
            self._send_json(400, {"success": False, "error": "No crypto token inserted."})
            return

        if not pdf_b64:
            self._send_json(400, {"success": False, "error": "pdf_base64 is required."})
            return

        certs = app.get_certificates()
        if not certs:
            self._send_json(400, {"success": False, "error": "No signing certificate available on token."})
            return

        cert = certs[0]

        try:
            pdf_bytes = base64.b64decode(pdf_b64)
            # Write temp input and output
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as in_f:
                in_f.write(pdf_bytes)
                in_path = in_f.name

            out_path = in_path + ".signed.pdf"

            res = app.signer.sign_pdf(
                input_pdf_path=in_path,
                output_pdf_path=out_path,
                token_id=token.token_id,
                slot=0,
                pin=pin,
                cert=cert,
                reason=reason,
                location=location,
                is_simulated=token.is_simulated,
            )

            if res.success and os.path.exists(out_path):
                with open(out_path, "rb") as out_f:
                    signed_pdf_bytes = out_f.read()

                # Clean up
                try:
                    os.remove(in_path)
                    os.remove(out_path)
                except Exception:
                    pass

                self._send_json(
                    200,
                    {
                        "success": True,
                        "signed_pdf_base64": base64.b64encode(signed_pdf_bytes).decode("ascii"),
                        "signer": cert.common_name,
                        "pan": cert.pan_number,
                    },
                )
            else:
                self._send_json(500, {"success": False, "error": res.error_message})

        except Exception as e:
            self._send_json(500, {"success": False, "error": str(e)})

    def _handle_embridge_version(self):
        self._send_json(
            200,
            {
                "status": 1,
                "version": "5.9.3.1",
                "message": "Success",
                "service": "Dhanyah Crypto Utility emBridge Gateway",
            },
        )

    def _handle_embridge_list_token(self):
        app = self.server_app
        token = app.get_primary_token()
        if not token:
            self._send_json(
                200,
                {
                    "status": 0,
                    "version": "5.9.3.1",
                    "message": "No smart card or USB token detected.",
                    "tokens": [],
                    "tokenList": [],
                },
            )
            return

        token_entry = {
            "tokenId": 0,
            "tokenName": token.name,
            "tokenSerial": token.serial_number or "DH-2026-FIPS3",
            "status": "Connected",
            "tokenType": "HARDWARE",
            "model": getattr(token, "model", "") or token.name,
            "manufacturer": getattr(token, "manufacturer", "") or "Dhanyah PKI",
        }
        self._send_json(
            200,
            {
                "status": 1,
                "version": "5.9.3.1",
                "message": "Token list retrieved successfully",
                "tokens": [token_entry],
                "tokenList": [token_entry],
            },
        )

    def _handle_embridge_list_certificate(self):
        app = self.server_app
        certs = app.get_certificates()
        if not certs:
            self._send_json(
                200,
                {
                    "status": 0,
                    "version": "5.9.3.1",
                    "message": "No certificate found on token.",
                    "certificates": [],
                    "certificateList": [],
                },
            )
            return

        cert_list = []
        for idx, cert in enumerate(certs):
            valid_from_str = cert.valid_from.strftime("%d-%m-%Y %H:%M:%S") if hasattr(cert, "valid_from") else ""
            valid_to_str = cert.valid_to.strftime("%d-%m-%Y %H:%M:%S") if hasattr(cert, "valid_to") else ""
            cert_b64 = base64.b64encode(cert.cert_der).decode("ascii")
            cert_list.append(
                {
                    "certId": idx,
                    "keyId": idx,
                    "alias": cert.common_name,
                    "commonName": cert.common_name,
                    "issuer": cert.issuer_cn,
                    "serialNumber": cert.serial_number_hex,
                    "validFrom": valid_from_str,
                    "validTo": valid_to_str,
                    "certificate": cert_b64,
                    "publicKey": cert.fingerprint_sha256,
                    "pan": cert.pan_number or "",
                }
            )

        self._send_json(
            200,
            {
                "status": 1,
                "version": "5.9.3.1",
                "message": "Certificate list retrieved successfully",
                "certificates": cert_list,
                "certificateList": cert_list,
            },
        )

    def _handle_embridge_pkcs_sign(self, payload: Dict[str, Any]):
        app = self.server_app
        token = app.get_primary_token()
        if not token:
            self._send_json(200, {"status": 0, "version": "5.9.3.1", "message": "No token connected."})
            return

        raw_input = payload.get("data") or payload.get("hash") or payload.get("tbsData") or ""
        pin = payload.get("pin") or payload.get("password") or ""
        algo = payload.get("algo") or payload.get("algorithm") or "SHA256"

        if not raw_input:
            self._send_json(200, {"status": 0, "version": "5.9.3.1", "message": "No data or hash provided to sign."})
            return

        try:
            input_bytes = base64.b64decode(raw_input)
        except Exception:
            input_bytes = raw_input.encode("utf-8")

        certs = app.get_certificates()
        cert = certs[0] if certs else None
        ck_id = cert.ck_id if cert else b""

        try:
            if len(input_bytes) in [20, 32, 64]:
                sig_bytes = app.signer.sign_hash_hardware(
                    token_id=token.token_id,
                    slot=payload.get("slot", 0),
                    pin=pin,
                    data_hash=input_bytes,
                    ck_id=ck_id,
                    algo=algo,
                    is_simulated=token.is_simulated,
                )
            else:
                sig_bytes = app.signer.sign_data(
                    token_id=token.token_id,
                    slot=payload.get("slot", 0),
                    pin=pin,
                    raw_data=input_bytes,
                    algo=algo,
                    ck_id=ck_id,
                    is_simulated=token.is_simulated,
                )

            sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
            self._send_json(
                200,
                {
                    "status": 1,
                    "version": "5.9.3.1",
                    "message": "Data signed successfully",
                    "signedText": sig_b64,
                    "signature": sig_b64,
                },
            )
        except Exception as e:
            logger.error(f"emBridge PKCSSign error: {e}")
            self._send_json(200, {"status": 0, "version": "5.9.3.1", "message": f"Signing error: {e}"})

    def _handle_emsigner_certificates(self):
        app = self.server_app
        certs = app.get_certificates()
        cert_items = []
        for c in certs:
            cert_items.append(
                {
                    "certificate": base64.b64encode(c.cert_der).decode("ascii"),
                    "alias": c.common_name,
                    "serialNumber": c.serial_number_hex,
                    "issuer": c.issuer_cn,
                    "validTo": c.valid_to.strftime("%d-%m-%Y %H:%M:%S") if hasattr(c, "valid_to") else "",
                    "pan": c.pan_number or "",
                }
            )
        self._send_json(200, {"status": "success", "certificates": cert_items})

    def _handle_emsigner_sign(self, payload: Dict[str, Any]):
        app = self.server_app
        token = app.get_primary_token()
        if not token:
            self._send_json(400, {"status": "error", "error": "No crypto token inserted."})
            return

        raw_input = payload.get("data") or payload.get("hash") or payload.get("signData") or ""
        pin = payload.get("pin") or payload.get("password") or ""
        algo = payload.get("algo") or "SHA256"

        try:
            input_bytes = base64.b64decode(raw_input)
        except Exception:
            input_bytes = raw_input.encode("utf-8")

        certs = app.get_certificates()
        cert = certs[0] if certs else None
        ck_id = cert.ck_id if cert else b""

        try:
            if len(input_bytes) in [20, 32, 64]:
                sig_bytes = app.signer.sign_hash_hardware(
                    token_id=token.token_id,
                    slot=payload.get("slot", 0),
                    pin=pin,
                    data_hash=input_bytes,
                    ck_id=ck_id,
                    algo=algo,
                    is_simulated=token.is_simulated,
                )
            else:
                sig_bytes = app.signer.sign_data(
                    token_id=token.token_id,
                    slot=payload.get("slot", 0),
                    pin=pin,
                    raw_data=input_bytes,
                    algo=algo,
                    ck_id=ck_id,
                    is_simulated=token.is_simulated,
                )

            sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
            self._send_json(200, {"status": "success", "signature": sig_b64})
        except Exception as e:
            self._send_json(500, {"status": "error", "error": str(e)})

    def _send_json(self, status: int, data: Dict[str, Any]):
        content = json.dumps(data, indent=2).encode("utf-8")
        self._set_cors_headers(status)
        self.wfile.write(content)

    def _log_request(self):
        msg = f"[{self.command}] {self.path} from {self.client_address[0]}"
        logger.info(msg)
        if self.server_app and self.server_app.log_callback:
            self.server_app.log_callback(msg)

    def log_message(self, format, *args):
        # Suppress default stderr output
        pass


class LoopbackServer:
    """Threaded local loopback HTTP gateway server supporting multi-port listeners."""

    def __init__(
        self,
        token_detector,
        pkcs11_mgr,
        cert_manager,
        pin_manager,
        signer,
        host: str = DEFAULT_LOOPBACK_HOST,
        port: int = DEFAULT_LOOPBACK_PORT,
    ):
        self.detector = token_detector
        self.pkcs11_mgr = pkcs11_mgr
        self.cert_manager = cert_manager
        self.pin_manager = pin_manager
        self.signer = signer
        self.host = host
        self.port = port
        self._servers: Dict[int, ThreadingHTTPServer] = {}
        self._server_threads: Dict[int, threading.Thread] = {}
        self.active_ports: List[int] = []
        self.port_protocols: Dict[int, str] = {}
        self.port_configs: List[Dict[str, Any]] = load_gateway_ports_config()

        # Ensure requested self.port is included in configs
        if not any(c.get("port") == self.port for c in self.port_configs):
            self.port_configs.insert(
                0,
                {
                    "port": self.port,
                    "protocol": "http",
                    "name": "Configured Primary Port",
                    "portal": "Local Gateway Client",
                    "enabled": True,
                    "builtin": False,
                },
            )

        self.log_callback: Optional[Callable[[str], None]] = None

    def get_primary_token(self):
        return self.detector.get_primary_token()

    def get_driver_statuses(self):
        return self.pkcs11_mgr.get_all_driver_statuses()

    def get_certificates(self):
        token = self.get_primary_token()
        if not token:
            return []
        if token.is_simulated or token.token_id == "SIMULATED":
            return [self.cert_manager.generate_simulated_dsc()]
        return self.cert_manager.get_token_certificates(token.token_id)

    def trust_ssl_certificate(self) -> Tuple[bool, str]:
        """Install local certificate to Windows Trusted Root store."""
        return install_localhost_root_ca()

    def _bind_single_port(self, port: int, protocol: str) -> bool:
        """Binds and starts a single port listener."""
        if port in self._servers:
            return True

        # Prevent clashing with official emBridge service if it is running
        if port in (26769, 26770) and check_embridge_service_running():
            logger.info(
                f"Official emBridge Windows service is active on port {port}. "
                f"Dhanyah will not bind to port {port} to prevent clashing."
            )
            return False

        crt_path, key_path = ensure_localhost_ssl_cert()
        ssl_ready = os.path.exists(crt_path) and os.path.exists(key_path)
        is_https = (str(protocol).lower() == "https") and ssl_ready

        try:
            class ReusableServer(ThreadingHTTPServer):
                allow_reuse_address = True
                daemon_threads = True

            server = ReusableServer((self.host, port), LoopbackRequestHandler)
            if is_https:
                import ssl
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_ctx.load_cert_chain(certfile=crt_path, keyfile=key_path)
                server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)

            thread = threading.Thread(
                target=server.serve_forever, daemon=True, name=f"GatewayThread_{port}"
            )
            thread.start()
            self._servers[port] = server
            self._server_threads[port] = thread
            if port not in self.active_ports:
                self.active_ports.append(port)
            self.port_protocols[port] = "https" if is_https else "http"
            proto = "https" if is_https else "http"
            logger.info(f"Gateway listening on {proto}://{self.host}:{port}")
            if self.log_callback:
                self.log_callback(f"Gateway active on {proto}://{self.host}:{port}")
            return True
        except OSError as e:
            logger.info(
                f"Port {port} already bound by service or restricted: {e}. Falling back to active ports."
            )
            return False
        except Exception as e:
            logger.warning(f"Error binding port {port}: {e}")
            return False

    def start(self) -> bool:
        """Start the loopback gateway across all configured government portal ports with HTTPS support."""
        if self._servers:
            return True

        LoopbackRequestHandler.server_app = self
        self.port_configs = load_gateway_ports_config()

        # Ensure requested self.port is included in configs
        if not any(c.get("port") == self.port for c in self.port_configs):
            self.port_configs.insert(
                0,
                {
                    "port": self.port,
                    "protocol": "http",
                    "name": "Configured Primary Port",
                    "portal": "Local Gateway Client",
                    "enabled": True,
                    "builtin": False,
                },
            )

        # Log official emBridge coexistence
        if check_embridge_service_running():
            logger.info("Official emBridge service is active. Dhanyah will coexist peacefully without touching or stopping emBridge.")

        bound_any = False
        for cfg in self.port_configs:
            if not cfg.get("enabled", True):
                continue
            port = int(cfg["port"])
            protocol = cfg.get("protocol", "http")
            if self._bind_single_port(port, protocol):
                bound_any = True

        return bound_any

    def stop_port(self, port: int) -> bool:
        """Stops a single active port listener."""
        server = self._servers.pop(port, None)
        if server:
            try:
                server.shutdown()
                server.server_close()
            except Exception as e:
                logger.debug(f"Error closing port {port}: {e}")

        thread = self._server_threads.pop(port, None)
        if thread:
            try:
                if thread.is_alive():
                    thread.join(timeout=0.5)
            except Exception:
                pass

        if port in self.active_ports:
            self.active_ports.remove(port)
        self.port_protocols.pop(port, None)
        logger.info(f"Stopped gateway listener on port {port}")
        return True

    def stop(self):
        """Stop all gateway server instances."""
        ports = list(self._servers.keys())
        for port in ports:
            self.stop_port(port)
        self._servers.clear()
        self._server_threads.clear()
        self.active_ports.clear()
        self.port_protocols.clear()
        logger.info("All Gateway servers stopped.")

    def is_running(self) -> bool:
        return len(self._servers) > 0

    def add_custom_port(
        self, port: int, protocol: str = "http", name: str = "", portal: str = ""
    ) -> Tuple[bool, str]:
        """Adds a custom port to configuration, saves it, and starts listening on it."""
        if not (1 <= port <= 65535):
            return False, f"Invalid port number: {port}. Must be between 1 and 65535."

        protocol = protocol.lower().strip()
        if protocol not in ["http", "https"]:
            protocol = "http"

        if not name:
            name = f"Custom Port {port} ({protocol.upper()})"
        if not portal:
            portal = "Custom Government / ERP Portal"

        # Check if port already exists in config
        existing = next((c for c in self.port_configs if c.get("port") == port), None)
        if existing:
            existing["protocol"] = protocol
            existing["name"] = name
            existing["portal"] = portal
            existing["enabled"] = True
        else:
            self.port_configs.append(
                {
                    "port": port,
                    "protocol": protocol,
                    "name": name,
                    "portal": portal,
                    "enabled": True,
                    "builtin": False,
                }
            )

        save_gateway_ports_config(self.port_configs)

        # If gateway is running, attempt to bind port immediately
        if self.is_running():
            ok = self._bind_single_port(port, protocol)
            if ok:
                return True, f"Port {port} ({protocol.upper()}) added and successfully activated!"
            else:
                proc = find_process_on_port(port)
                conflict_msg = f" (occupied by {proc[1]} PID {proc[0]})" if proc else ""
                return False, f"Port {port} saved, but failed to bind{conflict_msg}. Use 'Free Port' to claim it."
        return True, f"Port {port} ({protocol.upper()}) saved to configuration."

    def remove_custom_port(self, port: int) -> Tuple[bool, str]:
        """Removes a custom port from configuration and stops its listener."""
        self.stop_port(port)
        self.port_configs = [c for c in self.port_configs if c.get("port") != port]
        save_gateway_ports_config(self.port_configs)
        return True, f"Port {port} removed."

    def toggle_port(self, port: int, enable: bool) -> Tuple[bool, str]:
        """Enables or disables a configured port."""
        for c in self.port_configs:
            if c.get("port") == port:
                c["enabled"] = enable
                break
        save_gateway_ports_config(self.port_configs)

        if enable:
            protocol = next((c.get("protocol", "http") for c in self.port_configs if c.get("port") == port), "http")
            ok = self._bind_single_port(port, protocol)
            return (ok, f"Port {port} activated." if ok else f"Port {port} failed to bind.")
        else:
            self.stop_port(port)
            return True, f"Port {port} stopped."

    def free_and_claim_port(self, port: int) -> Tuple[bool, str]:
        """Kills any conflicting process and starts listening on the port."""
        if port in (26769, 26770) and check_embridge_service_running():
            return False, f"Port {port} is dedicated to official emBridge. Dhanyah coexists with emBridge without terminating it."

        self.stop_port(port)
        ok_kill, msg_kill = kill_process_on_port(port)
        import time
        time.sleep(0.4)

        protocol = next((c.get("protocol", "http") for c in self.port_configs if c.get("port") == port), "http")
        ok_bind = self._bind_single_port(port, protocol)
        if ok_bind:
            return True, f"Successfully freed and claimed port {port} ({protocol.upper()})!"
        return False, f"Attempted to free port {port}, but could not bind: {msg_kill}"

    def get_port_overview(self, check_conflicts: bool = False) -> List[Dict[str, Any]]:
        """Returns the current runtime status of all configured ports."""
        embridge_running = check_embridge_service_running()
        overview = []
        for c in self.port_configs:
            port = int(c["port"])
            protocol = c.get("protocol", "http")
            is_active = port in self._servers
            is_embridge_port = (port in (26769, 26770)) and embridge_running
            conflict = None
            if not is_active and not is_embridge_port and c.get("enabled", True) and check_conflicts:
                conflict_info = find_process_on_port(port)
                if conflict_info:
                    conflict = {"pid": conflict_info[0], "process": conflict_info[1]}

            overview.append(
                {
                    "port": port,
                    "protocol": protocol,
                    "name": c.get("name", f"Port {port}"),
                    "portal": c.get("portal", ""),
                    "enabled": c.get("enabled", True),
                    "builtin": c.get("builtin", False),
                    "is_active": is_active,
                    "embridge_active": is_embridge_port,
                    "conflict": conflict,
                }
            )
        return overview

    def test_port(self, port: int) -> Tuple[bool, str]:
        """Tests loopback responsiveness of a specific port."""
        protocol = self.port_protocols.get(port)
        if not protocol:
            cfg = next((c for c in self.port_configs if c.get("port") == port), None)
            protocol = cfg.get("protocol", "http") if cfg else "http"
        return test_port_connectivity(port, protocol)
