"""
Dhanyah Crypto Utility - Local Network (LAN) DSC Mesh Subsystem
Enables zero-configuration peer discovery, remote token mounting, and
cross-machine cryptographic signing across office LAN workstations.
"""

import base64
import json
import logging
import os
import socket
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Callable, Any

from core.constants import DEFAULT_LOOPBACK_PORT, APP_VERSION

logger = logging.getLogger("DhanyahCrypto.LanMesh")

LAN_MESH_BROADCAST_PORT = 18205
LAN_BEACON_MAGIC = "DHANYAH_DSC_MESH_v1"
PEER_TIMEOUT_SECONDS = 16.0


def get_local_lan_ip() -> str:
    """Detect the local machine's primary LAN IPv4 address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


@dataclass
class LanCertificateInfo:
    common_name: str
    pan_number: str = ""
    cert_class: str = "Class 3"
    issuer: str = ""
    valid_from: str = ""
    valid_to: str = ""
    serial_hex: str = ""
    cert_der_b64: str = ""
    token_id: str = "REMOTE_LAN"
    slot: int = 0
    is_ca: bool = False
    token_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LanCertificateInfo":
        return cls(
            common_name=d.get("common_name", "Unknown Signer"),
            pan_number=d.get("pan_number", ""),
            cert_class=d.get("cert_class", "Class 3"),
            issuer=d.get("issuer", ""),
            valid_from=d.get("valid_from", ""),
            valid_to=d.get("valid_to", ""),
            serial_hex=d.get("serial_hex", ""),
            cert_der_b64=d.get("cert_der_b64", ""),
            token_id=d.get("token_id", "REMOTE_LAN"),
            slot=d.get("slot", 0),
            is_ca=d.get("is_ca", False),
            token_name=d.get("token_name", ""),
        )

    def to_parsed_certificate(self) -> Any:
        """Converts to a ParsedCertificate instance compatible with all UI and crypto signing widgets."""
        import base64
        import datetime
        from core.cert_manager import CertManager, ParsedCertificate
        if self.cert_der_b64:
            try:
                der = base64.b64decode(self.cert_der_b64)
                p = ParsedCertificate(
                    cert_der=der,
                    label=self.common_name,
                    token_id="REMOTE_LAN",
                    slot=self.slot,
                    token_name=self.token_name or f"LAN Virtual ({self.common_name})",
                )
                return p
            except Exception as e:
                logger.warning(f"Failed to parse remote DER bytes: {e}")

        sim = CertManager.generate_simulated_dsc(
            cn=self.common_name,
            pan=self.pan_number or "ABCDE1234F",
            org=f"Remote Token ({self.cert_class})",
        )
        sim.token_id = "REMOTE_LAN"
        sim.token_name = self.token_name or f"LAN Virtual ({self.common_name})"
        return sim


@dataclass
class LanPeer:
    peer_id: str
    hostname: str
    ip: str
    port: int = DEFAULT_LOOPBACK_PORT
    version: str = APP_VERSION
    has_token: bool = False
    token_name: str = ""
    token_id: str = ""
    is_simulated: bool = False
    sharing_enabled: bool = True
    require_prompt: bool = False
    certificates: List[LanCertificateInfo] = field(default_factory=list)
    last_seen: float = field(default_factory=time.time)
    is_manual: bool = False

    @property
    def display_name(self) -> str:
        return f"{self.hostname} ({self.ip})"

    @property
    def is_online(self) -> bool:
        return (time.time() - self.last_seen) < PEER_TIMEOUT_SECONDS

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["certificates"] = [c.to_dict() if isinstance(c, LanCertificateInfo) else c for c in self.certificates]
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LanPeer":
        certs_raw = d.get("certificates", [])
        certs = [LanCertificateInfo.from_dict(c) if isinstance(c, dict) else c for c in certs_raw]
        return cls(
            peer_id=d.get("peer_id", f"{d.get('hostname', 'unknown')}_{d.get('ip', '')}"),
            hostname=d.get("hostname", "Unknown Host"),
            ip=d.get("ip", "127.0.0.1"),
            port=d.get("port", DEFAULT_LOOPBACK_PORT),
            version=d.get("version", APP_VERSION),
            has_token=d.get("has_token", False),
            token_name=d.get("token_name", ""),
            token_id=d.get("token_id", ""),
            is_simulated=d.get("is_simulated", False),
            sharing_enabled=d.get("sharing_enabled", True),
            require_prompt=d.get("require_prompt", False),
            certificates=certs,
            last_seen=d.get("last_seen", time.time()),
            is_manual=d.get("is_manual", False),
        )


class LanMeshManager:
    """
    Coordinates UDP broadcast beacon discovery and LAN peer management.
    Allows workstations to publish local hardware tokens and mount remote peer tokens.
    """

    def __init__(
        self,
        local_port: int = DEFAULT_LOOPBACK_PORT,
        broadcast_port: int = LAN_MESH_BROADCAST_PORT,
    ):
        self.local_port = local_port
        self.broadcast_port = broadcast_port
        self.hostname = socket.gethostname()
        self.local_ip = get_local_lan_ip()

        # Local sharing preferences
        self.is_sharing_enabled = True
        self.require_prompt_before_sign = False

        # Peer directory: peer_id -> LanPeer
        self._peers: Dict[str, LanPeer] = {}
        self._peers_lock = threading.Lock()

        # Mounted virtual remote peer for this workstation
        self.mounted_peer: Optional[LanPeer] = None
        self.mounted_cert: Optional[LanCertificateInfo] = None

        # Provider callbacks to query local token status
        self.get_local_token_fn: Optional[Callable[[], Any]] = None
        self.get_local_certs_fn: Optional[Callable[[], List[Any]]] = None

        # Change notification listeners
        self._listeners: List[Callable[[List[LanPeer]], None]] = []

        # Worker threads
        self._running = False
        self._broadcast_thread: Optional[threading.Thread] = None
        self._listen_thread: Optional[threading.Thread] = None

    def register_update_callback(self, cb: Callable[[List[LanPeer]], None]):
        """Register a callback invoked whenever the LAN peer list changes."""
        self._listeners.append(cb)

    def _notify_listeners(self):
        peers = self.get_peers()
        for cb in self._listeners:
            try:
                cb(peers)
            except Exception as e:
                logger.error(f"Error in LAN mesh update listener: {e}")

    def get_peers(self) -> List[LanPeer]:
        """Return list of active, non-expired peers (excluding localhost)."""
        now = time.time()
        with self._peers_lock:
            # Purge expired non-manual peers
            expired = [
                pid for pid, p in self._peers.items()
                if not p.is_manual and (now - p.last_seen) > PEER_TIMEOUT_SECONDS
            ]
            for pid in expired:
                logger.info(f"LAN Peer expired: {self._peers[pid].display_name}")
                del self._peers[pid]

            return list(self._peers.values())

    def start(self):
        """Start the LAN Mesh beacon broadcaster and discovery listener."""
        if self._running:
            return
        self._running = True
        logger.info(f"Starting Dhanyah LAN DSC Mesh (IP: {self.local_ip}, UDP Broadcast: {self.broadcast_port})...")

        self._listen_thread = threading.Thread(target=self._listen_worker, daemon=True, name="LanMeshListener")
        self._listen_thread.start()

        self._broadcast_thread = threading.Thread(target=self._broadcast_worker, daemon=True, name="LanMeshBroadcaster")
        self._broadcast_thread.start()

    def stop(self):
        """Stop background LAN Mesh threads."""
        self._running = False
        logger.info("Dhanyah LAN DSC Mesh stopped.")

    def set_sharing_enabled(self, enabled: bool):
        self.is_sharing_enabled = enabled
        logger.info(f"LAN Token Sharing set to: {enabled}")

    def set_require_prompt(self, require: bool):
        self.require_prompt_before_sign = require
        logger.info(f"LAN Sign Require Prompt set to: {require}")

    # -------------------------------------------------------------------------
    # Virtual Remote Token Mounting
    # -------------------------------------------------------------------------
    def mount_remote_peer(self, peer_id: str, cert_index: int = 0) -> bool:
        """Mount a remote LAN workstation's token as active on this PC."""
        with self._peers_lock:
            peer = self._peers.get(peer_id)
            if not peer or not peer.has_token:
                logger.warning(f"Cannot mount peer {peer_id}: Not found or has no token.")
                return False

        # Attempt to pull full certificate DER details via HTTP
        try:
            url = f"http://{peer.ip}:{peer.port}/api/lan/info"
            req = urllib.request.Request(url, headers={"User-Agent": f"DhanyahMesh/{APP_VERSION}"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("certificates"):
                    peer.certificates = [LanCertificateInfo.from_dict(c) for c in data.get("certificates", [])]
        except Exception as e:
            logger.debug(f"HTTP cert info fetch during mount: {e}")

        with self._peers_lock:
            self.mounted_peer = peer
            if peer.certificates and 0 <= cert_index < len(peer.certificates):
                self.mounted_cert = peer.certificates[cert_index]
            else:
                user_certs = [c for c in peer.certificates if not c.is_ca]
                self.mounted_cert = user_certs[0] if user_certs else (peer.certificates[0] if peer.certificates else None)

        logger.info(f"Mounted virtual remote token from {peer.display_name} ({peer.token_name})")
        return True

    def unmount_remote_peer(self):
        """Detach currently mounted virtual remote token."""
        self.mounted_peer = None
        self.mounted_cert = None
        logger.info("Unmounted virtual remote token.")

    # -------------------------------------------------------------------------
    # Manual Peer Connect (for VLANs or networks where UDP broadcast is disabled)
    # -------------------------------------------------------------------------
    def add_manual_peer(self, host: str, port: int = DEFAULT_LOOPBACK_PORT) -> Optional[LanPeer]:
        """Directly query a remote PC by IP or hostname and add as a peer."""
        try:
            url = f"http://{host}:{port}/api/lan/info"
            req = urllib.request.Request(url, headers={"User-Agent": f"DhanyahMesh/{APP_VERSION}"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            peer = LanPeer(
                peer_id=f"{data.get('hostname', host)}_{host}",
                hostname=data.get("hostname", host),
                ip=host,
                port=port,
                version=data.get("version", APP_VERSION),
                has_token=data.get("has_token", False),
                token_name=data.get("token_name", ""),
                token_id=data.get("token_id", ""),
                is_simulated=data.get("is_simulated", False),
                sharing_enabled=data.get("sharing_enabled", True),
                certificates=[LanCertificateInfo.from_dict(c) for c in data.get("certificates", [])],
                last_seen=time.time(),
                is_manual=True,
            )

            with self._peers_lock:
                self._peers[peer.peer_id] = peer

            self._notify_listeners()
            return peer
        except Exception as e:
            logger.warning(f"Could not connect to manual peer at {host}:{port}: {e}")
            return None

    # -------------------------------------------------------------------------
    # Remote Cryptographic Signing Client
    # -------------------------------------------------------------------------
    def sign_remote_hash(
        self,
        peer_ip: str,
        peer_port: int,
        pin: str,
        hash_hex: str,
        slot: int = 0,
        token_id: str = "",
        serial_hex: str = "",
        alias: str = "",
        algo: str = "SHA256",
    ) -> Dict[str, Any]:
        """
        Send a hash signature request to a remote workstation's Dhanyah instance.
        Returns response dict with 'success' and 'signature_hex' / 'signature_b64'.
        """
        url = f"http://{peer_ip}:{peer_port}/api/lan/sign"
        payload = json.dumps({
            "pin": pin,
            "hash_hex": hash_hex,
            "slot": slot,
            "token_id": token_id,
            "serial_hex": serial_hex,
            "alias": alias,
            "algo": algo,
            "client_hostname": self.hostname,
            "client_ip": self.local_ip,
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"DhanyahMeshClient/{APP_VERSION}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=20.0) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result
        except urllib.error.HTTPError as he:
            try:
                err_data = json.loads(he.read().decode("utf-8"))
                return err_data
            except Exception:
                return {"success": False, "error": f"HTTP {he.code}: {he.reason}"}
        except Exception as ex:
            return {"success": False, "error": f"Network error during remote sign: {ex}"}

    # -------------------------------------------------------------------------
    # Background UDP Broadcaster & Listener Workers
    # -------------------------------------------------------------------------
    def _broadcast_worker(self):
        """Periodically broadcast local token beacon to LAN UDP broadcast address."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(1.0)

        while self._running:
            try:
                # Refresh local IP
                self.local_ip = get_local_lan_ip()

                # Query local tokens
                tokens = []
                if hasattr(self, "get_local_tokens_fn") and self.get_local_tokens_fn:
                    tokens = [t for t in self.get_local_tokens_fn() if t]
                elif self.get_local_token_fn:
                    prim = self.get_local_token_fn()
                    if prim:
                        tokens = [prim]

                token = tokens[0] if tokens else None
                tok_names = " + ".join([t.name for t in tokens]) if tokens else ""
                certs = self.get_local_certs_fn() if self.get_local_certs_fn else []

                cert_payloads = []
                for c in certs:
                    if hasattr(c, "common_name"):
                        der_b64 = ""
                        if hasattr(c, "cert_der") and c.cert_der:
                            der_b64 = base64.b64encode(c.cert_der).decode("ascii")
                        cert_payloads.append({
                            "common_name": c.common_name,
                            "pan_number": getattr(c, "pan_number", ""),
                            "cert_class": getattr(c, "cert_class", "Class 3"),
                            "issuer": getattr(c, "issuer_cn", ""),
                            "valid_from": c.valid_from.isoformat() if hasattr(c, "valid_from") and c.valid_from else "",
                            "valid_to": c.valid_to.isoformat() if hasattr(c, "valid_to") and c.valid_to else "",
                            "serial_hex": getattr(c, "serial_number_hex", ""),
                            "token_name": getattr(c, "token_name", "") or (token.name if token else ""),
                            "token_id": getattr(c, "token_id", "") or (token.token_id if token else ""),
                            "slot": getattr(c, "slot", 0),
                            "is_ca": getattr(c, "is_ca", False),
                            "cert_der_b64": der_b64,
                        })

                beacon_data = {
                    "magic": LAN_BEACON_MAGIC,
                    "peer_id": f"{self.hostname}_{self.local_ip}",
                    "hostname": self.hostname,
                    "ip": self.local_ip,
                    "port": self.local_port,
                    "version": APP_VERSION,
                    "sharing_enabled": self.is_sharing_enabled,
                    "require_prompt": self.require_prompt_before_sign,
                    "has_token": bool(tokens),
                    "token_name": tok_names,
                    "token_id": token.token_id if token else "",
                    "tokens_count": len(tokens),
                    "is_simulated": any(getattr(t, "is_simulated", False) for t in tokens) if tokens else False,
                    "certificates": cert_payloads,
                    "timestamp": time.time(),
                }

                message = json.dumps(beacon_data).encode("utf-8")
                try:
                    sock.sendto(message, ("<broadcast>", self.broadcast_port))
                except Exception:
                    pass
                try:
                    sock.sendto(message, ("255.255.255.255", self.broadcast_port))
                except Exception:
                    pass
            except Exception as e:
                logger.debug(f"Broadcast beacon send warning: {e}")

            time.sleep(4.0)

        try:
            sock.close()
        except Exception:
            pass

    def _listen_worker(self):
        """Listen for UDP beacons from other Dhanyah workstations on LAN."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", self.broadcast_port))
        except Exception as e:
            logger.warning(f"Could not bind LAN Mesh UDP listener on port {self.broadcast_port}: {e}")
            return

        sock.settimeout(1.5)

        while self._running:
            try:
                data, addr = sock.recvfrom(65535)
                packet = json.loads(data.decode("utf-8"))

                # Validate magic string
                if packet.get("magic") != LAN_BEACON_MAGIC:
                    continue

                peer_ip = addr[0]
                peer_hostname = packet.get("hostname", "")

                # Ignore our own broadcast
                if peer_ip == self.local_ip and peer_hostname == self.hostname:
                    continue

                peer_id = packet.get("peer_id", f"{peer_hostname}_{peer_ip}")
                certs = [LanCertificateInfo.from_dict(c) for c in packet.get("certificates", [])]

                peer = LanPeer(
                    peer_id=peer_id,
                    hostname=peer_hostname,
                    ip=peer_ip,
                    port=packet.get("port", DEFAULT_LOOPBACK_PORT),
                    version=packet.get("version", APP_VERSION),
                    has_token=packet.get("has_token", False),
                    token_name=packet.get("token_name", ""),
                    token_id=packet.get("token_id", ""),
                    is_simulated=packet.get("is_simulated", False),
                    sharing_enabled=packet.get("sharing_enabled", True),
                    require_prompt=packet.get("require_prompt", False),
                    certificates=certs,
                    last_seen=time.time(),
                    is_manual=False,
                )

                has_changed = False
                with self._peers_lock:
                    prev = self._peers.get(peer_id)
                    if (
                        prev is None
                        or prev.has_token != peer.has_token
                        or len(prev.certificates) != len(peer.certificates)
                    ):
                        has_changed = True
                    self._peers[peer_id] = peer

                if has_changed:
                    logger.info(f"Discovered/Updated LAN Peer: {peer.display_name} (Token: {peer.token_name})")
                    self._notify_listeners()

            except socket.timeout:
                # Periodic purge & UI notification
                self.get_peers()
            except Exception as e:
                logger.debug(f"Packet receive notice: {e}")

        try:
            sock.close()
        except Exception:
            pass
