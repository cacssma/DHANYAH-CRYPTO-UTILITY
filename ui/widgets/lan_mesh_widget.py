"""
Dhanyah Crypto Utility - Network DSC Mesh UI Widget
Enables discovering other LAN workstations running Dhanyah, inspecting remote tokens,
and mounting remote DSC certificates for seamless network-wide signing.
"""

import logging
from typing import List, Optional
from PySide6.QtCore import Qt, Signal, QObject, Slot
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QFrame,
    QScrollArea,
    QCheckBox,
    QInputDialog,
    QMessageBox,
)

from core.lan_mesh import LanMeshManager, LanPeer, LanCertificateInfo

logger = logging.getLogger("DhanyahCrypto.LanMeshUI")


class MeshSignalBridge(QObject):
    """Thread-safe signal bridge for background LAN discovery events."""
    peers_updated_signal = Signal(object)


class LanMeshWidget(QWidget):
    """Interactive GUI dashboard for discovering, sharing, and mounting remote LAN DSCs."""

    # Signal emitted when a virtual remote token is mounted or unmounted
    remote_token_mounted = Signal(object, object)  # (LanPeer, LanCertificateInfo or None)
    remote_token_unmounted = Signal()

    def __init__(self, mesh_mgr: LanMeshManager, parent=None):
        super().__init__(parent)
        self.mesh_mgr = mesh_mgr
        self._bridge = MeshSignalBridge()
        self._bridge.peers_updated_signal.connect(self._on_peers_updated_ui)

        # Wire background listener into bridge
        self.mesh_mgr.register_update_callback(
            lambda peers: self._bridge.peers_updated_signal.emit(peers)
        )

        self._init_ui()

    def _init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(12)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        self.main_layout = QVBoxLayout(content)
        self.main_layout.setContentsMargins(14, 14, 14, 14)
        self.main_layout.setSpacing(14)

        # -------------------------------------------------------------
        # CARD 1: Local Node Status & Sharing Policy
        # -------------------------------------------------------------
        node_card = QFrame()
        node_card.setProperty("class", "CardFrame")
        nc_layout = QVBoxLayout(node_card)
        nc_layout.setContentsMargins(16, 14, 16, 14)
        nc_layout.setSpacing(10)

        # Top row: title & network badge
        n_top = QHBoxLayout()
        lbl_mesh_title = QLabel("DHANYAH LOCAL NETWORK (LAN) DSC MESH")
        lbl_mesh_title.setProperty("class", "SectionTitle")
        n_top.addWidget(lbl_mesh_title)
        n_top.addStretch()

        self.lbl_badge_status = QLabel("MESH ACTIVE (UDP: 18205)")
        self.lbl_badge_status.setProperty("class", "BadgeValid")
        n_top.addWidget(self.lbl_badge_status)
        nc_layout.addLayout(n_top)

        # Workstation info line
        self.lbl_node_info = QLabel(
            f"This Computer: <b>{self.mesh_mgr.hostname}</b>  |  LAN IP: <b>{self.mesh_mgr.local_ip}</b>  |  Port: <b>{self.mesh_mgr.local_port}</b>"
        )
        self.lbl_node_info.setProperty("class", "SubText")
        nc_layout.addWidget(self.lbl_node_info)

        lbl_desc = QLabel(
            "Share plugged-in crypto tokens across all computers in your office over Wi-Fi or Ethernet. "
            "Staff members can sign via browser portals (MCA, GST, Income Tax), emSigner, and emBridge "
            "without physically unplugging or passing USB dongles around."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setProperty("class", "SubText")
        nc_layout.addWidget(lbl_desc)

        # Policy Controls Row
        opts_row = QHBoxLayout()
        opts_row.setSpacing(20)

        self.chk_share = QCheckBox("Share my connected tokens on Local Network")
        self.chk_share.setChecked(self.mesh_mgr.is_sharing_enabled)
        self.chk_share.setProperty("class", "FieldLabel")
        self.chk_share.toggled.connect(self._on_share_toggled)
        opts_row.addWidget(self.chk_share)

        self.chk_prompt = QCheckBox("Require security prompt before remote signing")
        self.chk_prompt.setChecked(self.mesh_mgr.require_prompt_before_sign)
        self.chk_prompt.setProperty("class", "FieldLabel")
        self.chk_prompt.toggled.connect(self._on_prompt_toggled)
        opts_row.addWidget(self.chk_prompt)

        opts_row.addStretch()

        btn_rescan = QPushButton("🔄 Rescan LAN")
        btn_rescan.setMinimumHeight(32)
        btn_rescan.clicked.connect(self._rescan_peers)
        opts_row.addWidget(btn_rescan)

        btn_manual = QPushButton("➕ Add PC by IP...")
        btn_manual.setMinimumHeight(32)
        btn_manual.clicked.connect(self._prompt_manual_ip)
        opts_row.addWidget(btn_manual)

        nc_layout.addLayout(opts_row)
        self.main_layout.addWidget(node_card)

        # -------------------------------------------------------------
        # CARD 2: Active Mounted Virtual Token Banner (conditional)
        # -------------------------------------------------------------
        self.mount_banner = QFrame()
        self.mount_banner.setProperty("class", "CardFrame")
        mb_layout = QHBoxLayout(self.mount_banner)
        mb_layout.setContentsMargins(16, 12, 16, 12)

        icon_lbl = QLabel("🌐")
        icon_lbl.setStyleSheet("font-size: 24px;")
        mb_layout.addWidget(icon_lbl)

        mb_text_box = QVBoxLayout()
        self.lbl_mounted_title = QLabel("ACTIVE VIRTUAL REMOTE TOKEN")
        self.lbl_mounted_title.setProperty("class", "DeviceHighlight")
        self.lbl_mounted_desc = QLabel("No remote token mounted.")
        self.lbl_mounted_desc.setProperty("class", "SubText")
        mb_text_box.addWidget(self.lbl_mounted_title)
        mb_text_box.addWidget(self.lbl_mounted_desc)
        mb_layout.addLayout(mb_text_box)

        mb_layout.addStretch()

        self.btn_unmount = QPushButton("❌ Detach / Unmount Token")
        self.btn_unmount.setProperty("class", "DangerButton")
        self.btn_unmount.setMinimumHeight(34)
        self.btn_unmount.clicked.connect(self._unmount_current)
        mb_layout.addWidget(self.btn_unmount)

        self.mount_banner.setVisible(False)
        self.main_layout.addWidget(self.mount_banner)

        # -------------------------------------------------------------
        # CARD 3: Discovered LAN Workstations Container
        # -------------------------------------------------------------
        peers_card = QFrame()
        peers_card.setProperty("class", "CardFrame")
        self.pc_layout = QVBoxLayout(peers_card)
        self.pc_layout.setContentsMargins(16, 16, 16, 16)
        self.pc_layout.setSpacing(12)

        lbl_peers_title = QLabel("DISCOVERED WORKSTATIONS & REMOTE DSC TOKENS")
        lbl_peers_title.setProperty("class", "CardTitle")
        self.pc_layout.addWidget(lbl_peers_title)

        # Placeholder label when no peers are visible
        self.lbl_no_peers = QLabel(
            "Searching local network for workstations running Dhanyah Crypto Utility...\n\n"
            "• Ensure Dhanyah is installed and running on other PCs on the same Wi-Fi or Ethernet LAN.\n"
            "• If your office uses separated subnets or corporate VLANs, use 'Add PC by IP' above to connect directly."
        )
        self.lbl_no_peers.setProperty("class", "EmptyPlaceholder")
        self.lbl_no_peers.setAlignment(Qt.AlignCenter)
        self.pc_layout.addWidget(self.lbl_no_peers)

        # Container for dynamic peer cards
        self.peer_cards_container = QVBoxLayout()
        self.peer_cards_container.setSpacing(10)
        self.pc_layout.addLayout(self.peer_cards_container)

        self.main_layout.addWidget(peers_card)
        self.main_layout.addStretch()

        scroll.setWidget(content)
        root_layout.addWidget(scroll)

        # Initial render
        self._refresh_peer_cards()

    # -------------------------------------------------------------------------
    # UI Event Handlers
    # -------------------------------------------------------------------------
    def _on_share_toggled(self, checked: bool):
        self.mesh_mgr.set_sharing_enabled(checked)
        if checked:
            self.lbl_badge_status.setText("MESH ACTIVE (UDP: 18205)")
            self.lbl_badge_status.setProperty("class", "BadgeValid")
        else:
            self.lbl_badge_status.setText("SHARING PAUSED")
            self.lbl_badge_status.setProperty("class", "BadgeWarning")
        self.lbl_badge_status.setStyleSheet("")

    def _on_prompt_toggled(self, checked: bool):
        self.mesh_mgr.set_require_prompt(checked)

    def _rescan_peers(self):
        peers = self.mesh_mgr.get_peers()
        self._render_peer_cards(peers)

    def _prompt_manual_ip(self):
        ip_str, ok = QInputDialog.getText(
            self,
            "Connect Remote Workstation",
            "Enter the IP address or Hostname of the remote PC running Dhanyah:\n(e.g. 192.168.1.50 or DESKTOP-PC)",
        )
        if ok and ip_str.strip():
            target = ip_str.strip()
            peer = self.mesh_mgr.add_manual_peer(target)
            if peer:
                QMessageBox.information(
                    self,
                    "Connection Successful",
                    f"Successfully connected to {peer.display_name}!\n"
                    f"Hardware Token: {peer.token_name or 'None plugged in'}\n"
                    f"Certificates Found: {len(peer.certificates)}",
                )
            else:
                QMessageBox.warning(
                    self,
                    "Connection Failed",
                    f"Could not reach Dhanyah Crypto Utility at {target}:{self.mesh_mgr.local_port}.\n\n"
                    "Please verify:\n1. Dhanyah is running on the remote PC.\n2. Windows Firewall allows port 18200.",
                )

    @Slot(object)
    def _on_peers_updated_ui(self, peers: List[LanPeer]):
        self._render_peer_cards(peers)

    def _render_peer_cards(self, peers: List[LanPeer]):
        # Clean previous items
        while self.peer_cards_container.count():
            item = self.peer_cards_container.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        if not peers:
            self.lbl_no_peers.setVisible(True)
            return

        self.lbl_no_peers.setVisible(False)

        for peer in peers:
            card = QFrame()
            card.setProperty("class", "SubCardFrame")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(14, 12, 14, 12)
            card_layout.setSpacing(8)

            # Header row
            head_row = QHBoxLayout()
            lbl_name = QLabel(f"💻  {peer.hostname}")
            lbl_name.setProperty("class", "SectionTitle")
            head_row.addWidget(lbl_name)

            lbl_ip = QLabel(f"{peer.ip}:{peer.port}")
            lbl_ip.setProperty("class", "TechCode")
            head_row.addWidget(lbl_ip)

            head_row.addStretch()

            status_text = "● ONLINE" if peer.is_online else "OFFLINE"
            lbl_stat = QLabel(status_text)
            lbl_stat.setProperty("class", "BadgeValid" if peer.is_online else "BadgeExpired")
            head_row.addWidget(lbl_stat)
            card_layout.addLayout(head_row)

            # Token row
            token_box = QHBoxLayout()
            token_title = f"🛡️ Hardware Token: {peer.token_name}" if peer.has_token else "⚪ No Hardware Token Inserted"
            lbl_token = QLabel(token_title)
            lbl_token.setProperty("class", "FieldLabel" if peer.has_token else "SubText")
            token_box.addWidget(lbl_token)
            token_box.addStretch()

            if not peer.sharing_enabled:
                lbl_shared = QLabel("Sharing Disabled by Host")
                lbl_shared.setProperty("class", "BadgeWarning")
                token_box.addWidget(lbl_shared)

            card_layout.addLayout(token_box)

            # Certificates listing
            if peer.has_token and peer.certificates:
                for idx, c in enumerate(peer.certificates):
                    cert_frame = QFrame()
                    cert_frame.setStyleSheet("background-color: transparent; border-top: 1px solid #334155; padding-top: 6px;")
                    cf_layout = QHBoxLayout(cert_frame)
                    cf_layout.setContentsMargins(0, 4, 0, 0)

                    c_info = QVBoxLayout()
                    pan_str = f" [PAN: {c.pan_number}]" if c.pan_number else ""
                    lbl_c_name = QLabel(f"<b>{c.common_name}</b> ({c.cert_class}){pan_str}")
                    lbl_c_name.setProperty("class", "ValueText")
                    lbl_c_exp = QLabel(f"Issued by: {c.issuer} | Valid to: {c.valid_to[:10] if c.valid_to else 'N/A'}")
                    lbl_c_exp.setProperty("class", "SubText")
                    c_info.addWidget(lbl_c_name)
                    c_info.addWidget(lbl_c_exp)
                    cf_layout.addLayout(c_info)

                    cf_layout.addStretch()

                    # Check if this peer is currently mounted
                    is_this_mounted = (
                        self.mesh_mgr.mounted_peer
                        and self.mesh_mgr.mounted_peer.peer_id == peer.peer_id
                        and self.mesh_mgr.mounted_cert
                        and self.mesh_mgr.mounted_cert.common_name == c.common_name
                    )

                    if is_this_mounted:
                        btn_mount = QPushButton("✔ ACTIVE MOUNTED")
                        btn_mount.setProperty("class", "SuccessButton")
                        btn_mount.setEnabled(False)
                        btn_mount.setMinimumHeight(32)
                        cf_layout.addWidget(btn_mount)
                    else:
                        btn_mount = QPushButton("⚡ Mount for Signing on this PC")
                        btn_mount.setProperty("class", "PrimaryButton")
                        btn_mount.setMinimumHeight(32)
                        btn_mount.clicked.connect(
                            lambda _=False, p_id=peer.peer_id, c_idx=idx: self._mount_peer_token(p_id, c_idx)
                        )
                        cf_layout.addWidget(btn_mount)

                    card_layout.addWidget(cert_frame)

            self.peer_cards_container.addWidget(card)

    def _mount_peer_token(self, peer_id: str, cert_index: int):
        ok = self.mesh_mgr.mount_remote_peer(peer_id, cert_index)
        if ok and self.mesh_mgr.mounted_peer:
            peer = self.mesh_mgr.mounted_peer
            cert = self.mesh_mgr.mounted_cert
            self._update_mount_banner()
            self._render_peer_cards(self.mesh_mgr.get_peers())

            # Emit signal to update MainWindow, Banner, and Signer
            self.remote_token_mounted.emit(peer, cert)

            pan_msg = f"\nPAN Number: {cert.pan_number}" if cert and cert.pan_number else ""
            QMessageBox.information(
                self,
                "Remote Token Mounted",
                f"Successfully mounted remote token from:\n{peer.display_name}\n\n"
                f"Signer: {cert.common_name if cert else peer.token_name}{pan_msg}\n\n"
                f"• Built-in PDF Document Signer will now use this remote token.\n"
                f"• emSigner, emBridge, and government web portals (MCA, GST, ITD) will sign using this token via local loopback.",
            )

    def _unmount_current(self):
        self.mesh_mgr.unmount_remote_peer()
        self._update_mount_banner()
        self._render_peer_cards(self.mesh_mgr.get_peers())
        self.remote_token_unmounted.emit()
        QMessageBox.information(
            self,
            "Token Unmounted",
            "Remote virtual token has been detached. Dhanyah is now ready for local physical USB tokens.",
        )

    def _update_mount_banner(self):
        if self.mesh_mgr.mounted_peer:
            peer = self.mesh_mgr.mounted_peer
            cert = self.mesh_mgr.mounted_cert
            cert_name = cert.common_name if cert else peer.token_name
            pan_str = f" [PAN: {cert.pan_number}]" if cert and cert.pan_number else ""
            self.lbl_mounted_title.setText(f"ACTIVE VIRTUAL TOKEN: {cert_name}{pan_str}")
            self.lbl_mounted_desc.setText(
                f"Mounted from <b>{peer.display_name}</b> ({peer.token_name}). "
                f"All local applications, emSigner, emBridge, and PDF Signer will sign via this remote token over LAN."
            )
            self.mount_banner.setVisible(True)
        else:
            self.mount_banner.setVisible(False)

    def _refresh_peer_cards(self):
        self._update_mount_banner()
        self._render_peer_cards(self.mesh_mgr.get_peers())
