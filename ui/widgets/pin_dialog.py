"""
Dhanyah Crypto Utility - PIN Management Widget (Verify & Change Token PIN)
"""

from typing import List, Optional, Any
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QFrame,
    QMessageBox,
    QCheckBox,
    QComboBox,
    QScrollArea,
)

from core.pin_manager import PinManager, PinResult


class PinManagementWidget(QWidget):
    """Widget for safe PIN verification and PIN changes."""

    def __init__(self, pin_manager: PinManager, parent=None):
        super().__init__(parent)
        self.pin_mgr = pin_manager
        self._current_token_id = ""
        self._current_slot = 0
        self._is_simulated = False
        self._tokens: List[Any] = []
        self._init_ui()

    def set_token_context(
        self,
        token_id: str,
        slot: int = 0,
        is_simulated: bool = False,
        tokens: Optional[List[Any]] = None,
    ):
        self._current_token_id = token_id
        self._current_slot = slot
        self._is_simulated = is_simulated
        self._tokens = list(tokens) if tokens else []

        if len(self._tokens) > 1:
            self.token_bar.setVisible(True)
            self.combo_tokens.blockSignals(True)
            self.combo_tokens.clear()
            active_idx = 0
            for idx, t in enumerate(self._tokens):
                label = f"{t.name}  |  Slot: {t.reader_name}"
                self.combo_tokens.addItem(label, t)
                if t.token_id == token_id:
                    active_idx = idx
            self.combo_tokens.setCurrentIndex(active_idx)
            self.combo_tokens.blockSignals(False)
        else:
            self.token_bar.setVisible(False)

        has_token = bool(token_id)
        self.btn_verify.setEnabled(has_token)
        self.btn_change.setEnabled(has_token)
        if not has_token:
            self.lbl_verify_res.setText("Token not detected. Insert a token or enable Demo mode.")
            self.lbl_verify_res.setProperty("class", "BadgeWarning")
        else:
            self.lbl_verify_res.setText("Ready to verify token credentials.")
            self.lbl_verify_res.setProperty("class", "BadgeInfo")
        self.lbl_verify_res.setStyleSheet("")

    def _on_token_selected(self, index: int):
        token = self.combo_tokens.currentData()
        if token:
            self._current_token_id = token.token_id
            self._is_simulated = token.is_simulated
            target_slot = 0
            if not token.is_simulated and hasattr(self.pin_mgr, "pkcs11_mgr") and self.pin_mgr.pkcs11_mgr:
                slots = self.pin_mgr.pkcs11_mgr.get_slots_with_token(token.token_id)
                target_slot = slots[0] if slots else 0
            self._current_slot = target_slot
            self.lbl_verify_res.setText(f"Active PIN Target: {token.name} on slot {target_slot}")
            self.lbl_verify_res.setProperty("class", "BadgeInfo")
            self.lbl_verify_res.setStyleSheet("")

    def _init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(8)

        # Multi-Token selector bar (shown if 2+ tokens connected)
        self.token_bar = QFrame()
        self.token_bar.setVisible(False)
        tb_layout = QHBoxLayout(self.token_bar)
        tb_layout.setContentsMargins(12, 8, 12, 8)
        self.token_bar.setStyleSheet(
            "background-color: rgba(14, 165, 233, 0.08); border: 1px solid rgba(14, 165, 233, 0.3); border-radius: 6px;"
        )
        lbl_switch = QLabel("🔑 Select Target Hardware Token:")
        lbl_switch.setStyleSheet("font-weight: bold; color: #0284c7;")
        self.combo_tokens = QComboBox()
        self.combo_tokens.setMinimumHeight(30)
        self.combo_tokens.currentIndexChanged.connect(self._on_token_selected)
        tb_layout.addWidget(lbl_switch)
        tb_layout.addWidget(self.combo_tokens, 1)
        root_layout.addWidget(self.token_bar)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QHBoxLayout(content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(16)

        # Left Column: PIN Verification
        verify_card = QFrame()
        verify_card.setProperty("class", "CardFrame")
        v_layout = QVBoxLayout(verify_card)
        v_layout.setContentsMargins(18, 18, 18, 18)
        v_layout.setSpacing(12)

        lbl_v_title = QLabel("VERIFY TOKEN PIN")
        lbl_v_title.setProperty("class", "SectionTitle")
        v_layout.addWidget(lbl_v_title)

        lbl_v_desc = QLabel(
            "Test token communication and verify your User PIN without locking the hardware. "
            "Safe C_Login test."
        )
        lbl_v_desc.setWordWrap(True)
        lbl_v_desc.setProperty("class", "SubText")
        v_layout.addWidget(lbl_v_desc)

        lbl_v_pin = QLabel("User PIN:")
        lbl_v_pin.setProperty("class", "FieldLabel")
        v_layout.addWidget(lbl_v_pin)

        self.edit_verify_pin = QLineEdit()
        self.edit_verify_pin.setMinimumHeight(34)
        self.edit_verify_pin.setEchoMode(QLineEdit.Password)
        self.edit_verify_pin.setPlaceholderText("Enter token PIN (e.g. 12345678)")
        v_layout.addWidget(self.edit_verify_pin)

        self.chk_show_v = QCheckBox("Show PIN characters")
        self.chk_show_v.toggled.connect(
            lambda checked: self.edit_verify_pin.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        )
        v_layout.addWidget(self.chk_show_v)

        self.btn_verify = QPushButton("Verify PIN")
        self.btn_verify.setProperty("class", "PrimaryButton")
        self.btn_verify.setMinimumHeight(38)
        self.btn_verify.clicked.connect(self._on_verify_clicked)
        v_layout.addWidget(self.btn_verify)

        self.lbl_verify_res = QLabel("Ready.")
        self.lbl_verify_res.setProperty("class", "BadgeInfo")
        self.lbl_verify_res.setWordWrap(True)
        v_layout.addWidget(self.lbl_verify_res)

        v_layout.addStretch()

        # Warning Card Note
        warn_note = QFrame()
        warn_note.setProperty("class", "SubCardFrame")
        wn_layout = QVBoxLayout(warn_note)
        lbl_warn = QLabel(
            "⚠️ Safeguard Note: Indian FIPS L3 tokens typically lock after 15 consecutive incorrect PIN attempts. "
            "If you are unsure of the PIN, check with your DSC provider before retrying."
        )
        lbl_warn.setWordWrap(True)
        lbl_warn.setStyleSheet("color: #d97706; font-size: 11px; font-weight: 500;")
        wn_layout.addWidget(lbl_warn)
        v_layout.addWidget(warn_note)

        layout.addWidget(verify_card)

        # Right Column: PIN Change Utility
        change_card = QFrame()
        change_card.setProperty("class", "CardFrame")
        c_layout = QVBoxLayout(change_card)
        c_layout.setContentsMargins(18, 18, 18, 18)
        c_layout.setSpacing(12)

        lbl_c_title = QLabel("CHANGE TOKEN PIN")
        lbl_c_title.setProperty("class", "SectionTitle")
        c_layout.addWidget(lbl_c_title)

        lbl_c_desc = QLabel(
            "Update the User PIN for this crypto token using the standard PKCS#11 C_SetPIN interface."
        )
        lbl_c_desc.setWordWrap(True)
        lbl_c_desc.setProperty("class", "SubText")
        c_layout.addWidget(lbl_c_desc)

        # Inputs
        lbl_old = QLabel("Current (Old) PIN:")
        lbl_old.setProperty("class", "FieldLabel")
        c_layout.addWidget(lbl_old)

        self.edit_old_pin = QLineEdit()
        self.edit_old_pin.setMinimumHeight(34)
        self.edit_old_pin.setEchoMode(QLineEdit.Password)
        c_layout.addWidget(self.edit_old_pin)

        lbl_new = QLabel("New PIN (4-16 chars):")
        lbl_new.setProperty("class", "FieldLabel")
        c_layout.addWidget(lbl_new)

        self.edit_new_pin = QLineEdit()
        self.edit_new_pin.setMinimumHeight(34)
        self.edit_new_pin.setEchoMode(QLineEdit.Password)
        c_layout.addWidget(self.edit_new_pin)

        lbl_confirm = QLabel("Confirm New PIN:")
        lbl_confirm.setProperty("class", "FieldLabel")
        c_layout.addWidget(lbl_confirm)

        self.edit_confirm_pin = QLineEdit()
        self.edit_confirm_pin.setMinimumHeight(34)
        self.edit_confirm_pin.setEchoMode(QLineEdit.Password)
        c_layout.addWidget(self.edit_confirm_pin)

        self.chk_show_c = QCheckBox("Show PIN characters")
        self.chk_show_c.toggled.connect(self._toggle_change_visibility)
        c_layout.addWidget(self.chk_show_c)

        self.btn_change = QPushButton("Update Token PIN")
        self.btn_change.setProperty("class", "SuccessButton")
        self.btn_change.setMinimumHeight(38)
        self.btn_change.clicked.connect(self._on_change_clicked)
        c_layout.addWidget(self.btn_change)

        self.lbl_change_res = QLabel("PIN length must be 4 to 16 characters.")
        self.lbl_change_res.setProperty("class", "SubText")
        c_layout.addWidget(self.lbl_change_res)

        c_layout.addStretch()

        layout.addWidget(change_card)

        scroll.setWidget(content)
        root_layout.addWidget(scroll)

    def _toggle_change_visibility(self, checked: bool):
        mode = QLineEdit.Normal if checked else QLineEdit.Password
        self.edit_old_pin.setEchoMode(mode)
        self.edit_new_pin.setEchoMode(mode)
        self.edit_confirm_pin.setEchoMode(mode)

    def _on_verify_clicked(self):
        pin = self.edit_verify_pin.text()
        if not pin:
            QMessageBox.warning(self, "Input Required", "Please enter the Token PIN to verify.")
            return

        res: PinResult = self.pin_mgr.verify_pin(
            token_id=self._current_token_id,
            slot=self._current_slot,
            pin=pin,
            is_simulated=self._is_simulated,
        )

        self.lbl_verify_res.setText(res.message)
        if res.success:
            self.lbl_verify_res.setProperty("class", "BadgeValid")
        elif res.is_locked:
            self.lbl_verify_res.setProperty("class", "BadgeExpired")
        else:
            self.lbl_verify_res.setProperty("class", "BadgeWarning")
        self.lbl_verify_res.setStyleSheet("")

    def _on_change_clicked(self):
        old_pin = self.edit_old_pin.text()
        new_pin = self.edit_new_pin.text()
        confirm_pin = self.edit_confirm_pin.text()

        if not old_pin or not new_pin or not confirm_pin:
            QMessageBox.warning(self, "Input Required", "All PIN fields are required.")
            return

        if new_pin != confirm_pin:
            QMessageBox.warning(self, "Mismatch", "New PIN and Confirm PIN do not match.")
            return

        reply = QMessageBox.question(
            self,
            "Confirm PIN Change",
            f"Are you sure you want to change the Token PIN?\nMake sure you remember the new PIN!",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        res = self.pin_mgr.change_pin(
            token_id=self._current_token_id,
            slot=self._current_slot,
            old_pin=old_pin,
            new_pin=new_pin,
            confirm_pin=confirm_pin,
            is_simulated=self._is_simulated,
        )

        if res.success:
            QMessageBox.information(self, "PIN Changed", res.message)
            self.edit_old_pin.clear()
            self.edit_new_pin.clear()
            self.edit_confirm_pin.clear()
            self.lbl_change_res.setText("Token PIN successfully updated.")
            self.lbl_change_res.setProperty("class", "BadgeValid")
            self.lbl_change_res.setStyleSheet("")
        else:
            QMessageBox.critical(self, "PIN Change Error", res.message)
            self.lbl_change_res.setText(res.message)
            self.lbl_change_res.setProperty("class", "BadgeExpired")
            self.lbl_change_res.setStyleSheet("")
