"""
Dhanyah Crypto Utility - Modern Professional QSS Theme & Stylesheet System
Provides curated Enterprise Dark Mode and a Stunning, High-Contrast Light Mode
tailored specifically for cryptographic security desktop applications.
"""

DARK_THEME_QSS = """
/* Global Window & Typography (Dark Mode) */
QMainWindow, QDialog, QWidget {
    background-color: #0f172a;
    color: #f1f5f9;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
}

/* Sidebar & Navigation */
QListWidget#SidebarList {
    background-color: #1e293b;
    border: none;
    border-right: 1px solid #334155;
    padding-top: 12px;
    font-size: 14px;
    font-weight: 500;
}

QListWidget#SidebarList::item {
    height: 48px;
    padding-left: 18px;
    margin: 4px 10px;
    border-radius: 8px;
    color: #94a3b8;
}

QListWidget#SidebarList::item:hover {
    background-color: #334155;
    color: #f8fafc;
}

QListWidget#SidebarList::item:selected {
    background-color: #2563eb;
    color: #ffffff;
    font-weight: 600;
}

/* Cards & Containers */
QFrame.CardFrame {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 12px;
}

QFrame.SubCardFrame {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 12px;
}

/* Typography Hierarchy */
QLabel.HeaderTitle {
    font-size: 16px;
    font-weight: 800;
    color: #ffffff;
    letter-spacing: 0.5px;
}

QLabel.SectionTitle {
    font-size: 14px;
    font-weight: 700;
    color: #ffffff;
}

QLabel.CardTitle {
    font-size: 11px;
    font-weight: 700;
    color: #94a3b8;
    letter-spacing: 1px;
}

QLabel.DeviceHighlight {
    font-size: 15px;
    font-weight: 700;
    color: #38bdf8;
}

QLabel.FieldLabel {
    color: #cbd5e1;
    font-weight: 600;
    font-size: 12px;
}

QLabel.ValueText {
    color: #f1f5f9;
    font-weight: 500;
    font-size: 12px;
}

QLabel.SubText {
    font-size: 12px;
    color: #94a3b8;
}

QLabel.TechCode {
    color: #38bdf8;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 11px;
}

QLabel.EmptyPlaceholder {
    color: #64748b;
    font-size: 13px;
    padding: 24px;
}

/* Status Badges */
QLabel.BadgeValid {
    background-color: #064e3b;
    color: #34d399;
    border: 1px solid #059669;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 600;
}

QLabel.BadgeWarning {
    background-color: #78350f;
    color: #fcd34d;
    border: 1px solid #d97706;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 600;
}

QLabel.BadgeExpired {
    background-color: #7f1d1d;
    color: #fca5a5;
    border: 1px solid #dc2626;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 600;
}

QLabel.BadgeInfo {
    background-color: #1e3a8a;
    color: #93c5fd;
    border: 1px solid #2563eb;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 600;
}

/* Primary and Action Buttons */
QPushButton {
    background-color: #334155;
    color: #f8fafc;
    border: 1px solid #475569;
    border-radius: 6px;
    padding: 7px 16px;
    font-weight: 500;
    min-height: 20px;
}

QPushButton:hover {
    background-color: #475569;
    border-color: #64748b;
}

QPushButton:pressed {
    background-color: #1e293b;
}

QPushButton:disabled {
    background-color: #1e293b;
    color: #64748b;
    border-color: #334155;
}

QPushButton.PrimaryButton {
    background-color: #2563eb;
    color: #ffffff;
    border: 1px solid #3b82f6;
    font-weight: 600;
}

QPushButton.PrimaryButton:hover {
    background-color: #1d4ed8;
    border-color: #60a5fa;
}

QPushButton.PrimaryButton:pressed {
    background-color: #1e40af;
}

QPushButton.SuccessButton {
    background-color: #059669;
    color: #ffffff;
    border: 1px solid #10b981;
    font-weight: 600;
}

QPushButton.SuccessButton:hover {
    background-color: #047857;
}

QPushButton.DangerButton {
    background-color: #dc2626;
    color: #ffffff;
    border: 1px solid #ef4444;
    font-weight: 600;
}

QPushButton.DangerButton:hover {
    background-color: #b91c1c;
}

/* Form Inputs */
QLineEdit, QComboBox, QTextEdit, QPlainTextEdit, QSpinBox {
    background-color: #0f172a;
    border: 1px solid #475569;
    border-radius: 6px;
    color: #f8fafc;
    padding: 6px 12px;
    font-size: 13px;
    min-height: 24px;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}

QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border: 1px solid #38bdf8;
    background-color: #111e38;
}

QComboBox::drop-down {
    border: none;
    padding-right: 8px;
}

QComboBox QAbstractItemView {
    background-color: #1e293b;
    color: #f8fafc;
    border: 1px solid #334155;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}

/* Checkboxes */
QCheckBox {
    color: #f1f5f9;
    font-size: 12px;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid #475569;
    background-color: #0f172a;
}

QCheckBox::indicator:checked {
    background-color: #2563eb;
    border-color: #3b82f6;
}

/* Tables */
QTableWidget {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    gridline-color: #334155;
    color: #f8fafc;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}

QTableWidget::item:selected {
    background-color: #2563eb;
    color: #ffffff;
}

QHeaderView::section {
    background-color: #0f172a;
    color: #94a3b8;
    font-weight: 600;
    padding: 8px;
    border: none;
    border-bottom: 2px solid #334155;
    border-right: 1px solid #1e293b;
}

/* Status Bar */
QStatusBar {
    background-color: #0f172a;
    border-top: 1px solid #334155;
    color: #94a3b8;
    font-size: 12px;
}

/* ScrollBars */
QScrollBar:vertical {
    border: none;
    background-color: #0f172a;
    width: 8px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background-color: #334155;
    min-height: 20px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background-color: #475569;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    border: none;
    background-color: #0f172a;
    height: 8px;
    margin: 0px;
}

QScrollBar::handle:horizontal {
    background-color: #334155;
    min-width: 20px;
    border-radius: 4px;
}

/* Tab Widget */
QTabWidget::pane {
    border: 1px solid #334155;
    border-radius: 8px;
    background-color: #1e293b;
    padding: 4px;
}

QTabBar::tab {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 8px 16px;
    margin-right: 4px;
    color: #94a3b8;
}

QTabBar::tab:selected {
    background-color: #1e293b;
    color: #38bdf8;
    border-bottom: 2px solid #38bdf8;
    font-weight: 600;
}

/* Menus & Tooltips */
QMenu {
    background-color: #1e293b;
    color: #f8fafc;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 4px 0px;
}

QMenu::item {
    padding: 6px 24px;
}

QMenu::item:selected {
    background-color: #2563eb;
    color: #ffffff;
}

QMenu::separator {
    height: 1px;
    background: #334155;
    margin: 4px 8px;
}

QToolTip {
    background-color: #1e293b;
    color: #ffffff;
    border: 1px solid #475569;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}
"""

LIGHT_THEME_QSS = """
/* Global Window & Typography (Curated Enterprise Light Mode) */
QMainWindow, QDialog, QWidget {
    background-color: #f8fafc;
    color: #0f172a;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
}

/* Sidebar & Navigation */
QListWidget#SidebarList {
    background-color: #ffffff;
    border: none;
    border-right: 1px solid #e2e8f0;
    padding-top: 12px;
    font-size: 14px;
    font-weight: 500;
}

QListWidget#SidebarList::item {
    height: 48px;
    padding-left: 18px;
    margin: 4px 10px;
    border-radius: 8px;
    color: #475569;
}

QListWidget#SidebarList::item:hover {
    background-color: #f1f5f9;
    color: #0f172a;
}

QListWidget#SidebarList::item:selected {
    background-color: #2563eb;
    color: #ffffff;
    font-weight: 600;
}

/* Cards & Containers */
QFrame.CardFrame {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 12px;
}

QFrame.SubCardFrame {
    background-color: #f1f5f9;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    padding: 12px;
}

/* Typography Hierarchy */
QLabel.HeaderTitle {
    font-size: 16px;
    font-weight: 800;
    color: #0f172a;
    letter-spacing: 0.5px;
}

QLabel.SectionTitle {
    font-size: 14px;
    font-weight: 700;
    color: #0f172a;
}

QLabel.CardTitle {
    font-size: 11px;
    font-weight: 700;
    color: #475569;
    letter-spacing: 1px;
}

QLabel.DeviceHighlight {
    font-size: 15px;
    font-weight: 700;
    color: #0284c7;
}

QLabel.FieldLabel {
    color: #334155;
    font-weight: 600;
    font-size: 12px;
}

QLabel.ValueText {
    color: #0f172a;
    font-weight: 500;
    font-size: 12px;
}

QLabel.SubText {
    font-size: 12px;
    color: #64748b;
}

QLabel.TechCode {
    color: #0369a1;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 11px;
}

QLabel.EmptyPlaceholder {
    color: #64748b;
    font-size: 13px;
    padding: 24px;
}

/* Status Badges - High contrast, accessible for Light theme */
QLabel.BadgeValid {
    background-color: #dcfce7;
    color: #15803d;
    border: 1px solid #86efac;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 600;
}

QLabel.BadgeWarning {
    background-color: #fef3c7;
    color: #b45309;
    border: 1px solid #fcd34d;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 600;
}

QLabel.BadgeExpired {
    background-color: #fee2e2;
    color: #b91c1c;
    border: 1px solid #fca5a5;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 600;
}

QLabel.BadgeInfo {
    background-color: #e0f2fe;
    color: #0369a1;
    border: 1px solid #7dd3fc;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 600;
}

/* Primary and Action Buttons */
QPushButton {
    background-color: #ffffff;
    color: #1e293b;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 7px 16px;
    font-weight: 500;
    min-height: 20px;
}

QPushButton:hover {
    background-color: #f1f5f9;
    border-color: #94a3b8;
}

QPushButton:pressed {
    background-color: #e2e8f0;
}

QPushButton:disabled {
    background-color: #f8fafc;
    color: #94a3b8;
    border-color: #e2e8f0;
}

QPushButton.PrimaryButton {
    background-color: #2563eb;
    color: #ffffff;
    border: 1px solid #1d4ed8;
    font-weight: 600;
}

QPushButton.PrimaryButton:hover {
    background-color: #1d4ed8;
    border-color: #1e40af;
}

QPushButton.PrimaryButton:pressed {
    background-color: #1e40af;
}

QPushButton.SuccessButton {
    background-color: #059669;
    color: #ffffff;
    border: 1px solid #047857;
    font-weight: 600;
}

QPushButton.SuccessButton:hover {
    background-color: #047857;
}

QPushButton.DangerButton {
    background-color: #dc2626;
    color: #ffffff;
    border: 1px solid #b91c1c;
    font-weight: 600;
}

QPushButton.DangerButton:hover {
    background-color: #b91c1c;
}

/* Form Inputs */
QLineEdit, QComboBox, QTextEdit, QPlainTextEdit, QSpinBox {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    color: #0f172a;
    padding: 6px 12px;
    font-size: 13px;
    min-height: 24px;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}

QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border: 1px solid #2563eb;
    background-color: #ffffff;
}

QComboBox::drop-down {
    border: none;
    padding-right: 8px;
}

QComboBox QAbstractItemView {
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}

/* Checkboxes */
QCheckBox {
    color: #0f172a;
    font-size: 12px;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid #cbd5e1;
    background-color: #ffffff;
}

QCheckBox::indicator:checked {
    background-color: #2563eb;
    border-color: #1d4ed8;
}

/* Tables */
QTableWidget {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    gridline-color: #f1f5f9;
    color: #0f172a;
    selection-background-color: #dbeafe;
    selection-color: #1e3a8a;
}

QTableWidget::item:selected {
    background-color: #dbeafe;
    color: #1e3a8a;
}

QHeaderView::section {
    background-color: #f1f5f9;
    color: #334155;
    font-weight: 600;
    padding: 8px;
    border: none;
    border-bottom: 2px solid #cbd5e1;
    border-right: 1px solid #e2e8f0;
}

/* Status Bar */
QStatusBar {
    background-color: #ffffff;
    border-top: 1px solid #e2e8f0;
    color: #475569;
    font-size: 12px;
}

/* ScrollBars */
QScrollBar:vertical {
    border: none;
    background-color: #f1f5f9;
    width: 8px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background-color: #cbd5e1;
    min-height: 20px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background-color: #94a3b8;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    border: none;
    background-color: #f1f5f9;
    height: 8px;
    margin: 0px;
}

QScrollBar::handle:horizontal {
    background-color: #cbd5e1;
    min-width: 20px;
    border-radius: 4px;
}

/* Tab Widget */
QTabWidget::pane {
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    background-color: #ffffff;
    padding: 4px;
}

QTabBar::tab {
    background-color: #f1f5f9;
    border: 1px solid #e2e8f0;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 8px 16px;
    margin-right: 4px;
    color: #475569;
}

QTabBar::tab:selected {
    background-color: #ffffff;
    color: #2563eb;
    border-bottom: 2px solid #2563eb;
    font-weight: 600;
}

/* Menus & Tooltips */
QMenu {
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 4px 0px;
}

QMenu::item {
    padding: 6px 24px;
}

QMenu::item:selected {
    background-color: #2563eb;
    color: #ffffff;
}

QMenu::separator {
    height: 1px;
    background: #e2e8f0;
    margin: 4px 8px;
}

QToolTip {
    background-color: #0f172a;
    color: #ffffff;
    border: 1px solid #0f172a;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}
"""


def get_theme_qss(is_dark_mode: bool) -> str:
    """Returns the QSS stylesheet for the selected theme mode."""
    return DARK_THEME_QSS if is_dark_mode else LIGHT_THEME_QSS


def get_log_console_style(is_dark_mode: bool) -> str:
    """Returns styling for the live request stream log box."""
    if is_dark_mode:
        return (
            "font-family: 'Consolas', 'Courier New', monospace; "
            "font-size: 11px; "
            "background-color: #0b1120; "
            "color: #f1f5f9; "
            "border: 1px solid #334155; "
            "border-radius: 6px; "
            "padding: 6px;"
        )
    else:
        return (
            "font-family: 'Consolas', 'Courier New', monospace; "
            "font-size: 11px; "
            "background-color: #ffffff; "
            "color: #0f172a; "
            "border: 1px solid #cbd5e1; "
            "border-radius: 6px; "
            "padding: 6px;"
        )


def get_status_pill_style(state: str, is_dark_mode: bool) -> str:
    """
    Returns high-contrast background & foreground colors for dynamically styled pills.
    state: 'active' | 'simulation' | 'empty'
    """
    if state == "active":
        if is_dark_mode:
            return "background-color: #16a34a; color: #ffffff; padding: 4px 10px; border-radius: 10px; font-weight: bold;"
        else:
            return "background-color: #dcfce7; color: #15803d; border: 1px solid #86efac; padding: 4px 10px; border-radius: 10px; font-weight: bold;"
    elif state == "simulation":
        if is_dark_mode:
            return "background-color: #0284c7; color: #ffffff; padding: 4px 10px; border-radius: 10px; font-weight: bold;"
        else:
            return "background-color: #e0f2fe; color: #0369a1; border: 1px solid #7dd3fc; padding: 4px 10px; border-radius: 10px; font-weight: bold;"
    else:
        return ""
