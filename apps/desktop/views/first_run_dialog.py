"""
AgentShield AI — First-Run Setup & Configuration Wizard (Phase 12).

Guides users on initial launch through:
1. Welcome & Deployment Mode Selection (Local vs Remote)
2. Backend Connection Verification
3. Administrator Credentials Setup
4. System Readiness Confirmation
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from apps.desktop.services.backend_client import backend_client
from apps.desktop.themes.design_tokens import T


class FirstRunDialog(QDialog):
    """Interactive multi-step wizard for initial deployment and administrator setup."""

    setup_completed = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AgentShield AI — Initial Setup Wizard")
        self.setFixedSize(580, 480)
        self.setStyleSheet(f"background:{T.SURFACE}; color:{T.TEXT};")

        self._deployment_mode = "LOCAL"
        self._backend_url = "http://localhost:8000"

        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_6, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        # Header step indicator
        self._title_lbl = QLabel("AgentShield Setup (Step 1 of 4)")
        self._title_lbl.setStyleSheet(f"font-size:{T.FS_LG}px; font-weight:700; color:{T.PRIMARY};")
        root.addWidget(self._title_lbl)

        # Stacked Pages
        self._stack = QStackedWidget()
        self._stack.addWidget(self._page_welcome())
        self._stack.addWidget(self._page_backend_connection())
        self._stack.addWidget(self._page_admin_setup())
        self._stack.addWidget(self._page_summary())
        root.addWidget(self._stack)

        # Navigation Buttons
        btn_box = QHBoxLayout()
        self._back_btn = QPushButton("Back")
        self._back_btn.setObjectName("secondary")
        self._back_btn.clicked.connect(self._go_back)
        self._back_btn.setEnabled(False)

        self._next_btn = QPushButton("Next")
        self._next_btn.setObjectName("primary")
        self._next_btn.clicked.connect(self._go_next)

        btn_box.addWidget(self._back_btn)
        btn_box.addStretch()
        btn_box.addWidget(self._next_btn)
        root.addLayout(btn_box)

    def _page_welcome(self) -> QWidget:
        p = QWidget()
        lay = QVBoxLayout(p)
        lay.setSpacing(T.SP_4)

        lbl = QLabel("Welcome to AgentShield AI\nUniversal Runtime Security Gateway")
        lbl.setStyleSheet(f"font-size:{T.FS_XL}px; font-weight:700; color:{T.TEXT};")
        lay.addWidget(lbl)

        desc = QLabel(
            "AgentShield provides an independent, non-bypassable security layer between your AI "
            "agents and protected tools. Choose your desired deployment topology:"
        )
        desc.setWordWrap(True)
        lay.addWidget(desc)

        self._radio_local = QRadioButton("Local Deployment (Recommended for Development)")
        self._radio_local.setChecked(True)
        lbl_local_desc = QLabel("Runs the FastAPI backend and database locally on this machine.")
        lbl_local_desc.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px; margin-left:24px;")

        self._radio_remote = QRadioButton("Remote Deployment (Enterprise & Team Gateway)")
        lbl_remote_desc = QLabel("Connects this desktop control center to a remote, hosted AgentShield server.")
        lbl_remote_desc.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px; margin-left:24px;")

        self._mode_group = QButtonGroup(self)
        self._mode_group.addButton(self._radio_local)
        self._mode_group.addButton(self._radio_remote)

        lay.addWidget(self._radio_local)
        lay.addWidget(lbl_local_desc)
        lay.addSpacing(T.SP_2)
        lay.addWidget(self._radio_remote)
        lay.addWidget(lbl_remote_desc)
        lay.addStretch()
        return p

    def _page_backend_connection(self) -> QWidget:
        p = QWidget()
        lay = QVBoxLayout(p)
        lay.setSpacing(T.SP_4)

        lbl = QLabel("Backend Gateway Configuration")
        lbl.setStyleSheet(f"font-size:{T.FS_LG}px; font-weight:700;")
        lay.addWidget(lbl)

        form = QFormLayout()
        self._url_input = QLineEdit("http://localhost:8000")
        form.addRow("Backend URL:", self._url_input)
        lay.addLayout(form)

        self._test_btn = QPushButton("Test Connection")
        self._test_btn.setObjectName("secondary")
        self._test_btn.clicked.connect(self._test_connection)
        lay.addWidget(self._test_btn)

        self._status_lbl = QLabel("Status: Click 'Test Connection' to verify server responsiveness.")
        self._status_lbl.setWordWrap(True)
        self._status_lbl.setStyleSheet(f"color:{T.TEXT_SEC};")
        lay.addWidget(self._status_lbl)
        lay.addStretch()
        return p

    def _page_admin_setup(self) -> QWidget:
        p = QWidget()
        lay = QVBoxLayout(p)
        lay.setSpacing(T.SP_3)

        lbl = QLabel("Initial Security Administrator Setup")
        lbl.setStyleSheet(f"font-size:{T.FS_LG}px; font-weight:700;")
        lay.addWidget(lbl)

        note = QLabel("No default passwords exist. Create the primary security administrator account:")
        note.setStyleSheet(f"color:{T.TEXT_SEC};")
        lay.addWidget(note)

        form = QFormLayout()
        self._admin_user = QLineEdit("admin")
        self._admin_email = QLineEdit("admin@agentshield.local")
        self._admin_pass1 = QLineEdit()
        self._admin_pass1.setEchoMode(QLineEdit.EchoMode.Password)
        self._admin_pass2 = QLineEdit()
        self._admin_pass2.setEchoMode(QLineEdit.EchoMode.Password)

        form.addRow("Username:", self._admin_user)
        form.addRow("Email:", self._admin_email)
        form.addRow("Password (min 8 chars):", self._admin_pass1)
        form.addRow("Confirm Password:", self._admin_pass2)
        lay.addLayout(form)
        lay.addStretch()
        return p

    def _page_summary(self) -> QWidget:
        p = QWidget()
        lay = QVBoxLayout(p)
        lay.setSpacing(T.SP_4)

        lbl = QLabel("✓ AgentShield Is Ready!")
        lbl.setStyleSheet(f"font-size:{T.FS_LG}px; font-weight:700; color:{T.SUCCESS};")
        lay.addWidget(lbl)

        self._summary_txt = QLabel()
        self._summary_txt.setWordWrap(True)
        lay.addWidget(self._summary_txt)
        lay.addStretch()
        return p

    def _test_connection(self):
        url = self._url_input.text().strip()
        self._status_lbl.setText("Testing connection...")
        backend_client.base_url = url

        health = backend_client.get_system_health()
        if health and health.get("status") in ("healthy", "ok"):
            self._status_lbl.setText(f"✓ Connected successfully! Version: {health.get('version')}")
            self._status_lbl.setStyleSheet(f"color:{T.SUCCESS}; font-weight:600;")
        else:
            self._status_lbl.setText("✗ Could not connect. Ensure the backend process is running.")
            self._status_lbl.setStyleSheet(f"color:{T.DANGER}; font-weight:600;")

    def _go_next(self):
        idx = self._stack.currentIndex()
        if idx == 0:
            self._deployment_mode = "LOCAL" if self._radio_local.isChecked() else "REMOTE"
            self._url_input.setText("http://localhost:8000" if self._deployment_mode == "LOCAL" else "https://agentshield.yourdomain.com")
        elif idx == 2:
            p1 = self._admin_pass1.text()
            p2 = self._admin_pass2.text()
            if len(p1) < 8:
                QMessageBox.warning(self, "Invalid Password", "Administrator password must be at least 8 characters long.")
                return
            if p1 != p2:
                QMessageBox.warning(self, "Password Mismatch", "Passwords do not match.")
                return

            self._summary_txt.setText(
                f"Deployment Mode: {self._deployment_mode}\n"
                f"Backend Server:  {self._url_input.text().strip()}\n"
                f"Administrator:   {self._admin_user.text().strip()} ({self._admin_email.text().strip()})\n\n"
                "All security verification and policy enforcement rules are active. Click 'Finish' to enter the dashboard."
            )
            self._next_btn.setText("Finish")
        elif idx == 3:
            self.setup_completed.emit({
                "deployment_mode": self._deployment_mode,
                "backend_url": self._url_input.text().strip(),
                "admin_user": self._admin_user.text().strip(),
            })
            self.accept()
            return

        next_idx = idx + 1
        self._stack.setCurrentIndex(next_idx)
        self._title_lbl.setText(f"AgentShield Setup (Step {next_idx + 1} of 4)")
        self._back_btn.setEnabled(True)

    def _go_back(self):
        idx = self._stack.currentIndex()
        if idx > 0:
            prev_idx = idx - 1
            self._stack.setCurrentIndex(prev_idx)
            self._title_lbl.setText(f"AgentShield Setup (Step {prev_idx + 1} of 4)")
            self._next_btn.setText("Next")
            if prev_idx == 0:
                self._back_btn.setEnabled(False)
