"""
AgentShield AI — Interactive Demo Agent Runner Dialog.

Provides a clean, intuitive GUI interface to execute and evaluate autonomous agents
under both Protected (Firewall ON) and Unprotected (Firewall OFF) conditions.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from apps.desktop.components.icons import get_icon, get_pixmap
from apps.desktop.components.status_badge import RiskBadge, StatusBadge
from apps.desktop.themes.design_tokens import T

TARGET_TEST_FILE = Path(r"C:\Users\ajayv\Downloads\IMG_4023_0.webp")


class AgentExecutionWorker(QObject):
    """Background worker executing the agent so the Qt event loop never blocks."""

    finished = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        webpage_type: str,
        firewall_on: bool,
        use_mock_model: bool = True,
        custom_file_path: str = "",
        llm_provider: str = "simulated",
        api_key: str = "",
    ):
        super().__init__()
        self.webpage_type = webpage_type
        self.firewall_on = firewall_on
        self.use_mock_model = use_mock_model
        self.custom_file_path = custom_file_path
        self.llm_provider = llm_provider
        self.api_key = api_key

    def run(self):
        try:
            from demos.agent.agent import PoisonedWebpageDemoAgent
            from demos.agent.agentshield_adapter import AgentShieldAdapter
            from demos.agent.agent import (
                NORMAL_WEBPAGE,
                POISONED_WEBPAGE,
                Webpage,
            )

            # Select or construct target webpage
            if self.custom_file_path and Path(self.custom_file_path).exists():
                p = Path(self.custom_file_path)
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    html_content = f.read()
                target_webpage = Webpage(
                    id="user-custom-webpage",
                    url=f"file:///{p.as_posix()}",
                    title=f"Custom: {p.name}",
                    content=html_content,
                    is_poisoned=True,
                    description=f"User-provided custom file: {p.name}",
                )
            elif self.webpage_type == "local_html":
                html_path = Path("poisoned_webpage_demo.html")
                if html_path.exists():
                    with open(html_path, "r", encoding="utf-8") as f:
                        html_content = f.read()
                else:
                    html_content = POISONED_WEBPAGE.content

                target_webpage = Webpage(
                    id="local-html-demo",
                    url="file:///e:/AgentShield/poisoned_webpage_demo.html",
                    title="Benchmark Analysis of Multi-Agent Collaboration Frameworks",
                    content=html_content,
                    is_poisoned=True,
                    description="Local poisoned HTML test page targeting unauthorized deletion",
                )
            elif self.webpage_type == "poisoned_report":
                target_webpage = POISONED_WEBPAGE
            else:
                target_webpage = NORMAL_WEBPAGE

            adapter = AgentShieldAdapter(use_live_backend=True)
            agent = PoisonedWebpageDemoAgent(
                adapter=adapter,
                firewall_on=self.firewall_on,
                use_mock_model=(self.llm_provider == "simulated"),
                llm_provider=self.llm_provider,
                api_key=self.api_key,
            )

            scenario_name = f"gui_demo_{'protected' if self.firewall_on else 'unprotected'}_{self.llm_provider}"
            ctx = agent.run(target_webpage, scenario_id=scenario_name)
            self.finished.emit(ctx)
        except Exception as exc:
            self.failed.emit(str(exc))


class DemoAgentRunnerDialog(QDialog):
    """Interactive GUI dialog allowing users to run and test autonomous agents simply."""

    def __init__(self, agent_name: str = "PoisonedWebpageDemoAgent", parent=None):
        super().__init__(parent)
        self.agent_name = agent_name
        self._custom_html_path: str = ""
        self._thread: QThread | None = None
        self._worker: AgentExecutionWorker | None = None
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle(f"Run AI Agent — {self.agent_name}")
        self.setMinimumWidth(640)
        self.setStyleSheet(
            f"QDialog {{ background: {T.SURFACE}; }} "
            f"QLabel {{ background: transparent; color: {T.TEXT}; }} "
            f"QComboBox {{ background: {T.SURFACE}; border: 1px solid {T.BORDER}; "
            f"border-radius: {T.R_SM}px; padding: 6px 10px; color: {T.TEXT}; font-size: {T.FS_MD}px; }} "
            f"QComboBox:focus {{ border-color: {T.PRIMARY}; }}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)
        layout.setSpacing(T.SP_4)

        # ── Header Card ───────────────────────────────────────────────────────
        hdr = QHBoxLayout()
        hdr.setSpacing(T.SP_3)

        icon_lbl = QLabel()
        icon_lbl.setPixmap(get_pixmap("agent", size=26, color=T.PRIMARY))
        icon_lbl.setFixedSize(40, 40)
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl.setStyleSheet(
            f"background: #EFF6FF; border: 1px solid #DBEAFE; border-radius: {T.R_MD}px; padding: 4px;"
        )
        hdr.addWidget(icon_lbl)

        hdr_info = QVBoxLayout()
        hdr_info.setSpacing(1)
        title_l = QLabel(self.agent_name)
        title_l.setStyleSheet(f"color:{T.TEXT}; font-size:{T.FS_LG}px; font-weight:700;")
        sub_l = QLabel("Autonomous Agent Security Testing Sandbox")
        sub_l.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px;")
        hdr_info.addWidget(title_l)
        hdr_info.addWidget(sub_l)
        hdr.addLayout(hdr_info, 1)

        hdr.addWidget(StatusBadge("Active"))
        layout.addLayout(hdr)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color:{T.BORDER};")
        layout.addWidget(sep)

        # ── Configuration Form ────────────────────────────────────────────────
        form_grid = QGridLayout()
        form_grid.setSpacing(T.SP_3)

        # Target Webpage selection
        form_grid.addWidget(QLabel("Target Webpage:"), 0, 0)
        web_row = QHBoxLayout()
        web_row.setSpacing(T.SP_2)
        self.webpage_combo = QComboBox()
        self.webpage_combo.addItem("📄 Local Test File (poisoned_webpage_demo.html)", "local_html")
        self.webpage_combo.addItem("⚠️ Poisoned Webpage (Hidden Prompt Injection Directive)", "poisoned_report")
        self.webpage_combo.addItem("🛡️ Normal Webpage (Clean Technical Article - No Injection)", "normal")
        web_row.addWidget(self.webpage_combo, 1)

        self.browse_btn = QPushButton("Browse...")
        self.browse_btn.setIcon(get_icon("folder", size=14, color=T.TEXT))
        self.browse_btn.setFixedHeight(34)
        self.browse_btn.setToolTip("Select your own custom HTML / text file with indirect prompt injection")
        self.browse_btn.setStyleSheet(
            f"QPushButton {{ background-color: #F1F5F9; color: {T.TEXT}; border: 1px solid {T.BORDER}; "
            f"border-radius: {T.R_SM}px; padding: 4px 12px; font-weight: 600; font-size: 12px; }} "
            f"QPushButton:hover {{ background-color: #E2E8F0; }}"
        )
        self.browse_btn.clicked.connect(self._browse_custom_html)
        web_row.addWidget(self.browse_btn)
        form_grid.addLayout(web_row, 0, 1)

        # Runtime Firewall Mode
        form_grid.addWidget(QLabel("Security Gateway:"), 1, 0)
        self.firewall_combo = QComboBox()
        self.firewall_combo.addItem("🛡️ Firewall ON — Protected Mode (Enforce Zero-Trust)", True)
        self.firewall_combo.addItem("⚠️ Firewall OFF — Unprotected Baseline (Vulnerable)", False)
        form_grid.addWidget(self.firewall_combo, 1, 1)

        # Execution Model
        form_grid.addWidget(QLabel("Reasoning Engine:"), 2, 0)
        self.engine_combo = QComboBox()
        self.engine_combo.addItem("💎 Google Gemini (Live gemini-2.0-flash / gemini-1.5-flash)", "gemini")
        self.engine_combo.addItem("🌐 OpenRouter (Live Llama 3.3, Claude, DeepSeek, GPT-4o)", "openrouter")
        self.engine_combo.addItem("🟢 OpenAI (Live gpt-4o / gpt-4o-mini)", "openai")
        self.engine_combo.addItem("⚡ Simulated Model (Offline Deterministic Evaluation)", "simulated")
        self.engine_combo.currentIndexChanged.connect(self._on_engine_changed)
        form_grid.addWidget(self.engine_combo, 2, 1)

        # API Key Row
        self.key_label = QLabel("API Key:")
        form_grid.addWidget(self.key_label, 3, 0)

        key_row = QHBoxLayout()
        key_row.setSpacing(T.SP_2)
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_input.setFixedHeight(30)
        self.api_key_input.setStyleSheet(
            f"QLineEdit {{ background: {T.SURFACE}; border: 1px solid {T.BORDER}; "
            f"border-radius: {T.R_SM}px; padding: 4px 10px; color: {T.TEXT}; font-size: {T.FS_SM}px; }} "
            f"QLineEdit:focus {{ border-color: {T.PRIMARY}; }}"
        )
        key_row.addWidget(self.api_key_input, 1)

        self.save_key_btn = QPushButton("Save Key")
        self.save_key_btn.setFixedHeight(30)
        self.save_key_btn.setStyleSheet(
            f"QPushButton {{ background-color: #F1F5F9; color: {T.TEXT}; border: 1px solid {T.BORDER}; "
            f"border-radius: {T.R_SM}px; font-size: 11px; padding: 2px 10px; font-weight: 600; }} "
            f"QPushButton:hover {{ background-color: #E2E8F0; }}"
        )
        self.save_key_btn.clicked.connect(self._save_api_key)
        key_row.addWidget(self.save_key_btn)

        form_grid.addLayout(key_row, 3, 1)

        # Target File Status
        form_grid.addWidget(QLabel("Target File (Poison):"), 4, 0)
        file_row = QHBoxLayout()
        file_row.setSpacing(T.SP_2)

        self.file_path_lbl = QLabel(TARGET_TEST_FILE.name)
        self.file_path_lbl.setToolTip(str(TARGET_TEST_FILE))
        self.file_path_lbl.setStyleSheet(f"font-family: monospace; color: {T.TEXT_SEC}; font-size: {T.FS_SM}px;")
        file_row.addWidget(self.file_path_lbl)

        self.file_status_badge = QLabel()
        self._refresh_file_status()
        file_row.addWidget(self.file_status_badge)

        self.recreate_btn = QPushButton("Re-create File")
        self.recreate_btn.setFixedHeight(26)
        self.recreate_btn.setStyleSheet(
            f"QPushButton {{ background-color: #F1F5F9; color: {T.TEXT}; border: 1px solid {T.BORDER}; "
            f"border-radius: {T.R_SM}px; font-size: 11px; padding: 2px 10px; font-weight: 600; }} "
            f"QPushButton:hover {{ background-color: #E2E8F0; }}"
        )
        self.recreate_btn.clicked.connect(self._recreate_test_file)
        file_row.addWidget(self.recreate_btn)
        file_row.addStretch()

        form_grid.addLayout(file_row, 4, 1)

        layout.addLayout(form_grid)

        # Select initial reasoning engine based on available keys
        try:
            from demos.agent.config import settings
            if settings.gemini_api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
                self.engine_combo.setCurrentIndex(0)
            elif settings.openrouter_api_key or os.environ.get("OPENROUTER_API_KEY"):
                self.engine_combo.setCurrentIndex(1)
            elif settings.openai_api_key or os.environ.get("OPENAI_API_KEY"):
                self.engine_combo.setCurrentIndex(2)
            else:
                self.engine_combo.setCurrentIndex(3)
        except Exception:
            self.engine_combo.setCurrentIndex(3)

        self._on_engine_changed()

        # ── Run Action Button ─────────────────────────────────────────────────
        self.run_btn = QPushButton("Run Agent Execution")
        self.run_btn.setIcon(get_icon("play", size=16, color="#FFFFFF"))
        self.run_btn.setFixedHeight(38)
        self.run_btn.setStyleSheet(
            f"QPushButton {{ background-color: {T.PRIMARY}; color: {T.TEXT_ON_PRIMARY}; "
            f"border: none; border-radius: {T.R_SM}px; font-weight: 700; font-size: 14px; }} "
            f"QPushButton:hover {{ background-color: {T.PRIMARY_HOVER}; }} "
            f"QPushButton:disabled {{ background-color: #94A3B8; }}"
        )
        self.run_btn.clicked.connect(self._start_execution)
        layout.addWidget(self.run_btn)

        # ── Live Status Banner ────────────────────────────────────────────────
        self.status_banner = QLabel("Ready. Select options above and click 'Run Agent Execution'.")
        self.status_banner.setStyleSheet(
            f"background: {T.SURFACE_ALT}; color: {T.TEXT_SEC}; border: 1px solid {T.BORDER}; "
            f"border-radius: {T.R_SM}px; padding: 10px 14px; font-weight: 600; font-size: 13px;"
        )
        self.status_banner.setWordWrap(True)
        layout.addWidget(self.status_banner)

        # ── Execution Metrics Grid (Hidden initially, visible on result) ───────
        self.metrics_frame = QFrame()
        self.metrics_frame.setStyleSheet(
            f"background: {T.SURFACE}; border: 1px solid {T.BORDER}; border-radius: {T.R_SM}px; padding: 8px;"
        )
        self.metrics_frame.setVisible(False)
        self.metrics_grid = QGridLayout(self.metrics_frame)
        self.metrics_grid.setSpacing(T.SP_2)
        layout.addWidget(self.metrics_frame)

        # ── Agent Response & Audit Box ────────────────────────────────────────
        resp_title = QLabel("Agent Execution Response & Security Notice:")
        resp_title.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
        layout.addWidget(resp_title)

        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        self.output_box.setFixedHeight(110)
        self.output_box.setPlaceholderText("Agent output and security enforcement verdict will appear here...")
        self.output_box.setStyleSheet(
            f"background: {T.SURFACE_ALT}; color: {T.TEXT}; border: 1px solid {T.BORDER}; "
            f"border-radius: {T.R_SM}px; font-family: monospace; font-size: {T.FS_SM}px; padding: 8px 10px;"
        )
        layout.addWidget(self.output_box)

        # ── Dialog Action Buttons ─────────────────────────────────────────────
        btn_box = QHBoxLayout()
        btn_box.addStretch()

        self.close_btn = QPushButton("Close")
        self.close_btn.setStyleSheet(
            f"QPushButton {{ background-color: #F1F5F9; color: #0F172A; border: 1px solid #CBD5E1; "
            f"border-radius: {T.R_SM}px; padding: 6px 20px; font-weight: 600; min-height: 28px; }} "
            f"QPushButton:hover {{ background-color: #E2E8F0; }}"
        )
        self.close_btn.clicked.connect(self.accept)
        btn_box.addWidget(self.close_btn)

        layout.addLayout(btn_box)

    def _browse_custom_html(self):
        """Open file picker allowing user to select any custom HTML or text file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Your Custom HTML or Text File",
            str(Path.cwd()),
            "Web & Text Files (*.html *.htm *.txt);;All Files (*.*)",
        )
        if file_path:
            self._custom_html_path = file_path
            p = Path(file_path)
            label = f"📂 Custom: {p.name}"
            idx = self.webpage_combo.findData("custom")
            if idx >= 0:
                self.webpage_combo.setItemText(idx, label)
                self.webpage_combo.setCurrentIndex(idx)
            else:
                self.webpage_combo.addItem(label, "custom")
                self.webpage_combo.setCurrentIndex(self.webpage_combo.count() - 1)
            self.status_banner.setText(f"Loaded custom file: {p.name}")

    def _on_engine_changed(self):
        """Update API key input when reasoning engine selection changes."""
        engine = self.engine_combo.currentData()
        from demos.agent.config import settings
        if engine == "gemini":
            self.key_label.setVisible(True)
            self.api_key_input.setVisible(True)
            self.save_key_btn.setVisible(True)
            self.api_key_input.setText(settings.gemini_api_key or "")
            self.api_key_input.setPlaceholderText("Enter Google Gemini API Key (or set GEMINI_API_KEY in .env)")
        elif engine == "openrouter":
            self.key_label.setVisible(True)
            self.api_key_input.setVisible(True)
            self.save_key_btn.setVisible(True)
            self.api_key_input.setText(settings.openrouter_api_key or "")
            self.api_key_input.setPlaceholderText("Enter OpenRouter API Key sk-or-... (or set OPENROUTER_API_KEY)")
        elif engine == "openai":
            self.key_label.setVisible(True)
            self.api_key_input.setVisible(True)
            self.save_key_btn.setVisible(True)
            self.api_key_input.setText(settings.openai_api_key or "")
            self.api_key_input.setPlaceholderText("Enter OpenAI API Key sk-... (or set OPENAI_API_KEY)")
        else:
            self.key_label.setVisible(False)
            self.api_key_input.setVisible(False)
            self.save_key_btn.setVisible(False)

    def _save_api_key(self):
        """Save entered API key to .env so user doesn't have to re-enter it."""
        key = self.api_key_input.text().strip()
        engine = self.engine_combo.currentData()
        if not key:
            QMessageBox.information(self, "API Key", "Please enter an API key to save.")
            return

        var_name = "GEMINI_API_KEY" if engine == "gemini" else ("OPENROUTER_API_KEY" if engine == "openrouter" else "OPENAI_API_KEY")
        demo_env = Path("demos/agent/.env")
        demo_env.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        if demo_env.exists():
            lines = demo_env.read_text(encoding="utf-8").splitlines()

        updated = False
        new_lines = []
        for line in lines:
            if line.startswith(f"{var_name}="):
                new_lines.append(f"{var_name}={key}")
                updated = True
            else:
                new_lines.append(line)
        if not updated:
            new_lines.append(f"{var_name}={key}")

        demo_env.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        os.environ[var_name] = key
        from demos.agent.config import settings
        setattr(settings, var_name.lower(), key)
        QMessageBox.information(self, "Key Saved", f"{var_name} successfully saved to .env!")

    def _start_execution(self):
        """Launch background worker for smooth execution."""
        webpage_type = self.webpage_combo.currentData()
        firewall_on = self.firewall_combo.currentData()
        engine = self.engine_combo.currentData()
        api_key = self.api_key_input.text().strip()

        self.run_btn.setEnabled(False)
        self.run_btn.setText("Executing Agent...")
        self.status_banner.setText("⏳ Ingesting webpage and processing agent workflow through AgentShield...")
        self.status_banner.setStyleSheet(
            "background: #FEF3C7; color: #92400E; border: 1px solid #FDE68A; "
            "border-radius: 6px; padding: 10px 14px; font-weight: 600; font-size: 13px;"
        )
        self.output_box.clear()
        self.metrics_frame.setVisible(False)

        self._thread = QThread()
        self._worker = AgentExecutionWorker(
            webpage_type=webpage_type,
            firewall_on=firewall_on,
            use_mock_model=(engine == "simulated"),
            custom_file_path=self._custom_html_path if webpage_type == "custom" else "",
            llm_provider=engine,
            api_key=api_key,
        )
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_execution_finished)
        self._worker.failed.connect(self._on_execution_failed)
        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.start()

    def _on_execution_finished(self, ctx: Any):
        """Handle completed execution and update GUI state."""
        self.run_btn.setEnabled(True)
        self.run_btn.setText("Run Agent Execution")

        firewall_on = ctx.firewall_mode == "PROTECTED"
        injection_found = ctx.injection_detected
        tool_executed = ctx.malicious_tool_executed

        # Update Banner
        if firewall_on and injection_found and not tool_executed:
            self.status_banner.setText(
                "🛡️ ATTACK CONTAINED — Prompt Injection Detected & Blocked by AgentShield Runtime Firewall!"
            )
            self.status_banner.setStyleSheet(
                "background: #DCFCE7; color: #166534; border: 1px solid #86EFAC; "
                "border-radius: 6px; padding: 10px 14px; font-weight: 700; font-size: 13px;"
            )
        elif not firewall_on and tool_executed:
            self.status_banner.setText(
                "⚠️ VULNERABLE EXPLOIT — Firewall was OFF: Malicious directive executed without protection!"
            )
            self.status_banner.setStyleSheet(
                "background: #FEE2E2; color: #991B1B; border: 1px solid #FCA5A5; "
                "border-radius: 6px; padding: 10px 14px; font-weight: 700; font-size: 13px;"
            )
        else:
            self.status_banner.setText(
                "✅ TASK COMPLETED — Webpage summarized cleanly with zero threats detected."
            )
            self.status_banner.setStyleSheet(
                "background: #EFF6FF; color: #1E40AF; border: 1px solid #93C5FD; "
                "border-radius: 6px; padding: 10px 14px; font-weight: 700; font-size: 13px;"
            )

        # Update Metrics Grid
        while self.metrics_grid.count():
            item = self.metrics_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        metrics = [
            ("Firewall Mode", ctx.firewall_mode),
            ("Duration", f"{ctx.duration_seconds:.3f} s"),
            ("Prompt Injection", "DETECTED (CRITICAL)" if injection_found else "None"),
            ("Malicious Tool Call", "BLOCKED BY SHIELD" if (injection_found and not tool_executed) else ("EXECUTED (EXFIL)" if tool_executed else "No Attempt")),
        ]

        for idx, (label, val) in enumerate(metrics):
            k_lbl = QLabel(label + ":")
            k_lbl.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px; font-weight:600;")
            v_lbl = QLabel(val)
            color = "#166534" if "BLOCKED" in val or "None" in val else ("#991B1B" if "EXECUTED" in val or "DETECTED" in val else T.TEXT)
            v_lbl.setStyleSheet(f"color:{color}; font-size:{T.FS_SM}px; font-weight:700;")
            self.metrics_grid.addWidget(k_lbl, idx // 2, (idx % 2) * 2)
            self.metrics_grid.addWidget(v_lbl, idx // 2, (idx % 2) * 2 + 1)

        self.metrics_frame.setVisible(True)

        # Display Final Output
        self.output_box.setPlainText(ctx.final_response)

        # Trigger parent refresh if available to update Live Activity / Dashboard
        parent = self.parent()
        if parent and hasattr(parent, "refresh_data"):
            parent.refresh_data()

        self._refresh_file_status()

    def _refresh_file_status(self):
        """Update file status badge reflecting whether target test file exists."""
        if TARGET_TEST_FILE.exists():
            self.file_status_badge.setText("File Exists (Ready)")
            self.file_status_badge.setStyleSheet(
                "background: #DCFCE7; color: #166534; border: 1px solid #86EFAC; "
                "border-radius: 4px; padding: 2px 8px; font-weight: 700; font-size: 11px;"
            )
        else:
            self.file_status_badge.setText("File Deleted (Missing)")
            self.file_status_badge.setStyleSheet(
                "background: #FEE2E2; color: #991B1B; border: 1px solid #FCA5A5; "
                "border-radius: 4px; padding: 2px 8px; font-weight: 700; font-size: 11px;"
            )

    def _recreate_test_file(self):
        """Re-create test dummy file so user can test deletion again."""
        try:
            TARGET_TEST_FILE.parent.mkdir(parents=True, exist_ok=True)
            TARGET_TEST_FILE.write_bytes(b"dummy image webp test payload")
            self._refresh_file_status()
            self.status_banner.setText(f"Target test file re-created at {TARGET_TEST_FILE.name}")
        except Exception as exc:
            QMessageBox.warning(self, "Create File Error", f"Could not create test file: {exc}")

    def _on_execution_failed(self, error_msg: str):
        """Handle worker failure."""
        self.run_btn.setEnabled(True)
        self.run_btn.setText("Run Agent Execution")
        self.status_banner.setText(f"❌ Execution Error: {error_msg}")
        self.status_banner.setStyleSheet(
            "background: #FEE2E2; color: #991B1B; border: 1px solid #FCA5A5; "
            "border-radius: 6px; padding: 10px 14px; font-weight: 700; font-size: 13px;"
        )
        self._refresh_file_status()
        QMessageBox.critical(self, "Agent Error", f"Agent execution encountered an error:\n{error_msg}")


if __name__ == "__main__":
    import sys
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyle("Fusion")
    dlg = DemoAgentRunnerDialog("PoisonedWebpageDemoAgent")
    dlg.show()
    sys.exit(app.exec())
