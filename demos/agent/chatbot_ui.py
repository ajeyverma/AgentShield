"""
AgentShield AI — Interactive Autonomous Chatbot UI.

A modern, full-featured AI Chatbot interface featuring:
- Live conversation flow with formatted user & assistant bubbles
- Attachment buttons for Document/File Upload and Video Upload
- Live model switching: Google Gemini (2.0/1.5 Flash), OpenRouter (Llama 3.3, Claude, DeepSeek), and Simulated
- One-click AgentShield Security Firewall toggle (Protected vs Unprotected)
- Real-time tool execution tracking and security block notices
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QSize, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

# Workspace imports
ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from apps.desktop.components.icons import get_icon, get_pixmap
from apps.desktop.themes.design_tokens import T
from demos.agent.agent import PoisonedWebpageDemoAgent
from demos.agent.agentshield_adapter import AgentShieldAdapter
from demos.agent.config import settings
from demos.agent.agent import Webpage

TARGET_FILE = Path(r"C:\Users\ajayv\Downloads\IMG_4023_0.webp")


class ChatWorker(QObject):
    """Background worker executing the autonomous agent reasoning loop."""

    finished = Signal(dict)
    failed = Signal(str)

    def __init__(
        self,
        user_message: str,
        attached_file_path: str | None,
        llm_provider: str,
        api_key: str,
    ):
        super().__init__()
        self.user_message = user_message
        self.attached_file_path = attached_file_path
        self.llm_provider = llm_provider
        self.api_key = api_key

    def run(self):
        try:
            # 1. Detect if AgentShield security gateway is running on localhost
            import httpx
            agentshield_running = False
            try:
                resp = httpx.get(f"{settings.backend_url}/api/v1/health", timeout=1.0)
                agentshield_running = (resp.status_code == 200)
            except Exception:
                agentshield_running = False

            # 2. Prepare Content & Webpage/Document context
            content = ""
            file_name = ""
            is_video = False
            if self.attached_file_path and Path(self.attached_file_path).exists():
                p = Path(self.attached_file_path)
                file_name = p.name
                ext = p.suffix.lower()
                is_video = ext in (".mp4", ".webm", ".mov", ".avi", ".mkv")

                if is_video:
                    file_size_mb = p.stat().st_size / (1024 * 1024)
                    content = (
                        f"[Video Attachment: {p.name} ({file_size_mb:.2f} MB)]\n"
                        f"Video Format: {ext}\n"
                        f"User Prompt on Video: {self.user_message}\n"
                    )
                else:
                    try:
                        content = p.read_text(encoding="utf-8", errors="replace")
                    except Exception:
                        content = f"[Attached Document: {p.name}]"
            else:
                content = self.user_message or "Analyze current operational context."

            target_webpage = Webpage(
                id="chat-context",
                url=f"file:///{self.attached_file_path}" if self.attached_file_path else "chat://user-session",
                title=file_name or "User Conversation Request",
                content=content,
                is_poisoned=("delete" in content.lower() or "secret" in content.lower()),
                description=f"Chat message with attached {file_name if file_name else 'prompt'}",
            )

            # 3. Run Autonomous Agent:
            # - If AgentShield IS running: adapter actively intercepts & enforces zero-trust BLOCK!
            # - If AgentShield IS NOT running: agent operates standalone without a shield (vulnerable)!
            adapter = AgentShieldAdapter(use_live_backend=True) if agentshield_running else None
            agent = PoisonedWebpageDemoAgent(
                adapter=adapter,
                firewall_on=agentshield_running,
                use_mock_model=(self.llm_provider == "simulated"),
                llm_provider=self.llm_provider,
                api_key=self.api_key,
            )

            ctx = agent.run(target_webpage, scenario_id=f"chat_{self.llm_provider}")

            result = {
                "final_response": ctx.final_response,
                "agentshield_active": agentshield_running,
                "injection_detected": ctx.injection_detected,
                "malicious_tool_attempted": ctx.malicious_tool_attempted,
                "malicious_tool_blocked": ctx.malicious_tool_blocked,
                "malicious_tool_executed": ctx.malicious_tool_executed,
                "tool_calls": ctx.tool_call_attempts,
                "firewall_mode": "PROTECTED" if agentshield_running else "UNPROTECTED",
                "errors": ctx.errors,
            }
            self.finished.emit(result)

        except Exception as exc:
            self.failed.emit(str(exc))


class ChatMessageBubble(QFrame):
    """Message card supporting both User and Agent turns with sleek styling."""

    def __init__(
        self,
        sender: str,  # "user" or "agent"
        text: str,
        attachment_name: str | None = None,
        security_event: dict | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self.sender = sender
        self._setup_ui(text, attachment_name, security_event)

    def _setup_ui(self, text: str, attachment_name: str | None, security_event: dict | None):
        is_user = self.sender == "user"
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(6)

        # Bubble Background & Alignment
        if is_user:
            self.setStyleSheet(
                "QFrame { background-color: #2563EB; border-radius: 14px; border-bottom-right-radius: 2px; } "
                "QLabel { color: #FFFFFF; font-size: 13px; }"
            )
        else:
            self.setStyleSheet(
                f"QFrame {{ background-color: #FFFFFF; border: 1px solid {T.BORDER}; "
                f"border-radius: 14px; border-bottom-left-radius: 2px; }} "
                f"QLabel {{ color: {T.TEXT}; font-size: 13px; }}"
            )

        # Header with Avatar & Name
        hdr = QHBoxLayout()
        hdr.setSpacing(6)
        icon_lbl = QLabel()
        icon_name = "user" if is_user else "agent"
        icon_color = "#FFFFFF" if is_user else T.PRIMARY
        icon_lbl.setPixmap(get_pixmap(icon_name, size=16, color=icon_color))
        hdr.addWidget(icon_lbl)

        name_lbl = QLabel("You" if is_user else "AgentShield Autonomous Agent")
        name_lbl.setStyleSheet(f"font-weight: 700; font-size: 11px; {'color: #DBEAFE;' if is_user else 'color: #64748B;'}")
        hdr.addWidget(name_lbl)
        hdr.addStretch()
        layout.addLayout(hdr)

        # Attachment Chip if any
        if attachment_name:
            chip = QFrame()
            chip_l = QHBoxLayout(chip)
            chip_l.setContentsMargins(8, 4, 8, 4)
            chip_l.setSpacing(6)
            is_vid = any(attachment_name.lower().endswith(ext) for ext in (".mp4", ".webm", ".mov", ".avi"))
            ic = QLabel()
            ic.setPixmap(get_pixmap("video" if is_vid else "paperclip", size=14, color="#FFFFFF" if is_user else T.PRIMARY))
            chip_l.addWidget(ic)
            txt = QLabel(attachment_name)
            txt.setStyleSheet(f"font-size: 11px; font-weight: 600; {'color: #FFFFFF;' if is_user else 'color: #0F172A;'}")
            chip_l.addWidget(txt)
            chip_l.addStretch()

            chip_bg = "rgba(255,255,255,0.2)" if is_user else "#F1F5F9"
            chip.setStyleSheet(f"background: {chip_bg}; border-radius: 6px;")
            layout.addWidget(chip)

        # Message Text
        msg_lbl = QLabel(text)
        msg_lbl.setWordWrap(True)
        msg_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(msg_lbl)

        # Security Alert Box if threat detected or blocked
        if security_event:
            sec_card = QFrame()
            sec_card_l = QVBoxLayout(sec_card)
            sec_card_l.setContentsMargins(10, 8, 10, 8)
            sec_card_l.setSpacing(4)

            shield_active = security_event.get("agentshield_active", False)
            blocked = security_event.get("blocked", False)
            executed = security_event.get("executed", False)

            if shield_active and blocked:
                sec_card.setStyleSheet("background: #DCFCE7; border: 1px solid #86EFAC; border-radius: 8px;")
                status_t = "🛡️ Protected by AgentShield: Attack Blocked"
                status_c = "#166534"
                desc = "AgentShield security service is running. It inspected the untrusted input, identified an indirect prompt injection, and BLOCKED the unauthorized destructive action."
            elif not shield_active and executed:
                sec_card.setStyleSheet("background: #FEE2E2; border: 1px solid #FCA5A5; border-radius: 8px;")
                status_t = "⚠️ Exploited: AgentShield is NOT Running"
                status_c = "#991B1B"
                desc = "AgentShield is offline. The agent ran independently without runtime security, followed the hidden injection directive, and deleted the target file."
            else:
                sec_card.setStyleSheet("background: #F1F5F9; border: 1px solid #CBD5E1; border-radius: 8px;")
                status_t = "ℹ️ Security Status: Benign Content"
                status_c = "#334155"
                desc = "No malicious injection detected in message content."

            title = QLabel(status_t)
            title.setStyleSheet(f"font-weight: 700; font-size: 12px; color: {status_c};")
            body = QLabel(desc)
            body.setStyleSheet(f"font-size: 11px; color: {status_c};")
            body.setWordWrap(True)
            sec_card_l.addWidget(title)
            sec_card_l.addWidget(body)

            layout.addWidget(sec_card)


class AgentChatbotWindow(QWidget):
    """Standalone modern Chatbot UI for the autonomous agent."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._attached_file_path: str | None = None
        self._thread: QThread | None = None
        self._worker: ChatWorker | None = None
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("AgentShield AI — Autonomous Agent Chat")
        self.resize(800, 700)
        self.setMinimumSize(600, 500)
        self.setStyleSheet(
            f"QWidget {{ background: {T.SURFACE}; font-family: 'Segoe UI', system-ui, sans-serif; }} "
            f"QComboBox {{ background: {T.SURFACE}; border: 1px solid {T.BORDER}; "
            f"border-radius: {T.R_SM}px; padding: 4px 8px; color: {T.TEXT}; font-size: 12px; }} "
            f"QComboBox:focus {{ border-color: {T.PRIMARY}; }}"
        )

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── 1. Header Toolbar ──────────────────────────────────────────────────
        header = QFrame()
        header.setFixedHeight(58)
        header.setStyleSheet(
            f"background: #FFFFFF; border-bottom: 1px solid {T.BORDER}; padding: 0 16px;"
        )
        hdr_layout = QHBoxLayout(header)
        hdr_layout.setContentsMargins(16, 0, 16, 0)
        hdr_layout.setSpacing(12)

        bot_icon = QLabel()
        bot_icon.setPixmap(get_pixmap("agent", size=24, color=T.PRIMARY))
        hdr_layout.addWidget(bot_icon)

        title_box = QVBoxLayout()
        title_box.setSpacing(0)
        title_lbl = QLabel("Autonomous Agent")
        title_lbl.setStyleSheet(f"font-weight: 700; font-size: 14px; color: {T.TEXT};")
        sub_lbl = QLabel("Multi-Modal Hackathon Sandbox")
        sub_lbl.setStyleSheet(f"font-size: 11px; color: {T.TEXT_SEC};")
        title_box.addWidget(title_lbl)
        title_box.addWidget(sub_lbl)
        hdr_layout.addLayout(title_box)

        hdr_layout.addStretch()

        # Engine selector
        self.engine_combo = QComboBox()
        self.engine_combo.addItem("💎 Gemini Flash (gemini-3.1-flash-lite)", "gemini")
        self.engine_combo.addItem("🌐 OpenRouter", "openrouter")
        self.engine_combo.addItem("⚡ Simulated Model", "simulated")
        self.engine_combo.setToolTip("Select Reasoning Engine")
        hdr_layout.addWidget(self.engine_combo)

        # Automatic AgentShield live status indicator (No manual toggle button)
        self.gateway_status_lbl = QLabel()
        self.gateway_status_lbl.setFixedHeight(28)
        self._update_gateway_status()
        hdr_layout.addWidget(self.gateway_status_lbl)

        # Periodic timer checking if AgentShield backend is running
        self._status_timer = QTimer(self)
        self._status_timer.setInterval(2500)
        self._status_timer.timeout.connect(self._update_gateway_status)
        self._status_timer.start()

        # API Key Settings Button
        key_btn = QPushButton("API Key")
        key_btn.setFixedHeight(30)
        key_btn.setStyleSheet(
            f"QPushButton {{ background: #F1F5F9; color: {T.TEXT}; border: 1px solid {T.BORDER}; "
            f"border-radius: 6px; font-weight: 600; font-size: 12px; padding: 4px 10px; }} "
            f"QPushButton:hover {{ background: #E2E8F0; }}"
        )
        key_btn.clicked.connect(self._open_api_key_dialog)
        hdr_layout.addWidget(key_btn)

        # Clear Chat Button
        clear_btn = QPushButton("Clear")
        clear_btn.setIcon(get_icon("trash", size=14, color=T.TEXT_SEC))
        clear_btn.setFixedHeight(30)
        clear_btn.setStyleSheet(
            f"QPushButton {{ background: #F8FAFC; color: {T.TEXT_SEC}; border: 1px solid {T.BORDER}; "
            f"border-radius: 6px; font-size: 11px; padding: 4px 8px; }} "
            f"QPushButton:hover {{ background: #F1F5F9; color: {T.TEXT}; }}"
        )
        clear_btn.clicked.connect(self._clear_chat)
        hdr_layout.addWidget(clear_btn)

        main_layout.addWidget(header)

        # ── 2. Message History Area ───────────────────────────────────────────
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet(f"QScrollArea {{ border: none; background: {T.SURFACE_ALT}; }}")

        self.messages_container = QWidget()
        self.messages_container.setStyleSheet(f"background: {T.SURFACE_ALT};")
        self.messages_layout = QVBoxLayout(self.messages_container)
        self.messages_layout.setContentsMargins(20, 20, 20, 20)
        self.messages_layout.setSpacing(16)
        self.messages_layout.addStretch(1)

        self.scroll_area.setWidget(self.messages_container)
        main_layout.addWidget(self.scroll_area, 1)

        # Add initial greeting message
        self._add_welcome_message()

        # ── 3. Attachment Preview Strip (Hidden until file selected) ──────────
        self.attach_strip = QFrame()
        self.attach_strip.setFixedHeight(38)
        self.attach_strip.setStyleSheet(
            f"background: #FFFFFF; border-top: 1px solid {T.BORDER}; padding: 0 16px;"
        )
        self.attach_strip.setVisible(False)
        strip_layout = QHBoxLayout(self.attach_strip)
        strip_layout.setContentsMargins(16, 4, 16, 4)
        strip_layout.setSpacing(8)

        self.attach_icon = QLabel()
        strip_layout.addWidget(self.attach_icon)

        self.attach_name_lbl = QLabel()
        self.attach_name_lbl.setStyleSheet(f"font-weight: 600; font-size: 12px; color: {T.TEXT};")
        strip_layout.addWidget(self.attach_name_lbl)

        strip_layout.addStretch()

        remove_attach_btn = QPushButton("✕")
        remove_attach_btn.setFixedSize(22, 22)
        remove_attach_btn.setToolTip("Remove Attachment")
        remove_attach_btn.setStyleSheet(
            "QPushButton { background: #E2E8F0; border-radius: 11px; font-weight: bold; border: none; color: #475569; } "
            "QPushButton:hover { background: #CBD5E1; color: #0F172A; }"
        )
        remove_attach_btn.clicked.connect(self._clear_attachment)
        strip_layout.addWidget(remove_attach_btn)

        main_layout.addWidget(self.attach_strip)

        # ── 4. Bottom Input Bar ───────────────────────────────────────────────
        input_container = QFrame()
        input_container.setStyleSheet(
            f"background: #FFFFFF; border-top: 1px solid {T.BORDER}; padding: 12px 16px;"
        )
        input_layout = QHBoxLayout(input_container)
        input_layout.setContentsMargins(16, 12, 16, 12)
        input_layout.setSpacing(10)

        # Upload File Button
        self.upload_file_btn = QPushButton("Upload File")
        self.upload_file_btn.setIcon(get_icon("paperclip", size=16, color=T.TEXT))
        self.upload_file_btn.setFixedHeight(38)
        self.upload_file_btn.setToolTip("Attach Document / HTML / Code File")
        self.upload_file_btn.setStyleSheet(
            f"QPushButton {{ background: #F1F5F9; color: {T.TEXT}; border: 1px solid {T.BORDER}; "
            f"border-radius: {T.R_SM}px; font-weight: 600; font-size: 12px; padding: 0 12px; }} "
            f"QPushButton:hover {{ background: #E2E8F0; }}"
        )
        self.upload_file_btn.clicked.connect(self._browse_file)
        input_layout.addWidget(self.upload_file_btn)

        # Upload Video Button
        self.upload_video_btn = QPushButton("Upload Video")
        self.upload_video_btn.setIcon(get_icon("video", size=16, color=T.TEXT))
        self.upload_video_btn.setFixedHeight(38)
        self.upload_video_btn.setToolTip("Attach MP4 / WebM / Video File")
        self.upload_video_btn.setStyleSheet(
            f"QPushButton {{ background: #F1F5F9; color: {T.TEXT}; border: 1px solid {T.BORDER}; "
            f"border-radius: {T.R_SM}px; font-weight: 600; font-size: 12px; padding: 0 12px; }} "
            f"QPushButton:hover {{ background: #E2E8F0; }}"
        )
        self.upload_video_btn.clicked.connect(self._browse_video)
        input_layout.addWidget(self.upload_video_btn)

        # Text Message Input
        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("Type a message or instruction for the autonomous agent...")
        self.msg_input.setFixedHeight(38)
        self.msg_input.setStyleSheet(
            f"QLineEdit {{ background: {T.SURFACE}; border: 1px solid {T.BORDER}; "
            f"border-radius: {T.R_SM}px; padding: 0 14px; font-size: 13px; color: {T.TEXT}; }} "
            f"QLineEdit:focus {{ border-color: {T.PRIMARY}; }}"
        )
        self.msg_input.returnPressed.connect(self._send_message)
        input_layout.addWidget(self.msg_input, 1)

        # Send Button
        self.send_btn = QPushButton()
        self.send_btn.setIcon(get_icon("send", size=16, color="#FFFFFF"))
        self.send_btn.setFixedSize(38, 38)
        self.send_btn.setToolTip("Send Message (Enter)")
        self.send_btn.setStyleSheet(
            f"QPushButton {{ background: {T.PRIMARY}; border-radius: {T.R_SM}px; border: none; }} "
            f"QPushButton:hover {{ background: {T.PRIMARY_HOVER}; }} "
            f"QPushButton:disabled {{ background: #94A3B8; }}"
        )
        self.send_btn.clicked.connect(self._send_message)
        input_layout.addWidget(self.send_btn)

        main_layout.addWidget(input_container)

    def _add_welcome_message(self):
        welcome_text = (
            "Hello! I am your autonomous AI Agent.\n\n"
            "• You can chat with me, ask questions, or assign tasks.\n"
            "• Click **Upload File** to attach HTML documents, reports, or test files.\n"
            "• Click **Upload Video** to attach video recordings for inspection.\n\n"
            "🛡️ *Security Status:* If **AgentShield** is running on this PC, it automatically monitors and protects all my actions. "
            "If AgentShield is not running, I operate independently without security guardrails."
        )
        self._append_bubble("agent", welcome_text)

    def _update_gateway_status(self):
        """Automatically checks if the AgentShield security backend is running on localhost:8000."""
        import httpx
        try:
            r = httpx.get(f"{settings.backend_url}/api/v1/health", timeout=0.6)
            is_running = (r.status_code == 200)
        except Exception:
            is_running = False

        if is_running:
            self.gateway_status_lbl.setText("🛡️ AgentShield: Active (Protected)")
            self.gateway_status_lbl.setStyleSheet(
                "background: #DCFCE7; color: #166534; border: 1px solid #86EFAC; "
                "border-radius: 6px; font-weight: 700; font-size: 11px; padding: 2px 10px;"
            )
            self.gateway_status_lbl.setToolTip("AgentShield security service is running on port 8000. All agent actions are actively inspected.")
        else:
            self.gateway_status_lbl.setText("⚪ AgentShield: Offline (Unprotected)")
            self.gateway_status_lbl.setStyleSheet(
                "background: #F1F5F9; color: #64748B; border: 1px solid #CBD5E1; "
                "border-radius: 6px; font-weight: 600; font-size: 11px; padding: 2px 10px;"
            )
            self.gateway_status_lbl.setToolTip("AgentShield is not running. The agent operates independently without runtime security.")

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Document / Webpage File",
            str(ROOT_DIR),
            "Documents & Web (*.html *.htm *.txt *.pdf *.py *.json *.md);;All Files (*.*)",
        )
        if path:
            self._attached_file_path = path
            p = Path(path)
            self.attach_icon.setPixmap(get_pixmap("paperclip", size=14, color=T.PRIMARY))
            self.attach_name_lbl.setText(f"File: {p.name} ({p.stat().st_size / 1024:.1f} KB)")
            self.attach_strip.setVisible(True)
            self.msg_input.setPlaceholderText(f"Ask the agent about '{p.name}' or press Send to analyze...")

    def _browse_video(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Video File",
            str(ROOT_DIR),
            "Video Files (*.mp4 *.webm *.mov *.avi *.mkv);;All Files (*.*)",
        )
        if path:
            self._attached_file_path = path
            p = Path(path)
            size_mb = p.stat().st_size / (1024 * 1024)
            self.attach_icon.setPixmap(get_pixmap("video", size=14, color=T.PRIMARY))
            self.attach_name_lbl.setText(f"Video: {p.name} ({size_mb:.2f} MB)")
            self.attach_strip.setVisible(True)
            self.msg_input.setPlaceholderText(f"Ask the agent to analyze '{p.name}' or press Send...")

    def _clear_attachment(self):
        self._attached_file_path = None
        self.attach_strip.setVisible(False)
        self.msg_input.setPlaceholderText("Type a message or instruction for the autonomous agent...")

    def _send_message(self):
        text = self.msg_input.text().strip()
        attached = self._attached_file_path

        if not text and not attached:
            return

        display_text = text or (f"Analyze attached file: {Path(attached).name}" if attached else "")
        attach_name = Path(attached).name if attached else None

        # Add user message bubble
        self._append_bubble("user", display_text, attachment_name=attach_name)
        self.msg_input.clear()
        self._clear_attachment()

        # Disable send while executing
        self.send_btn.setEnabled(False)

        # Launch background agent execution
        provider = self.engine_combo.currentData()
        from dotenv import load_dotenv
        load_dotenv(ROOT_DIR / "demos" / "agent" / ".env", override=True)
        if provider == "gemini":
            api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or settings.gemini_api_key or ""
        elif provider == "openrouter":
            api_key = os.environ.get("OPENROUTER_API_KEY") or settings.openrouter_api_key or ""
        else:
            api_key = os.environ.get("OPENAI_API_KEY") or settings.openai_api_key or ""

        self._thread = QThread()
        self._worker = ChatWorker(
            user_message=display_text,
            attached_file_path=attached,
            llm_provider=provider,
            api_key=api_key or "",
        )
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_agent_finished)
        self._worker.failed.connect(self._on_agent_failed)
        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.start()

    def _on_agent_finished(self, result: dict):
        self.send_btn.setEnabled(True)

        resp_text = result.get("final_response", "")
        injection = result.get("injection_detected", False)
        blocked = result.get("malicious_tool_blocked", False)
        executed = result.get("malicious_tool_executed", False)
        shield_active = result.get("agentshield_active", False)

        sec_event = None
        if injection or blocked or executed:
            sec_event = {
                "agentshield_active": shield_active,
                "blocked": blocked,
                "executed": executed,
                "injection": injection,
            }

        self._append_bubble("agent", resp_text, security_event=sec_event)

    def _on_agent_failed(self, error_msg: str):
        self.send_btn.setEnabled(True)
        self._append_bubble("agent", f"❌ Execution Error: {error_msg}")

    def _append_bubble(
        self,
        sender: str,
        text: str,
        attachment_name: str | None = None,
        security_event: dict | None = None,
    ):
        bubble = ChatMessageBubble(
            sender=sender,
            text=text,
            attachment_name=attachment_name,
            security_event=security_event,
        )

        # Wrap in alignment container
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        if sender == "user":
            row.addStretch(1)
            row.addWidget(bubble, 3)
        else:
            row.addWidget(bubble, 3)
            row.addStretch(1)

        # Insert before bottom stretch
        idx = max(0, self.messages_layout.count() - 1)
        self.messages_layout.insertLayout(idx, row)

        # Auto scroll to bottom
        QApplication.processEvents()
        self.scroll_area.verticalScrollBar().setValue(self.scroll_area.verticalScrollBar().maximum())

    def _clear_chat(self):
        while self.messages_layout.count() > 1:
            item = self.messages_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                while item.layout().count():
                    child = item.layout().takeAt(0)
                    if child.widget():
                        child.widget().deleteLater()
        self._add_welcome_message()

    def _open_api_key_dialog(self):
        """Quick dialog to view or set GEMINI_API_KEY and OPENROUTER_API_KEY."""
        dlg = QDialog(self)
        dlg.setWindowTitle("API Key Configuration")
        dlg.setMinimumWidth(440)
        dlg.setStyleSheet(f"background: {T.SURFACE};")

        vbox = QVBoxLayout(dlg)
        vbox.setSpacing(12)

        title = QLabel("Configure LLM API Keys")
        title.setStyleSheet(f"font-size: 15px; font-weight: 700; color: {T.TEXT};")
        vbox.addWidget(title)

        # Gemini
        vbox.addWidget(QLabel("Google Gemini API Key:"))
        gemini_inp = QLineEdit()
        gemini_inp.setEchoMode(QLineEdit.EchoMode.Password)
        gemini_inp.setText(settings.gemini_api_key or "")
        gemini_inp.setPlaceholderText("AIzaSy...")
        gemini_inp.setStyleSheet(f"border: 1px solid {T.BORDER}; border-radius: 4px; padding: 6px;")
        vbox.addWidget(gemini_inp)

        # OpenRouter
        vbox.addWidget(QLabel("OpenRouter API Key:"))
        or_inp = QLineEdit()
        or_inp.setEchoMode(QLineEdit.EchoMode.Password)
        or_inp.setText(settings.openrouter_api_key or "")
        or_inp.setPlaceholderText("sk-or-...")
        or_inp.setStyleSheet(f"border: 1px solid {T.BORDER}; border-radius: 4px; padding: 6px;")
        vbox.addWidget(or_inp)

        btn_box = QHBoxLayout()
        btn_box.addStretch()
        save_btn = QPushButton("Save Keys")
        save_btn.setStyleSheet(f"background: {T.PRIMARY}; color: #FFFFFF; font-weight: bold; padding: 6px 16px; border-radius: 4px;")

        def save_keys():
            g_key = gemini_inp.text().strip()
            o_key = or_inp.text().strip()

            env_file = ROOT_DIR / "demos" / "agent" / ".env"
            lines = env_file.read_text(encoding="utf-8").splitlines() if env_file.exists() else []

            keys_to_update = {"GEMINI_API_KEY": g_key, "OPENROUTER_API_KEY": o_key}
            new_lines = []
            for line in lines:
                k = line.split("=")[0] if "=" in line else ""
                if k in keys_to_update:
                    new_lines.append(f"{k}={keys_to_update[k]}")
                    del keys_to_update[k]
                else:
                    new_lines.append(line)
            for k, val in keys_to_update.items():
                if val:
                    new_lines.append(f"{k}={val}")

            env_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            if g_key:
                os.environ["GEMINI_API_KEY"] = g_key
                settings.gemini_api_key = g_key
            if o_key:
                os.environ["OPENROUTER_API_KEY"] = o_key
                settings.openrouter_api_key = o_key

            dlg.accept()
            QMessageBox.information(self, "Keys Saved", "API keys successfully saved to .env!")

        save_btn.clicked.connect(save_keys)
        btn_box.addWidget(save_btn)
        vbox.addLayout(btn_box)

        dlg.exec()


if __name__ == "__main__":
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyle("Fusion")
    win = AgentChatbotWindow()
    win.show()
    sys.exit(app.exec())
