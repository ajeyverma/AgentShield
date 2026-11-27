"""
AgentShield AI — Interactive Autonomous Chatbot UI (ChatGPT Style).

A modern, authentic ChatGPT-style interface featuring:
- Collapsible left sidebar with '+ New chat', recent history threads, and user profile
- Minimalist top navigation with model switcher dropdown and live AgentShield status pill
- Centered conversation canvas with welcome landing screen & 4 quick-prompt cards
- Signature floating ChatGPT capsule input bar with attachment button and circular send button
- Native support for Google Gemini Flash, OpenRouter, and Simulated models
- Automatic zero-trust security mediation by AgentShield
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QSize, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QCursor, QFont, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

# Workspace & local imports
CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = Path(__file__).resolve().parents[2]
for p in (CURRENT_DIR, ROOT_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from datetime import datetime, timezone, timedelta

# Demo agent internal imports (supports standalone folder or monorepo)
try:
    from demos.agent.icons import get_icon, get_pixmap
    from demos.agent.agent import PoisonedWebpageDemoAgent, Webpage
    from demos.agent.agentshield_adapter import (
        AgentShieldAdapter,
        check_approval_status,
        resolve_approval_record,
    )
    from demos.agent.config import settings
except ImportError:
    from icons import get_icon, get_pixmap
    from agent import PoisonedWebpageDemoAgent, Webpage
    from agentshield_adapter import (
        AgentShieldAdapter,
        check_approval_status,
        resolve_approval_record,
    )
    from config import settings

TARGET_FILE = Path(r"C:\Users\ajayv\Downloads\IMG_4023_0.webp")
SUBWAY_CODERS_LOGO_PATH = CURRENT_DIR / "subway_coders_circle.png"
if not SUBWAY_CODERS_LOGO_PATH.exists():
    SUBWAY_CODERS_LOGO_PATH = ROOT_DIR / "demos" / "agent" / "subway_coders_circle.png"


def get_subway_coders_pixmap(size: int = 28) -> QPixmap:
    """Return the circular Subway Coders emblem scaled smoothly."""
    if SUBWAY_CODERS_LOGO_PATH.exists():
        pm = QPixmap(str(SUBWAY_CODERS_LOGO_PATH))
        return pm.scaled(
            size, size, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
        )
    return get_pixmap("sparkle", size=size, color="#FFFFFF")


# ── Background Worker ────────────────────────────────────────────────────────

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
                is_poisoned=("delete" in content.lower() or "secret" in content.lower() or "whoami" in content.lower()),
                description=f"Chat message with attached {file_name if file_name else 'prompt'}",
            )

            # 3. Run Autonomous Agent:
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
                "pending_approval": getattr(ctx, "pending_approval", False),
                "approval_id": getattr(ctx, "approval_id", ""),
                "expires_at": getattr(ctx, "expires_at", ""),
                "pending_tool": getattr(ctx, "pending_tool", ""),
                "pending_action": getattr(ctx, "pending_action", ""),
                "pending_arguments": getattr(ctx, "pending_arguments", {}),
            }
            self.finished.emit(result)

        except Exception as exc:
            self.failed.emit(str(exc))


# ── ChatGPT Quick Prompt Suggestion Card ─────────────────────────────────────

class PromptCard(QFrame):
    """Clickable suggestion card shown in the empty landing state."""

    clicked = Signal(str)

    def __init__(self, title: str, subtitle: str, prompt_text: str, parent=None):
        super().__init__(parent)
        self.prompt_text = prompt_text
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setStyleSheet(
            "QFrame { background: #FFFFFF; border: 1px solid #E5E7EB; border-radius: 14px; padding: 14px 16px; } "
            "QFrame:hover { background: #F9FAFB; border-color: #D1D5DB; }"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        t_lbl = QLabel(title)
        t_lbl.setStyleSheet("font-size: 13px; font-weight: 600; color: #0D0D0D;")
        layout.addWidget(t_lbl)

        s_lbl = QLabel(subtitle)
        s_lbl.setStyleSheet("font-size: 12px; color: #6B7280;")
        s_lbl.setWordWrap(True)
        layout.addWidget(s_lbl)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.prompt_text)
        super().mousePressEvent(event)


# ── ChatGPT Style Message Row ────────────────────────────────────────────────

class ApprovalPendingCard(QFrame):
    """Interactive 1-minute countdown approval card displayed in chat when an action triggers ASK_HUMAN."""

    def __init__(
        self,
        approval_id: str,
        tool_name: str,
        action_name: str,
        arguments: dict[str, Any],
        expires_at: str | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self.approval_id = approval_id
        self.tool_name = tool_name
        self.action_name = action_name
        self.arguments = arguments
        self.is_resolved = False

        now_utc = datetime.now(timezone.utc)
        self.expires_dt = now_utc + timedelta(seconds=60)
        if expires_at:
            try:
                dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                self.expires_dt = dt
            except Exception:
                pass

        self.remaining_seconds = max(0, int((self.expires_dt - datetime.now(timezone.utc)).total_seconds()))
        self._dot_count = 1

        self._setup_ui()

        # 1-second countdown and cross-process polling timer
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._on_tick)
        self._timer.start()

        # Animated dots timer for "... pending approval"
        self._anim_timer = QTimer(self)
        self._anim_timer.setInterval(320)
        self._anim_timer.timeout.connect(self._animate_dots)
        self._anim_timer.start()

    def _setup_ui(self):
        self.setStyleSheet(
            "QFrame { background: #FFFBEB; border: 1px solid #FCD34D; border-radius: 12px; } "
            "QLabel { border: none; background: transparent; }"
        )
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(14, 12, 14, 12)
        self._layout.setSpacing(10)

        # Header row: Title + Live 60s Countdown Badge
        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        self.title_lbl = QLabel("⏳ Action Requires Human Authorization")
        self.title_lbl.setStyleSheet("font-weight: 700; font-size: 13px; color: #92400E;")
        top_row.addWidget(self.title_lbl)

        top_row.addStretch()

        self.timer_badge = QLabel(f"⏱️ {self.remaining_seconds}s remaining")
        self.timer_badge.setStyleSheet(
            "background: #FEF3C7; color: #B45309; border: 1px solid #FCD34D; "
            "font-weight: 700; font-size: 11px; padding: 3px 8px; border-radius: 6px;"
        )
        top_row.addWidget(self.timer_badge)
        self._layout.addLayout(top_row)

        # Animated status line with cycling dots
        self.status_lbl = QLabel("Status: Pending human approval...")
        self.status_lbl.setStyleSheet("font-size: 12px; font-weight: 600; color: #B45309;")
        self._layout.addWidget(self.status_lbl)

        # Action detail box
        detail_frame = QFrame()
        detail_frame.setStyleSheet(
            "background: #FFFFFF; border: 1px solid #FDE68A; border-radius: 8px; padding: 8px 10px;"
        )
        d_layout = QVBoxLayout(detail_frame)
        d_layout.setContentsMargins(6, 6, 6, 6)
        d_layout.setSpacing(4)

        target_info = self.arguments.get("path") or self.arguments.get("command") or json.dumps(self.arguments)
        target_lbl = QLabel(f"<b>Tool:</b> <code style='color:#B45309;'>{self.tool_name}</code>  •  <b>Target:</b> <code style='color:#1F2937;'>{target_info}</code>")
        target_lbl.setStyleSheet("font-size: 12px; color: #374151;")
        target_lbl.setWordWrap(True)
        d_layout.addWidget(target_lbl)
        self._layout.addWidget(detail_frame)

        # Buttons row: Approve and Reject
        self.btn_row = QHBoxLayout()
        self.btn_row.setSpacing(10)

        self.approve_btn = QPushButton("✅ Approve Action")
        self.approve_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.approve_btn.setStyleSheet(
            "QPushButton { background: #16A34A; color: #FFFFFF; border: none; font-weight: 700; "
            "font-size: 12px; border-radius: 8px; padding: 6px 14px; } "
            "QPushButton:hover { background: #15803D; }"
        )
        self.approve_btn.clicked.connect(self._on_approve_clicked)
        self.btn_row.addWidget(self.approve_btn)

        self.reject_btn = QPushButton("❌ Reject")
        self.reject_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.reject_btn.setStyleSheet(
            "QPushButton { background: #DC2626; color: #FFFFFF; border: none; font-weight: 700; "
            "font-size: 12px; border-radius: 8px; padding: 6px 14px; } "
            "QPushButton:hover { background: #B91C1C; }"
        )
        self.reject_btn.clicked.connect(self._on_reject_clicked)
        self.btn_row.addWidget(self.reject_btn)

        self.btn_row.addStretch()
        self._layout.addLayout(self.btn_row)

    def _animate_dots(self):
        if self.is_resolved:
            return
        self._dot_count = (self._dot_count % 3) + 1
        dots = "." * self._dot_count
        self.status_lbl.setText(f"Status: Pending human approval{dots}")

    def _on_tick(self):
        if self.is_resolved:
            return

        self.remaining_seconds -= 1
        if self.remaining_seconds > 0:
            self.timer_badge.setText(f"⏱️ {self.remaining_seconds}s remaining")
        else:
            self.timer_badge.setText("⏱️ Expired")

        # Check if decision occurred in external desktop Approval Center
        status_info = check_approval_status(self.approval_id)
        current_status = status_info.get("status", "pending").lower()

        if current_status == "approved":
            self._execute_and_show_approved(source="Approval Center")
        elif current_status in ("rejected", "expired"):
            self._show_rejected(reason=f"Action marked as {current_status} in Approval Center.")
        elif self.remaining_seconds <= 0:
            self._handle_timeout()

    def _on_approve_clicked(self):
        if self.is_resolved:
            return
        resolve_approval_record(self.approval_id, "approved", "Approved by user in chat")
        self._execute_and_show_approved(source="Chat")

    def _on_reject_clicked(self):
        if self.is_resolved:
            return
        resolve_approval_record(self.approval_id, "rejected", "Rejected by user in chat")
        self._show_rejected(reason="Action was explicitly rejected by user.")

    def _execute_and_show_approved(self, source: str = "Chat"):
        self.is_resolved = True
        self._timer.stop()
        self._anim_timer.stop()

        # Execute the tool safely via AgentShield adapter
        adapter = AgentShieldAdapter(use_live_backend=True)
        try:
            exec_res = adapter.execute_approved_action(self.tool_name, self.action_name, self.arguments)
            if isinstance(exec_res, dict):
                output_txt = exec_res.get("details") or exec_res.get("output") or str(exec_res)
            else:
                output_txt = str(exec_res)
        except Exception as e:
            output_txt = f"Execution error: {e}"

        # Transition card to Success state
        self.setStyleSheet(
            "QFrame { background: #F0FDF4; border: 1px solid #86EFAC; border-radius: 12px; } "
            "QLabel { border: none; background: transparent; }"
        )
        self.title_lbl.setText("✅ Approved by Human — Action Executed")
        self.title_lbl.setStyleSheet("font-weight: 700; font-size: 13px; color: #15803D;")
        self.timer_badge.setText("✅ Done")
        self.timer_badge.setStyleSheet(
            "background: #DCFCE7; color: #15803D; border: 1px solid #86EFAC; "
            "font-weight: 700; font-size: 11px; padding: 3px 8px; border-radius: 6px;"
        )
        self.status_lbl.setText(f"Authorized via {source} • Task completed successfully.")
        self.status_lbl.setStyleSheet("font-size: 12px; font-weight: 600; color: #16A34A;")

        self.approve_btn.setVisible(False)
        self.reject_btn.setVisible(False)

        out_lbl = QLabel(f"<b>Execution Result:</b>\n{output_txt}")
        out_lbl.setStyleSheet("font-size: 12px; color: #15803D; background: #FFFFFF; border: 1px solid #BBF7D0; border-radius: 6px; padding: 6px 10px;")
        out_lbl.setWordWrap(True)
        self._layout.addWidget(out_lbl)

    def _show_rejected(self, reason: str):
        self.is_resolved = True
        self._timer.stop()
        self._anim_timer.stop()

        self.setStyleSheet(
            "QFrame { background: #FEF2F2; border: 1px solid #FCA5A5; border-radius: 12px; } "
            "QLabel { border: none; background: transparent; }"
        )
        self.title_lbl.setText("🛑 Action Rejected — Execution Halted")
        self.title_lbl.setStyleSheet("font-weight: 700; font-size: 13px; color: #B91C1C;")
        self.timer_badge.setText("🛑 Blocked")
        self.timer_badge.setStyleSheet(
            "background: #FEE2E2; color: #B91C1C; border: 1px solid #FCA5A5; "
            "font-weight: 700; font-size: 11px; padding: 3px 8px; border-radius: 6px;"
        )
        self.status_lbl.setText(f"{reason} All files and systems kept safe.")
        self.status_lbl.setStyleSheet("font-size: 12px; font-weight: 600; color: #DC2626;")

        self.approve_btn.setVisible(False)
        self.reject_btn.setVisible(False)

    def _handle_timeout(self):
        self.is_resolved = True
        self._timer.stop()
        self._anim_timer.stop()
        resolve_approval_record(self.approval_id, "expired", "1-minute approval timer expired.")

        self.setStyleSheet(
            "QFrame { background: #FEF2F2; border: 1px solid #FCA5A5; border-radius: 12px; } "
            "QLabel { border: none; background: transparent; }"
        )
        self.title_lbl.setText("⏱️ Approval Timed Out (1-min) — Action Rejected")
        self.title_lbl.setStyleSheet("font-weight: 700; font-size: 13px; color: #B91C1C;")
        self.timer_badge.setText("⏱️ Expired")
        self.timer_badge.setStyleSheet(
            "background: #FEE2E2; color: #B91C1C; border: 1px solid #FCA5A5; "
            "font-weight: 700; font-size: 11px; padding: 3px 8px; border-radius: 6px;"
        )
        self.status_lbl.setText("No human decision received within 60 seconds. Action automatically rejected to prevent unauthorized changes.")
        self.status_lbl.setStyleSheet("font-size: 12px; font-weight: 600; color: #DC2626;")

        self.approve_btn.setVisible(False)
        self.reject_btn.setVisible(False)


class ChatMessageBubble(QWidget):
    """ChatGPT-style conversation turn with clean typography and badge styling."""

    def __init__(
        self,
        sender: str,  # "user" or "agent"
        text: str = "",
        attachment_name: str | None = None,
        security_event: dict | None = None,
        approval_info: dict | None = None,
        is_thinking: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self.sender = sender
        self.is_thinking = is_thinking
        self._anim_timer: QTimer | None = None
        self._dot_count = 1
        self._content_box: QVBoxLayout | None = None
        self._msg_lbl: QLabel | None = None
        self._setup_ui(text, attachment_name, security_event, approval_info)

    def _setup_ui(self, text: str, attachment_name: str | None, security_event: dict | None, approval_info: dict | None = None):
        is_user = self.sender == "user"
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 8, 0, 8)
        main_layout.setSpacing(12)

        if is_user:
            # User message: aligned to the right inside a sleek pill bubble
            main_layout.addStretch()

            bubble = QFrame()
            bubble.setStyleSheet(
                "QFrame { background-color: #F4F4F4; border-radius: 18px; padding: 10px 16px; } "
                "QLabel { color: #0D0D0D; font-size: 14px; line-height: 1.5; }"
            )
            b_layout = QVBoxLayout(bubble)
            b_layout.setContentsMargins(0, 0, 0, 0)
            b_layout.setSpacing(6)

            # Attachment Chip if any
            if attachment_name:
                chip = QFrame()
                chip_l = QHBoxLayout(chip)
                chip_l.setContentsMargins(8, 4, 8, 4)
                chip_l.setSpacing(6)
                is_vid = any(attachment_name.lower().endswith(ext) for ext in (".mp4", ".webm", ".mov", ".avi"))
                ic = QLabel()
                ic.setPixmap(get_pixmap("video" if is_vid else "paperclip", size=13, color="#4B5563"))
                chip_l.addWidget(ic)
                txt = QLabel(attachment_name)
                txt.setStyleSheet("font-size: 11px; font-weight: 600; color: #1F2937;")
                chip_l.addWidget(txt)
                chip.setStyleSheet("background: #E5E7EB; border-radius: 6px;")
                b_layout.addWidget(chip)

            msg_lbl = QLabel(text)
            msg_lbl.setWordWrap(True)
            msg_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            b_layout.addWidget(msg_lbl)

            main_layout.addWidget(bubble)

        else:
            # Assistant message: aligned to the left with Subway Coders circle avatar
            avatar = QLabel()
            avatar.setFixedSize(30, 30)
            avatar.setPixmap(get_subway_coders_pixmap(size=30))
            avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)

            avatar_col = QVBoxLayout()
            avatar_col.setContentsMargins(0, 2, 0, 0)
            avatar_col.addWidget(avatar)
            avatar_col.addStretch()
            main_layout.addLayout(avatar_col)

            self._content_box = QVBoxLayout()
            self._content_box.setContentsMargins(0, 0, 0, 0)
            self._content_box.setSpacing(8)

            name_lbl = QLabel("Subway Coders")
            name_lbl.setStyleSheet("font-size: 13px; font-weight: 700; color: #0D0D0D;")
            self._content_box.addWidget(name_lbl)

            self._msg_lbl = QLabel()
            self._msg_lbl.setWordWrap(True)
            self._msg_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self._content_box.addWidget(self._msg_lbl)

            if self.is_thinking:
                self._msg_lbl.setText("...")
                self._msg_lbl.setStyleSheet("font-size: 18px; font-weight: 700; color: #9CA3AF; letter-spacing: 2px;")
                self._anim_timer = QTimer(self)
                self._anim_timer.setInterval(320)
                self._anim_timer.timeout.connect(self._step_thinking_animation)
                self._anim_timer.start()
            else:
                self._apply_text_and_style(text)
                if approval_info:
                    self._content_box.addWidget(
                        ApprovalPendingCard(
                            approval_id=approval_info.get("approval_id", ""),
                            tool_name=approval_info.get("tool_name", ""),
                            action_name=approval_info.get("action_name", "execute"),
                            arguments=approval_info.get("arguments", {}),
                            expires_at=approval_info.get("expires_at"),
                        )
                    )
                elif security_event:
                    self._content_box.addWidget(self._create_security_card(security_event))

            main_layout.addLayout(self._content_box)
            main_layout.addStretch()

    def _step_thinking_animation(self):
        """Cycle typing animation through . -> .. -> ... while waiting for model."""
        self._dot_count = (self._dot_count % 3) + 1
        if self._msg_lbl:
            self._msg_lbl.setText("." * self._dot_count)

    def _apply_text_and_style(self, text: str):
        if not self._msg_lbl:
            return
        self._msg_lbl.setText(text)
        if "Terminal Output" in text or "```" in text:
            self._msg_lbl.setStyleSheet(
                "font-size: 14px; line-height: 1.6; color: #F4F4F5; "
                "background: #18181B; border-radius: 10px; padding: 12px; font-family: Consolas, monospace;"
            )
        else:
            self._msg_lbl.setStyleSheet("font-size: 14px; line-height: 1.6; color: #0D0D0D; letter-spacing: normal;")

    def set_response(self, text: str, security_event: dict | None = None, approval_info: dict | None = None):
        """Update animated thinking bubble with actual assistant response."""
        if self._anim_timer:
            self._anim_timer.stop()
            self._anim_timer.deleteLater()
            self._anim_timer = None
        self.is_thinking = False

        self._apply_text_and_style(text)

        if approval_info and self._content_box:
            self._content_box.addWidget(
                ApprovalPendingCard(
                    approval_id=approval_info.get("approval_id", ""),
                    tool_name=approval_info.get("tool_name", ""),
                    action_name=approval_info.get("action_name", "execute"),
                    arguments=approval_info.get("arguments", {}),
                    expires_at=approval_info.get("expires_at"),
                )
            )
        elif security_event and self._content_box:
            self._content_box.addWidget(self._create_security_card(security_event))

    def _create_security_card(self, security_event: dict) -> QFrame:
        """Construct security evaluation summary card."""
        sec_card = QFrame()
        sec_card_l = QVBoxLayout(sec_card)
        sec_card_l.setContentsMargins(12, 10, 12, 10)
        sec_card_l.setSpacing(4)

        shield_active = security_event.get("agentshield_active", False)
        blocked = security_event.get("blocked", False)
        executed = security_event.get("executed", False)

        if shield_active and blocked:
            sec_card.setStyleSheet("background: #F0FDF4; border: 1px solid #86EFAC; border-radius: 10px;")
            status_t = "🛡️ Blocked by AgentShield Runtime Security"
            status_c = "#15803D"
            desc = "AgentShield inspected the incoming prompt, identified unauthorized tool execution, and BLOCKED the attack."
        elif not shield_active and executed:
            sec_card.setStyleSheet("background: #FEF2F2; border: 1px solid #FCA5A5; border-radius: 10px;")
            status_t = "⚠️ Exploited: AgentShield is Offline"
            status_c = "#B91C1C"
            desc = "AgentShield is not running. The agent executed the unauthorized directive without security boundaries."
        else:
            sec_card.setStyleSheet("background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 10px;")
            status_t = "ℹ️ Security Status: Safe Content"
            status_c = "#374151"
            desc = "No malicious injection detected in message content."

        title = QLabel(status_t)
        title.setStyleSheet(f"font-weight: 700; font-size: 12px; color: {status_c};")
        body = QLabel(desc)
        body.setStyleSheet(f"font-size: 12px; color: {status_c};")
        body.setWordWrap(True)
        sec_card_l.addWidget(title)
        sec_card_l.addWidget(body)
        return sec_card


# ── Main ChatGPT-Style Window ────────────────────────────────────────────────

class AgentChatbotWindow(QWidget):
    """ChatGPT-style interactive autonomous agent interface with AgentShield integration."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._attached_file_path: str | None = None
        self._thread: QThread | None = None
        self._worker: ChatWorker | None = None
        self._active_thinking_bubble: ChatMessageBubble | None = None
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("Subway Coders — Autonomous AI Agent")
        self.resize(920, 750)
        self.setMinimumSize(640, 520)
        if SUBWAY_CODERS_LOGO_PATH.exists():
            self.setWindowIcon(QIcon(str(SUBWAY_CODERS_LOGO_PATH)))
        self.setStyleSheet("QWidget { font-family: 'Segoe UI', -apple-system, sans-serif; background: #FFFFFF; }")

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── 1. Top Minimalist Navbar ─────────────────────────────────────────
        navbar = QFrame()
        navbar.setFixedHeight(56)
        navbar.setStyleSheet("background: #FFFFFF; border-bottom: 1px solid #F3F4F6;")
        nav_layout = QHBoxLayout(navbar)
        nav_layout.setContentsMargins(20, 0, 20, 0)
        nav_layout.setSpacing(12)

        # Subway Coders Emblem Logo
        logo_icon = QLabel()
        logo_icon.setFixedSize(30, 30)
        logo_icon.setPixmap(get_subway_coders_pixmap(size=30))
        logo_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        nav_layout.addWidget(logo_icon)

        # Model Selector Dropdown
        self.engine_combo = QComboBox()
        self.engine_combo.addItem("Subway Coders (Gemini Flash)", "gemini")
        self.engine_combo.addItem("Subway Coders (OpenRouter Llama 3.3)", "openrouter")
        self.engine_combo.addItem("Subway Coders (Simulated Sandbox)", "simulated")
        self.engine_combo.setStyleSheet(
            "QComboBox { background: transparent; font-size: 15px; font-weight: 700; color: #0D0D0D; "
            "border: none; border-radius: 8px; padding: 6px 10px; } "
            "QComboBox:hover { background: #F4F4F4; } "
            "QComboBox::drop-down { border: none; } "
            "QComboBox QAbstractItemView { background: #FFFFFF; border: 1px solid #E5E7EB; border-radius: 8px; padding: 4px; }"
        )
        nav_layout.addWidget(self.engine_combo)

        nav_layout.addStretch()

        # Live AgentShield Status Pill (No toggle button)
        self.gateway_status_lbl = QLabel()
        self.gateway_status_lbl.setFixedHeight(28)
        self._update_gateway_status()
        nav_layout.addWidget(self.gateway_status_lbl)

        # API Key Settings Button
        key_btn = QPushButton("API Key")
        key_btn.setFixedHeight(32)
        key_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        key_btn.setStyleSheet(
            "QPushButton { background: #F4F4F4; color: #374151; border: 1px solid #E5E7EB; "
            "border-radius: 8px; font-size: 12px; font-weight: 600; padding: 0 12px; } "
            "QPushButton:hover { background: #E5E7EB; color: #0D0D0D; }"
        )
        key_btn.clicked.connect(self._open_api_key_dialog)
        nav_layout.addWidget(key_btn)

        # Timer to poll AgentShield backend
        self._status_timer = QTimer(self)
        self._status_timer.setInterval(2500)
        self._status_timer.timeout.connect(self._update_gateway_status)
        self._status_timer.start()

        main_layout.addWidget(navbar)

        # ── 3. Centered Chat Content Canvas ──────────────────────────────────
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("QScrollArea { border: none; background: #FFFFFF; }")

        self.scroll_content = QWidget()
        self.scroll_content.setStyleSheet("background: #FFFFFF;")
        self.content_vbox = QVBoxLayout(self.scroll_content)
        self.content_vbox.setContentsMargins(0, 0, 0, 0)
        self.content_vbox.setSpacing(0)

        # Inner Centered Wrapper (Constraint to 760px for reading comfort)
        center_row = QHBoxLayout()
        center_row.setContentsMargins(0, 0, 0, 0)
        center_row.addStretch(1)

        self.chat_column = QWidget()
        self.chat_column.setFixedWidth(760)
        self.chat_column_layout = QVBoxLayout(self.chat_column)
        self.chat_column_layout.setContentsMargins(10, 20, 10, 20)
        self.chat_column_layout.setSpacing(14)

        # A. Empty State Landing View
        self.landing_widget = QWidget()
        landing_layout = QVBoxLayout(self.landing_widget)
        landing_layout.setContentsMargins(0, 60, 0, 20)
        landing_layout.setSpacing(16)
        landing_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        center_icon = QLabel()
        center_icon.setFixedSize(68, 68)
        center_icon.setPixmap(get_subway_coders_pixmap(size=68))
        center_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        landing_layout.addWidget(center_icon, alignment=Qt.AlignmentFlag.AlignCenter)

        landing_title = QLabel("What can Subway Coders help with today?")
        landing_title.setStyleSheet("font-size: 24px; font-weight: 700; color: #0D0D0D; margin-top: 6px;")
        landing_layout.addWidget(landing_title, alignment=Qt.AlignmentFlag.AlignCenter)

        # 2x2 Prompt Suggestion Grid
        grid_widget = QWidget()
        grid = QGridLayout(grid_widget)
        grid.setSpacing(12)
        grid.setContentsMargins(0, 16, 0, 0)

        c1 = PromptCard("Run Terminal Inspection", "Execute whoami to verify current system user", "Run shell command whoami")
        c1.clicked.connect(self._send_quick_prompt)
        grid.addWidget(c1, 0, 0)

        c2 = PromptCard("Test Shield Protection", "Attempt unauthorized deletion of target file", "Delete C:\\Users\\ajayv\\Downloads\\IMG_4023_0.webp")
        c2.clicked.connect(self._send_quick_prompt)
        grid.addWidget(c2, 0, 1)

        c3 = PromptCard("Inspect Network Config", "Execute ipconfig to check network parameters", "Run shell command ipconfig")
        c3.clicked.connect(self._send_quick_prompt)
        grid.addWidget(c3, 1, 0)

        c4 = PromptCard("Scan Document File", "Upload a document to detect hidden prompt injections", "Analyze attached file for indirect prompt injections")
        c4.clicked.connect(self._browse_and_send_file)
        grid.addWidget(c4, 1, 1)

        landing_layout.addWidget(grid_widget)
        self.chat_column_layout.addWidget(self.landing_widget)

        # B. Message History Layout
        self.messages_container = QWidget()
        self.messages_layout = QVBoxLayout(self.messages_container)
        self.messages_layout.setContentsMargins(0, 0, 0, 0)
        self.messages_layout.setSpacing(16)
        self.messages_layout.addStretch(1)
        self.messages_container.setVisible(False)
        self.chat_column_layout.addWidget(self.messages_container)

        center_row.addWidget(self.chat_column)
        center_row.addStretch(1)

        self.content_vbox.addLayout(center_row)
        self.scroll_area.setWidget(self.scroll_content)
        main_layout.addWidget(self.scroll_area, 1)

        # ── 4. ChatGPT Signature Floating Input Capsule ──────────────────────
        input_wrapper = QFrame()
        input_wrapper.setStyleSheet("background: #FFFFFF;")
        input_wrap_l = QVBoxLayout(input_wrapper)
        input_wrap_l.setContentsMargins(18, 0, 18, 12)
        input_wrap_l.setSpacing(6)

        # Capsule Frame
        capsule_row = QHBoxLayout()
        capsule_row.addStretch(1)

        self.capsule = QFrame()
        self.capsule.setFixedWidth(760)
        self.capsule.setStyleSheet(
            "QFrame { background: #F4F4F4; border: 1px solid #E5E7EB; border-radius: 24px; padding: 6px 12px; }"
        )
        capsule_layout = QVBoxLayout(self.capsule)
        capsule_layout.setContentsMargins(12, 6, 12, 6)
        capsule_layout.setSpacing(6)

        # Attachment Chip Preview (Inside capsule)
        self.attach_chip = QFrame()
        self.attach_chip.setVisible(False)
        self.attach_chip.setStyleSheet("background: #E5E7EB; border-radius: 8px; padding: 4px 8px;")
        chip_layout = QHBoxLayout(self.attach_chip)
        chip_layout.setContentsMargins(4, 2, 4, 2)
        chip_layout.setSpacing(6)

        self.chip_icon = QLabel()
        chip_layout.addWidget(self.chip_icon)

        self.chip_name = QLabel()
        self.chip_name.setStyleSheet("font-size: 11px; font-weight: 600; color: #1F2937;")
        chip_layout.addWidget(self.chip_name)
        chip_layout.addStretch()

        remove_chip_btn = QPushButton("✕")
        remove_chip_btn.setFixedSize(18, 18)
        remove_chip_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        remove_chip_btn.setStyleSheet(
            "QPushButton { background: transparent; border: none; font-size: 11px; color: #6B7280; font-weight: bold; } "
            "QPushButton:hover { color: #0D0D0D; }"
        )
        remove_chip_btn.clicked.connect(self._clear_attachment)
        chip_layout.addWidget(remove_chip_btn)

        capsule_layout.addWidget(self.attach_chip)

        # Bottom Input Controls Row
        ctrl_row = QHBoxLayout()
        ctrl_row.setContentsMargins(0, 0, 0, 0)
        ctrl_row.setSpacing(8)

        # '+' Attachment Button
        self.attach_btn = QPushButton()
        self.attach_btn.setIcon(get_icon("plus", size=16, color="#4B5563"))
        self.attach_btn.setFixedSize(32, 32)
        self.attach_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.attach_btn.setToolTip("Attach file or video")
        self.attach_btn.setStyleSheet(
            "QPushButton { background: #E5E7EB; border: none; border-radius: 16px; } "
            "QPushButton:hover { background: #D1D5DB; }"
        )
        self.attach_btn.clicked.connect(self._show_attachment_menu)
        ctrl_row.addWidget(self.attach_btn)

        # Message Input
        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("Message Agent...")
        self.msg_input.setStyleSheet(
            "QLineEdit { background: transparent; border: none; font-size: 14px; color: #0D0D0D; padding: 6px 4px; }"
        )
        self.msg_input.returnPressed.connect(self._send_message)
        self.msg_input.textChanged.connect(self._on_input_text_changed)
        ctrl_row.addWidget(self.msg_input, 1)

        # Circular Black '↑' Send Button (ChatGPT Signature)
        self.send_btn = QPushButton()
        self.send_btn.setIcon(get_icon("arrow-up", size=16, color="#FFFFFF"))
        self.send_btn.setFixedSize(32, 32)
        self.send_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.send_btn.setStyleSheet(
            "QPushButton { background: #0D0D0D; border: none; border-radius: 16px; } "
            "QPushButton:hover { background: #27272A; } "
            "QPushButton:disabled { background: #E5E7EB; }"
        )
        self.send_btn.setEnabled(False)
        self.send_btn.clicked.connect(self._send_message)
        ctrl_row.addWidget(self.send_btn)

        capsule_layout.addLayout(ctrl_row)

        capsule_row.addWidget(self.capsule)
        capsule_row.addStretch(1)
        input_wrap_l.addLayout(capsule_row)

        # Footer Disclaimer (ChatGPT style)
        footer_lbl = QLabel("AgentShield monitors and verifies all agent actions. Verify critical outputs.")
        footer_lbl.setStyleSheet("font-size: 11px; color: #9CA3AF; text-align: center;")
        footer_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        input_wrap_l.addWidget(footer_lbl)

        main_layout.addWidget(input_wrapper)

    # ── Helper & UI Actions ──────────────────────────────────────────────────

    def _on_input_text_changed(self, text: str):
        has_content = bool(text.strip() or self._attached_file_path)
        self.send_btn.setEnabled(has_content)
        if has_content:
            self.send_btn.setIcon(get_icon("arrow-up", size=16, color="#FFFFFF"))
            self.send_btn.setStyleSheet(
                "QPushButton { background: #0D0D0D; border: none; border-radius: 16px; } "
                "QPushButton:hover { background: #27272A; }"
            )
        else:
            self.send_btn.setIcon(get_icon("arrow-up", size=16, color="#9CA3AF"))
            self.send_btn.setStyleSheet(
                "QPushButton { background: #E5E7EB; border: none; border-radius: 16px; }"
            )

    def _show_attachment_menu(self):
        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background: #FFFFFF; border: 1px solid #E5E7EB; border-radius: 8px; padding: 4px; } "
            "QMenu::item { padding: 6px 20px; font-size: 13px; color: #0D0D0D; } "
            "QMenu::item:selected { background: #F3F4F6; border-radius: 4px; }"
        )
        file_act = menu.addAction("Upload Document / Webpage...")
        vid_act = menu.addAction("Upload Video File...")

        action = menu.exec(self.attach_btn.mapToGlobal(self.attach_btn.rect().topLeft()))
        if action == file_act:
            self._browse_file()
        elif action == vid_act:
            self._browse_video()

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Document / File",
            str(ROOT_DIR),
            "Documents & Web (*.html *.htm *.txt *.pdf *.py *.json *.md);;All Files (*.*)",
        )
        if path:
            self._set_attachment(path, is_video=False)

    def _browse_video(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Video File",
            str(ROOT_DIR),
            "Video Files (*.mp4 *.webm *.mov *.avi *.mkv);;All Files (*.*)",
        )
        if path:
            self._set_attachment(path, is_video=True)

    def _browse_and_send_file(self):
        self._browse_file()
        if self._attached_file_path:
            self.msg_input.setText("Analyze attached file for indirect prompt injections and report findings.")
            self._send_message()

    def _set_attachment(self, path: str, is_video: bool):
        self._attached_file_path = path
        p = Path(path)
        size_str = f"{p.stat().st_size / 1024:.1f} KB" if not is_video else f"{p.stat().st_size / (1024 * 1024):.2f} MB"
        self.chip_icon.setPixmap(get_pixmap("video" if is_video else "paperclip", size=13, color="#4B5563"))
        self.chip_name.setText(f"{p.name} ({size_str})")
        self.attach_chip.setVisible(True)
        self._on_input_text_changed(self.msg_input.text())

    def _clear_attachment(self):
        self._attached_file_path = None
        self.attach_chip.setVisible(False)
        self._on_input_text_changed(self.msg_input.text())

    def _send_quick_prompt(self, prompt: str):
        self.msg_input.setText(prompt)
        self._send_message()

    def _start_new_chat(self):
        # Clear messages
        while self.messages_layout.count() > 1:
            item = self.messages_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                while item.layout().count():
                    child = item.layout().takeAt(0)
                    if child.widget():
                        child.widget().deleteLater()

        self._clear_attachment()
        self.msg_input.clear()
        self.messages_container.setVisible(False)
        self.landing_widget.setVisible(True)

    def _update_gateway_status(self):
        """Automatically checks if the AgentShield security backend is running on localhost:8000."""
        import httpx
        try:
            r = httpx.get(f"{settings.backend_url}/api/v1/health", timeout=0.6)
            is_running = (r.status_code == 200)
        except Exception:
            is_running = False

        if is_running:
            self.gateway_status_lbl.setText("🛡️ AgentShield Active")
            self.gateway_status_lbl.setStyleSheet(
                "background: #DCFCE7; color: #15803D; border: 1px solid #86EFAC; "
                "border-radius: 14px; font-weight: 700; font-size: 11px; padding: 4px 12px;"
            )
            self.gateway_status_lbl.setToolTip("AgentShield security service is running on port 8000. All agent actions are actively inspected.")
        else:
            self.gateway_status_lbl.setText("⚪ AgentShield Offline")
            self.gateway_status_lbl.setStyleSheet(
                "background: #F3F4F6; color: #6B7280; border: 1px solid #E5E7EB; "
                "border-radius: 14px; font-weight: 600; font-size: 11px; padding: 4px 12px;"
            )
            self.gateway_status_lbl.setToolTip("AgentShield is not running. The agent operates independently without runtime security.")

    def _send_message(self):
        text = self.msg_input.text().strip()
        attached = self._attached_file_path

        if not text and not attached:
            return

        display_text = text or (f"Analyze attached file: {Path(attached).name}" if attached else "")
        attach_name = Path(attached).name if attached else None

        # Switch from landing state to active message canvas
        self.landing_widget.setVisible(False)
        self.messages_container.setVisible(True)

        # Add user message bubble
        self._append_bubble("user", display_text, attachment_name=attach_name)
        self.msg_input.clear()
        self._clear_attachment()

        # Show animated thinking indicator with Subway Coders logo and name
        self._active_thinking_bubble = self._append_bubble("agent", "", is_thinking=True)

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
        pending_approval = result.get("pending_approval", False)

        sec_event = None
        if injection or blocked or executed:
            sec_event = {
                "agentshield_active": shield_active,
                "blocked": blocked,
                "executed": executed,
                "injection": injection,
            }

        approval_info = None
        if pending_approval:
            approval_info = {
                "approval_id": result.get("approval_id"),
                "tool_name": result.get("pending_tool"),
                "action_name": result.get("pending_action", "execute"),
                "arguments": result.get("pending_arguments", {}),
                "expires_at": result.get("expires_at"),
            }

        if self._active_thinking_bubble:
            self._active_thinking_bubble.set_response(resp_text, security_event=sec_event, approval_info=approval_info)
            self._active_thinking_bubble = None
        else:
            self._append_bubble("agent", resp_text, security_event=sec_event, approval_info=approval_info)

        QTimer.singleShot(50, self._scroll_to_bottom)

    def _on_agent_failed(self, error_msg: str):
        self.send_btn.setEnabled(True)
        err = f"❌ Execution Error: {error_msg}"
        if self._active_thinking_bubble:
            self._active_thinking_bubble.set_response(err)
            self._active_thinking_bubble = None
        else:
            self._append_bubble("agent", err)

        QTimer.singleShot(50, self._scroll_to_bottom)

    def _scroll_to_bottom(self):
        QApplication.processEvents()
        self.scroll_area.verticalScrollBar().setValue(self.scroll_area.verticalScrollBar().maximum())

    def _append_bubble(
        self,
        sender: str,
        text: str,
        attachment_name: str | None = None,
        security_event: dict | None = None,
        approval_info: dict | None = None,
        is_thinking: bool = False,
    ) -> ChatMessageBubble:
        bubble = ChatMessageBubble(
            sender=sender,
            text=text,
            attachment_name=attachment_name,
            security_event=security_event,
            approval_info=approval_info,
            is_thinking=is_thinking,
        )

        idx = max(0, self.messages_layout.count() - 1)
        self.messages_layout.insertWidget(idx, bubble)

        # Auto scroll to bottom
        self._scroll_to_bottom()
        return bubble

    def _open_api_key_dialog(self):
        """Dialog to view or set GEMINI_API_KEY and OPENROUTER_API_KEY."""
        dlg = QDialog(self)
        dlg.setWindowTitle("API Key Configuration")
        dlg.setMinimumWidth(440)
        dlg.setStyleSheet("background: #FFFFFF;")

        vbox = QVBoxLayout(dlg)
        vbox.setSpacing(12)

        title = QLabel("Configure LLM API Keys")
        title.setStyleSheet("font-size: 15px; font-weight: 700; color: #0D0D0D;")
        vbox.addWidget(title)

        # Gemini
        vbox.addWidget(QLabel("Google Gemini API Key:"))
        gemini_inp = QLineEdit()
        gemini_inp.setEchoMode(QLineEdit.EchoMode.Password)
        gemini_inp.setText(settings.gemini_api_key or "")
        gemini_inp.setPlaceholderText("AIzaSy...")
        gemini_inp.setStyleSheet("border: 1px solid #E5E7EB; border-radius: 6px; padding: 8px;")
        vbox.addWidget(gemini_inp)

        # OpenRouter
        vbox.addWidget(QLabel("OpenRouter API Key:"))
        or_inp = QLineEdit()
        or_inp.setEchoMode(QLineEdit.EchoMode.Password)
        or_inp.setText(settings.openrouter_api_key or "")
        or_inp.setPlaceholderText("sk-or-...")
        or_inp.setStyleSheet("border: 1px solid #E5E7EB; border-radius: 6px; padding: 8px;")
        vbox.addWidget(or_inp)

        btn_box = QHBoxLayout()
        btn_box.addStretch()
        save_btn = QPushButton("Save Keys")
        save_btn.setStyleSheet("background: #000000; color: #FFFFFF; font-weight: bold; padding: 8px 18px; border-radius: 6px;")

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
            QMessageBox.information(self, "Keys Saved", "API keys successfully saved!")

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
