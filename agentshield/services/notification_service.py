"""
AgentShield AI — Notification Service (WhatsApp CLI + Desktop URI Scheme).

Dispatches complete, detailed human-in-the-loop security alerts with all approval metadata.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import threading
import urllib.parse
from pathlib import Path
from typing import Any

from agentshield.core.config import settings

logger = logging.getLogger("agentshield.notifications")


class NotificationService:
    """Dispatches human approval alerts to WhatsApp CLI or Desktop app."""

    def __init__(self):
        self._sent_approvals: set[str] = set()
        self._lock = threading.Lock()
        self._refresh_config()

    def _refresh_config(self) -> None:
        try:
            from dotenv import load_dotenv
            load_dotenv(override=False)
        except Exception:
            pass

        raw_phone = os.getenv("WHATSAPP_PHONE") or "918303719864"
        cleaned = "".join(ch for ch in raw_phone if ch.isdigit())
        self.phone = cleaned if cleaned else "918303719864"

    def send_approval_alert_sync(
        self,
        approval_id: str,
        tool_name: str,
        operation: str = "execute",
        reasons: list[str] | None = None,
        risk_level: str = "HIGH",
        pin_code: str | None = None,
        resource: str | None = None,
        arguments: dict[str, Any] | None = None,
        expires_at: str | None = None,
    ) -> None:
        """Fire-and-forget sync wrapper that safely dispatches approval alert strictly once."""
        if not approval_id:
            return

        with self._lock:
            if approval_id in self._sent_approvals:
                logger.debug("Approval alert already dispatched for %s", approval_id)
                return
            self._sent_approvals.add(approval_id)

        def _dispatch():
            self._execute_whatsapp_send(
                approval_id=approval_id,
                tool_name=tool_name,
                operation=operation,
                reasons=reasons,
                risk_level=risk_level,
                resource=resource,
                arguments=arguments,
                expires_at=expires_at,
            )

        t = threading.Thread(target=_dispatch, daemon=True, name=f"whatsapp-cmd-{approval_id[:8]}")
        t.start()

    async def send_approval_alert(
        self,
        approval_id: str,
        tool_name: str,
        operation: str,
        reasons: list[str] | None = None,
        risk_level: str = "HIGH",
        pin_code: str | None = None,
        resource: str | None = None,
        arguments: dict[str, Any] | None = None,
        expires_at: str | None = None,
        skip_dedup_check: bool = False,
    ) -> bool:
        """Async compatibility wrapper."""
        if not skip_dedup_check:
            with self._lock:
                if approval_id in self._sent_approvals:
                    return True
                self._sent_approvals.add(approval_id)

        def _dispatch():
            self._execute_whatsapp_send(
                approval_id=approval_id,
                tool_name=tool_name,
                operation=operation,
                reasons=reasons,
                risk_level=risk_level,
                resource=resource,
                arguments=arguments,
                expires_at=expires_at,
            )

        t = threading.Thread(target=_dispatch, daemon=True)
        t.start()
        return True

    def _find_mudslide_js(self) -> tuple[str | None, str | None]:
        """Locate node executable and mudslide index.js to bypass Windows cmd.exe newline truncation."""
        node_exe = shutil.which("node")
        if not node_exe:
            return None, None

        candidates = [
            Path(os.path.expandvars(r"%APPDATA%\npm\node_modules\mudslide\build\index.js")),
            Path(os.path.expandvars(r"%LOCALAPPDATA%\npm\node_modules\mudslide\build\index.js")),
            Path(os.path.expandvars(r"%ProgramFiles%\nodejs\node_modules\mudslide\build\index.js")),
        ]
        for c in candidates:
            if c.exists():
                return node_exe, str(c)

        # Try resolving via npm root -g
        try:
            r = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                p = Path(r.stdout.strip()) / "mudslide" / "build" / "index.js"
                if p.exists():
                    return node_exe, str(p)
        except Exception:
            pass

        return None, None

    def _execute_whatsapp_send(
        self,
        approval_id: str,
        tool_name: str,
        operation: str,
        reasons: list[str] | None = None,
        risk_level: str = "HIGH",
        resource: str | None = None,
        arguments: dict[str, Any] | None = None,
        expires_at: str | None = None,
    ) -> None:
        self._refresh_config()
        phone = self.phone

        reason_text = reasons[0] if reasons else "Destructive operation requires human authorization."
        target_text = resource or "N/A"
        args_text = json.dumps(arguments, indent=None) if arguments else "{}"
        exp_text = expires_at or "In 60 seconds"

        # Complete, detailed WhatsApp security message containing everything from the approval section
        alert_text = (
            f"🛡️ *AgentShield AI — Action Requires Human Authorization*\n\n"
            f"📋 *Approval Request Details:*\n"
            f"• *Tool Name:* `{tool_name}`\n"
            f"• *Operation:* `{operation}`\n"
            f"• *Risk Level:* *{risk_level.upper()}*\n"
            f"• *Target Resource:* `{target_text}`\n"
            f"• *Arguments:* `{args_text}`\n\n"
            f"⚠️ *Security Reason / Policy Check:*\n"
            f"{reason_text}\n\n"
            f"⏱️ *Countdown:* 60-Second Approval Window Active\n"
            f"📅 *Expires At:* `{exp_text}`\n"
            f"🔑 *Approval ID:* `{approval_id}`\n\n"
            f"👉 *Action Required:* Please open the AgentShield Control Center or the Subway Coders Chatbot to Authorize (Approve) or Reject this action before the timer expires."
        )

        logger.info("Dispatching full WhatsApp approval alert for %s (Approval: %s)", phone, approval_id)

        # 1. Direct Node.js invocation of mudslide (bypasses Windows cmd.exe newline truncation)
        node_exe, index_js = self._find_mudslide_js()
        if node_exe and index_js:
            try:
                res = subprocess.run(
                    [node_exe, index_js, "send", phone, alert_text],
                    capture_output=True,
                    text=True,
                    timeout=25,
                )
                if res.returncode == 0:
                    logger.info("Successfully sent full WhatsApp approval details via mudslide to %s", phone)
                    return
                else:
                    logger.warning("mudslide direct node send failed: %s", res.stderr.strip())
            except Exception as exc:
                logger.warning("mudslide direct node exception: %s", exc)

        # 2. Mudslide CLI binary fallback
        mudslide_cmd = shutil.which("mudslide") or shutil.which("mudslide.cmd")
        if mudslide_cmd:
            try:
                res = subprocess.run(
                    [mudslide_cmd, "send", phone, alert_text],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                if res.returncode == 0:
                    logger.info("Successfully sent WhatsApp alert via mudslide CLI to %s", phone)
                    return
            except Exception as exc:
                logger.warning("mudslide CLI dispatch exception: %s", exc)

        # 3. Fallback: Desktop URI Automation
        encoded_text = urllib.parse.quote(alert_text)
        ps_command = (
            f'Start-Process "whatsapp://send?phone={phone}&text={encoded_text}"; '
            f'Start-Sleep -Seconds 4; '
            f'$ws = New-Object -ComObject WScript.Shell; '
            f'$ws.SendKeys("{{ENTER}}"); '
            f'Start-Sleep -Seconds 2; '
            f'$ws.SendKeys("{{ENTER}}")'
        )

        try:
            subprocess.Popen(["powershell", "-NoProfile", "-Command", ps_command])
            logger.info("Fallback WhatsApp desktop alert launched for %s", phone)
        except Exception as exc:
            logger.error("Failed to execute fallback WhatsApp alert for %s: %s", phone, exc)


notification_service = NotificationService()
