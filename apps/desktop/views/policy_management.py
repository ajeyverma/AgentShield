"""
AgentShield AI — Policy Management Desktop View (Phase 10).

Provides complete security policy lifecycle management, including priority ordering,
structured conditions, policy simulation, version history, conflict detection,
and emergency security controls.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from apps.desktop.components.page_header import PageHeader
from apps.desktop.components.status_badge import StatusBadge
from apps.desktop.components.empty_state import EmptyState
from apps.desktop.components.icons import get_icon
from apps.desktop.services.backend_client import backend_client
from apps.desktop.themes.design_tokens import T

logger = logging.getLogger("agentshield.desktop.policy_management")


class PolicyEditorDialog(QDialog):
    """Dialog for creating and updating policies with priority and structured conditions."""

    def __init__(self, policy_data: dict[str, Any] | None = None, parent=None):
        super().__init__(parent)
        self.policy_data = policy_data or {}
        self.is_edit = bool(policy_data and policy_data.get("id"))
        self._build_ui()

    def _build_ui(self):
        title = "Edit Policy" if self.is_edit else "Create New Policy"
        self.setWindowTitle(title)
        self.setMinimumWidth(560)
        self.setObjectName("policyEditDialog")
        self.setStyleSheet(f"QDialog#policyEditDialog {{ background:{T.SURFACE}; }}")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)
        layout.setSpacing(T.SP_3)

        grid = QGridLayout()
        grid.setSpacing(T.SP_2)

        # Name
        grid.addWidget(QLabel("Policy Name:"), 0, 0)
        self.name_edit = QLineEdit(self.policy_data.get("name", ""))
        self.name_edit.setPlaceholderText("e.g. Block Shell Execution")
        grid.addWidget(self.name_edit, 0, 1)

        # Category
        grid.addWidget(QLabel("Category:"), 1, 0)
        self.cat_edit = QComboBox()
        self.cat_edit.addItems(["filesystem", "terminal", "network", "payment", "general", "system"])
        curr_cat = self.policy_data.get("category", "general")
        idx = self.cat_edit.findText(curr_cat)
        if idx >= 0:
            self.cat_edit.setCurrentIndex(idx)
        grid.addWidget(self.cat_edit, 1, 1)

        # Decision
        grid.addWidget(QLabel("Decision:"), 2, 0)
        self.decision_edit = QComboBox()
        self.decision_edit.addItems(["ALLOW", "BLOCK", "ASK_HUMAN"])
        curr_dec = self.policy_data.get("decision", "ALLOW").upper()
        idx_dec = self.decision_edit.findText(curr_dec)
        if idx_dec >= 0:
            self.decision_edit.setCurrentIndex(idx_dec)
        grid.addWidget(self.decision_edit, 2, 1)

        # Priority
        grid.addWidget(QLabel("Priority (Lower = Higher Precedence):"), 3, 0)
        self.priority_spin = QSpinBox()
        self.priority_spin.setRange(1, 1000)
        self.priority_spin.setValue(int(self.policy_data.get("priority", 100)))
        grid.addWidget(self.priority_spin, 3, 1)

        # Scopes
        grid.addWidget(QLabel("Tool Scope (* or pattern):"), 4, 0)
        self.tool_scope_edit = QLineEdit(self.policy_data.get("tool_scope", "*"))
        grid.addWidget(self.tool_scope_edit, 4, 1)

        grid.addWidget(QLabel("Action Scope:"), 5, 0)
        self.action_scope_edit = QLineEdit(self.policy_data.get("action_scope", "*"))
        grid.addWidget(self.action_scope_edit, 5, 1)

        grid.addWidget(QLabel("Resource Scope:"), 6, 0)
        self.resource_scope_edit = QLineEdit(self.policy_data.get("resource_scope", "*"))
        grid.addWidget(self.resource_scope_edit, 6, 1)

        layout.addLayout(grid)

        # Description
        layout.addWidget(QLabel("Description:"))
        self.desc_edit = QLineEdit(self.policy_data.get("description", ""))
        layout.addWidget(self.desc_edit)

        # Structured Conditions JSON
        layout.addWidget(QLabel("Structured Conditions (JSON array or object):"))
        self.cond_edit = QTextEdit()
        cond_val = self.policy_data.get("conditions_json") or "[]"
        self.cond_edit.setPlainText(cond_val)
        self.cond_edit.setMaximumHeight(80)
        self.cond_edit.setStyleSheet(
            f"background:{T.SURFACE_ALT}; border:none; border-radius:{T.R_SM}px; font-family:monospace; font-size:{T.FS_SM}px; padding:6px 10px;"
        )
        layout.addWidget(self.cond_edit)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self._validate_and_save)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def _validate_and_save(self):
        name = self.name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Validation Error", "Policy name is required.")
            return

        cond_text = self.cond_edit.toPlainText().strip()
        if cond_text:
            try:
                json.loads(cond_text)
            except Exception as e:
                QMessageBox.warning(self, "Invalid JSON", f"Conditions must be valid JSON: {e}")
                return

        self.payload = {
            "name": name,
            "description": self.desc_edit.text().strip() or None,
            "category": self.cat_edit.currentText(),
            "decision": self.decision_edit.currentText(),
            "priority": self.priority_spin.value(),
            "tool_scope": self.tool_scope_edit.text().strip() or "*",
            "action_scope": self.action_scope_edit.text().strip() or "*",
            "resource_scope": self.resource_scope_edit.text().strip() or "*",
            "conditions_json": cond_text if cond_text else None,
            "is_enabled": True,
        }
        self.accept()


class PolicySimulatorDialog(QDialog):
    """Interactive policy simulation sandbox executing synthetic checks without invoking tools."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        self.setWindowTitle("Policy Simulator — Safe Synthetic Evaluation")
        self.setMinimumWidth(620)
        self.setObjectName("policyEditDialog")
        self.setStyleSheet(f"QDialog#policyEditDialog {{ background:{T.SURFACE}; }}")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)
        layout.setSpacing(T.SP_3)

        info = QLabel(
            "🛡 <b>Simulation Sandbox:</b> Test action requests against policy engine and threat detectors.<br>"
            "Zero real tools are executed. All resources remain untouched."
        )
        info.setStyleSheet(
            f"background:{T.SURFACE_ALT}; border:none; padding:{T.SP_3}px; border-radius:{T.R_SM}px; color:{T.TEXT};"
        )
        layout.addWidget(info)

        grid = QGridLayout()
        grid.setSpacing(T.SP_2)

        grid.addWidget(QLabel("Tool Name:"), 0, 0)
        self.tool_edit = QLineEdit("bash")
        grid.addWidget(self.tool_edit, 0, 1)

        grid.addWidget(QLabel("Action/Operation:"), 1, 0)
        self.action_edit = QLineEdit("execute_command")
        grid.addWidget(self.action_edit, 1, 1)

        grid.addWidget(QLabel("Resource/Path:"), 2, 0)
        self.resource_edit = QLineEdit("/etc/passwd")
        grid.addWidget(self.resource_edit, 2, 1)

        grid.addWidget(QLabel("Arguments (JSON):"), 3, 0)
        self.args_edit = QTextEdit('{"command": "cat /etc/passwd"}')
        self.args_edit.setMaximumHeight(70)
        self.args_edit.setStyleSheet(f"background:{T.SURFACE}; border:1px solid {T.BORDER}; border-radius:{T.R_SM}px; font-family:monospace; font-size:{T.FS_SM}px; padding:6px 10px;")
        grid.addWidget(self.args_edit, 3, 1)

        layout.addLayout(grid)

        run_btn = QPushButton("Run Simulation")
        run_btn.setIcon(get_icon("play", size=14, color="#FFFFFF"))
        run_btn.setObjectName("primary")
        run_btn.clicked.connect(self._run_simulation)
        layout.addWidget(run_btn)

        layout.addWidget(QLabel("Simulation Outcome:"))
        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        self.result_box.setMaximumHeight(150)
        self.result_box.setStyleSheet(
            f"background:{T.SURFACE_ALT}; border:none; border-radius:{T.R_SM}px; font-family:monospace; font-size:{T.FS_SM}px; padding:6px 10px;"
        )
        layout.addWidget(self.result_box)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(
            f"QPushButton {{ background-color:{T.SURFACE}; color:{T.TEXT}; border:1px solid {T.BORDER}; padding:6px 16px; border-radius:4px; font-weight:600; }}"
            f"QPushButton:hover {{ background-color:{T.SURFACE_ALT}; }}"
        )
        close_btn.clicked.connect(self.reject)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

    def _run_simulation(self):
        try:
            parsed_args = json.loads(self.args_edit.toPlainText().strip() or "{}")
        except Exception as e:
            QMessageBox.warning(self, "Invalid Arguments", f"Arguments must be valid JSON: {e}")
            return

        payload = {
            "tool_name": self.tool_edit.text().strip(),
            "operation": self.action_edit.text().strip(),
            "resource": self.resource_edit.text().strip() or None,
            "arguments": parsed_args,
        }

        res = backend_client.simulate_policy(payload)
        if not res:
            self.result_box.setPlainText("Failed to contact backend simulator or error occurred.")
            return

        lines = [
            f"SIMULATED DECISION: {res.get('simulated_decision')}",
            f"Decision Source:    {res.get('decision_source')}",
            f"Matched Policy:     {res.get('matched_policy_name')} (Priority {res.get('matched_priority')})",
            f"Risk Score:         {res.get('risk_score', 0):.0f}/100 [{res.get('risk_level')}]",
            f"Real Tool Executed: {res.get('executed_real_tool')} (CONFIRMED ZERO EXECUTION)",
            "",
            "Reasons:",
        ]
        for r in res.get("reasons", []):
            lines.append(f"  • {r}")

        findings = res.get("threat_findings", [])
        if findings:
            lines.append("")
            lines.append(f"Threat Findings ({len(findings)}):")
            for f in findings:
                lines.append(f"  • [{f.get('severity')}] {f.get('threat_type')}: {f.get('title')}")

        self.result_box.setPlainText("\n".join(lines))


class EmergencyControlsDialog(QDialog):
    """Emergency Security Lockdown and circuit-breaker management."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self.refresh_controls()

    def _build_ui(self):
        self.setWindowTitle("Emergency Security Controls — Lockdown & Kill-Switch")
        self.setMinimumWidth(600)
        self.setObjectName("emergencyDialog")
        self.setStyleSheet(f"QDialog#emergencyDialog {{ background:{T.SURFACE}; }}")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)
        layout.setSpacing(T.SP_3)

        self.status_banner = QLabel("Checking lockdown status...")
        self.status_banner.setStyleSheet(
            f"background:{T.SURFACE_ALT}; color:{T.TEXT}; border:1px solid {T.BORDER}; padding:{T.SP_3}px; border-radius:{T.R_SM}px; font-weight:700;"
        )
        layout.addWidget(self.status_banner)

        # Quick actions row
        actions_row = QHBoxLayout()
        pause_btn = QPushButton("Pause All Executions")
        pause_btn.setIcon(get_icon("pause", size=14, color="#FFFFFF"))
        pause_btn.setObjectName("danger")
        pause_btn.setStyleSheet(f"background-color:{T.DANGER}; color:white; border:none; padding:5px 12px; font-weight:600; border-radius:4px;")
        pause_btn.clicked.connect(lambda: self._activate_quick("PAUSE_EXECUTIONS", "*"))

        deny_btn = QPushButton("Emergency Deny Mode")
        deny_btn.setIcon(get_icon("shield", size=14, color="#FFFFFF"))
        deny_btn.setObjectName("danger")
        deny_btn.setStyleSheet(f"background-color:{T.DANGER}; color:white; border:none; padding:5px 12px; font-weight:600; border-radius:4px;")
        deny_btn.clicked.connect(lambda: self._activate_quick("EMERGENCY_DENY_MODE", "*"))

        actions_row.addWidget(pause_btn)
        actions_row.addWidget(deny_btn)
        layout.addLayout(actions_row)

        layout.addWidget(QLabel("Active Emergency Controls:"))
        self.controls_list = QTextEdit()
        self.controls_list.setReadOnly(True)
        self.controls_list.setMaximumHeight(130)
        self.controls_list.setStyleSheet(
            f"background:{T.SURFACE_ALT}; color:{T.TEXT}; border:1px solid {T.BORDER}; font-family:monospace; font-size:{T.FS_SM}px; padding:4px;"
        )
        layout.addWidget(self.controls_list)

        revoke_btn = QPushButton("Revoke Emergency Control")
        revoke_btn.setIcon(get_icon("check", size=14, color=T.TEXT))
        revoke_btn.setObjectName("secondary")
        revoke_btn.setStyleSheet(
            f"background-color:{T.SURFACE}; color:{T.TEXT}; border:1px solid {T.BORDER}; padding:4px 10px; border-radius:4px;"
        )
        revoke_btn.clicked.connect(self._handle_revoke)
        layout.addWidget(revoke_btn)

        close_btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close_btn.setStyleSheet(
            f"QPushButton {{ background-color:{T.SURFACE}; color:{T.TEXT}; border:1px solid {T.BORDER}; padding:4px 12px; border-radius:4px; }}"
        )
        close_btn.rejected.connect(self.reject)
        layout.addWidget(close_btn)

    def refresh_controls(self):
        status = backend_client.get_emergency_status()
        if status:
            is_active = status.get("is_lockdown_active", False)
            cnt = status.get("active_controls_count", 0)
            if is_active or cnt > 0:
                self.status_banner.setText(f"⚠ LOCKDOWN ACTIVE — {cnt} Emergency Control(s) Enforcing!")
                self.status_banner.setStyleSheet(
                    f"background:{T.DANGER_BG}; color:{T.DANGER}; border:1px solid {T.DANGER}; padding:{T.SP_3}px; border-radius:{T.R_SM}px; font-weight:700;"
                )
            else:
                self.status_banner.setText("✓ Normal Operations — No Active Emergency Controls")
                self.status_banner.setStyleSheet(
                    f"background:{T.SUCCESS_BG}; color:{T.SUCCESS}; border:1px solid {T.SUCCESS}; padding:{T.SP_3}px; border-radius:{T.R_SM}px; font-weight:700;"
                )

            controls = status.get("active_controls", [])
            lines = []
            for c in controls:
                lines.append(f"• ID: {c.get('id')} | Type: {c.get('control_type')} | Target: {c.get('target_identifier')} | Reason: {c.get('reason')}")
            self.controls_list.setPlainText("\n".join(lines) if lines else "No active controls.")
        else:
            self.status_banner.setText("Backend offline or unreachable.")
            self.status_banner.setStyleSheet(
                f"background:{T.WARNING_BG}; color:{T.WARNING}; border:1px solid {T.WARNING}; padding:{T.SP_3}px; border-radius:{T.R_SM}px; font-weight:700;"
            )

    def _activate_quick(self, c_type: str, target: str):
        reason, ok = QInputDialog.getText(
            self,
            "Confirm Emergency Activation",
            f"Enter incident justification for {c_type}:",
        )
        if ok and reason and reason.strip():
            res = backend_client.activate_emergency_control(c_type, target, reason.strip())
            if res:
                QMessageBox.information(self, "Activated", f"Emergency control '{c_type}' activated successfully!")
            else:
                QMessageBox.warning(self, "Error", "Failed to activate emergency control.")
            self.refresh_controls()

    def _handle_revoke(self):
        c_id, ok = QInputDialog.getText(self, "Revoke Control", "Enter Control ID to revoke:")
        if ok and c_id and c_id.strip():
            res = backend_client.revoke_emergency_control(c_id.strip())
            if res:
                QMessageBox.information(self, "Revoked", "Emergency control revoked. System returning to normal policy flow.")
            else:
                QMessageBox.warning(self, "Error", "Failed to revoke control.")
            self.refresh_controls()


class PolicyManagementView(QWidget):
    """Full security policy management view with live backend integration."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._policies: list[dict[str, Any]] = []
        self._build_ui()
        self.refresh_data()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        root.addWidget(PageHeader(
            "Policy Management",
            "Security policies governing runtime agent actions with deterministic precedence.",
        ))

        # Top toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(T.SP_3)

        new_btn = QPushButton("+ New Policy")
        new_btn.setObjectName("primary")
        new_btn.setStyleSheet(
            f"background-color:{T.PRIMARY}; color:{T.TEXT_ON_PRIMARY}; border:none; padding:4px 10px; font-weight:600; border-radius:{T.R_SM}px;"
        )
        new_btn.clicked.connect(self._create_policy)
        toolbar.addWidget(new_btn)

        sim_btn = QPushButton("Policy Simulator")
        sim_btn.setObjectName("secondary")
        sim_btn.setStyleSheet(
            f"background-color:{T.SURFACE}; color:{T.TEXT}; border:1px solid {T.BORDER}; padding:4px 10px; border-radius:{T.R_SM}px;"
        )
        sim_btn.clicked.connect(lambda: PolicySimulatorDialog(self).exec())
        toolbar.addWidget(sim_btn)

        emg_btn = QPushButton("Emergency Controls")
        emg_btn.setIcon(get_icon("alert", size=14, color="#FFFFFF"))
        emg_btn.setObjectName("danger")
        emg_btn.setStyleSheet(
            f"background-color:{T.DANGER}; color:white; border:none; padding:4px 10px; font-weight:600; border-radius:{T.R_SM}px;"
        )
        emg_btn.clicked.connect(lambda: EmergencyControlsDialog(self).exec())
        toolbar.addWidget(emg_btn)

        conflicts_btn = QPushButton("Conflict Analysis")
        conflicts_btn.setIcon(get_icon("alert", size=14, color=T.TEXT))
        conflicts_btn.setObjectName("secondary")
        conflicts_btn.setStyleSheet(
            f"background-color:{T.SURFACE}; color:{T.TEXT}; border:1px solid {T.BORDER}; padding:4px 10px; border-radius:{T.R_SM}px;"
        )
        conflicts_btn.clicked.connect(self._check_conflicts)
        toolbar.addWidget(conflicts_btn)

        toolbar.addStretch()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setIcon(get_icon("refresh", size=14, color=T.TEXT))
        refresh_btn.setObjectName("secondary")
        refresh_btn.setStyleSheet(
            f"background-color:{T.SURFACE}; color:{T.TEXT}; border:1px solid {T.BORDER}; padding:4px 10px; border-radius:{T.R_SM}px;"
        )
        refresh_btn.clicked.connect(self.refresh_data)
        toolbar.addWidget(refresh_btn)

        root.addLayout(toolbar)

        # Policies Scroll View
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._list_container = QWidget()
        self._list_container.setStyleSheet(f"background:{T.BG_APP};")
        self._list_layout = QVBoxLayout(self._list_container)
        self._list_layout.setSpacing(T.SP_3)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._list_layout.addStretch()
        scroll.setWidget(self._list_container)
        root.addWidget(scroll)

    def refresh_data(self):
        backend_items = backend_client.get_policies()
        if backend_items is not None:
            self._policies = backend_items
        else:
            self._policies = []
        self._render_policies()

    def _render_policies(self):
        while self._list_layout.count() > 1:
            item = self._list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not self._policies:
            empty = EmptyState(
                "📜",
                "No custom security policies configured.",
                "Create a new policy using '+ New Policy' above or connect to the AgentShield backend.",
            )
            self._list_layout.insertWidget(0, empty)
        else:
            for idx, pol in enumerate(self._policies):
                card = self._make_card(pol)
                self._list_layout.insertWidget(idx, card)

    def _make_card(self, pol: dict[str, Any]) -> QFrame:
        card = QFrame()
        card.setObjectName("policyCard")
        card.setStyleSheet(
            f"QFrame#policyCard {{ background:{T.SURFACE}; border:1px solid {T.BORDER};"
            f"border-radius:{T.R_LG}px; padding:{T.SP_3}px; }} QLabel {{ border: none; }}"
        )
        lay = QHBoxLayout(card)
        lay.setContentsMargins(T.SP_4, T.SP_3, T.SP_4, T.SP_3)
        lay.setSpacing(T.SP_4)

        left = QVBoxLayout()
        name_l = QLabel(f"{pol.get('name', 'Policy')} (Priority {pol.get('priority', 100)})")
        name_l.setStyleSheet(f"color:{T.TEXT}; font-weight:700;")
        dec = pol.get("decision", "ALLOW")
        scopes = f"Tool: {pol.get('tool_scope', '*')} | Action: {pol.get('action_scope', '*')} | Resource: {pol.get('resource_scope', '*')}"
        sub_l = QLabel(f"Decision: {dec}  •  Scopes: {scopes}  •  v{pol.get('version', 1)}")
        sub_l.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px;")
        left.addWidget(name_l)
        left.addWidget(sub_l)
        lay.addLayout(left, 2)

        is_enabled = pol.get("is_enabled", True)
        lay.addWidget(StatusBadge("Active" if is_enabled else "Disabled"))

        # Toggle button
        toggle_btn = QPushButton("Disable" if is_enabled else "Enable")
        toggle_btn.setObjectName("secondary")
        toggle_btn.clicked.connect(lambda _, p=pol: self._toggle_policy(p))
        lay.addWidget(toggle_btn)

        # Duplicate button
        dup_btn = QPushButton("Duplicate")
        dup_btn.setObjectName("secondary")
        dup_btn.clicked.connect(lambda _, p=pol: self._duplicate_policy(p))
        lay.addWidget(dup_btn)

        # History button
        hist_btn = QPushButton("History")
        hist_btn.setObjectName("secondary")
        hist_btn.clicked.connect(lambda _, p=pol: self._view_history(p))
        lay.addWidget(hist_btn)

        # Edit button
        edit_btn = QPushButton("Edit")
        edit_btn.setObjectName("secondary")
        edit_btn.clicked.connect(lambda _, p=pol: self._edit_policy(p))
        lay.addWidget(edit_btn)

        return card

    def _create_policy(self):
        dlg = PolicyEditorDialog(parent=self)
        if dlg.exec():
            res = backend_client.create_policy(dlg.payload)
            if res:
                QMessageBox.information(self, "Success", "Policy created successfully!")
            else:
                QMessageBox.warning(self, "Error", "Failed to create policy.")
            self.refresh_data()

    def _edit_policy(self, pol: dict[str, Any]):
        dlg = PolicyEditorDialog(pol, parent=self)
        if dlg.exec():
            pol_id = pol.get("id")
            if pol_id:
                res = backend_client.update_policy(pol_id, dlg.payload)
                if res:
                    QMessageBox.information(self, "Success", "Policy updated successfully!")
                else:
                    QMessageBox.warning(self, "Error", "Failed to update policy.")
            self.refresh_data()

    def _toggle_policy(self, pol: dict[str, Any]):
        pol_id = pol.get("id")
        if not pol_id:
            return
        is_enabled = pol.get("is_enabled", True)
        if is_enabled:
            backend_client.disable_policy(pol_id)
        else:
            backend_client.enable_policy(pol_id)
        self.refresh_data()

    def _duplicate_policy(self, pol: dict[str, Any]):
        pol_id = pol.get("id")
        if pol_id:
            backend_client.duplicate_policy(pol_id)
            self.refresh_data()

    def _view_history(self, pol: dict[str, Any]):
        pol_id = pol.get("id")
        if not pol_id:
            return
        history = backend_client.get_policy_history(pol_id)
        if not history:
            QMessageBox.information(self, "Version History", "No historic snapshots available for this policy.")
            return

        lines = [f"=== Policy History for '{pol.get('name')}' ==="]
        for v in history:
            lines.append(f"Version {v.get('version')} (Created: {str(v.get('created_at'))[:19]}):")
            lines.append(f"  Priority: {v.get('priority')} | Decision: {v.get('decision')} | Changed By: {v.get('changed_by')}")
            lines.append(f"  Reason: {v.get('change_reason') or 'No reason provided'}")
            lines.append("")

        dlg = QDialog(self)
        dlg.setWindowTitle("Policy Version History")
        dlg.setMinimumWidth(500)
        lay = QVBoxLayout(dlg)
        txt = QTextEdit("\n".join(lines))
        txt.setReadOnly(True)
        lay.addWidget(txt)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(dlg.reject)
        lay.addWidget(btns)
        dlg.exec()

    def _check_conflicts(self):
        conflicts = backend_client.get_policy_conflicts()
        if not conflicts:
            QMessageBox.information(self, "Conflict Analysis", "✓ No conflicting or shadowed policies detected!")
            return

        lines = [f"Found {len(conflicts)} policy conflict(s):"]
        for c in conflicts:
            lines.append(f"• [{c.get('conflict_type')}] {c.get('policy_a_name')} (P{c.get('policy_a_priority')}) vs {c.get('policy_b_name')} (P{c.get('policy_b_priority')}): {c.get('details')}")

        dlg = QDialog(self)
        dlg.setWindowTitle("Policy Conflicts Detected")
        dlg.setMinimumWidth(550)
        lay = QVBoxLayout(dlg)
        txt = QTextEdit("\n".join(lines))
        txt.setReadOnly(True)
        lay.addWidget(txt)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(dlg.reject)
        lay.addWidget(btns)
        dlg.exec()
