# -*- mode: python ; coding: utf-8 -*-
"""
AgentShield AI — Subway Coders Chatbot Agent Standalone Spec
"""

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None
REPO_ROOT = Path(SPECPATH).resolve().parents[1]

added_datas = [
    (str(REPO_ROOT / "demos" / "agent" / "subway_coders_circle.png"), "demos/agent"),
    (str(REPO_ROOT / "demos" / "agent" / "subway_coders_logo.jpg"), "demos/agent"),
    (str(REPO_ROOT / "demos" / "agent" / "subway_coders.ico"), "demos/agent"),
    (str(REPO_ROOT / "demos" / "agent" / "data"), "demos/agent/data"),
    (str(REPO_ROOT / "demos" / "agent" / ".env"), "demos/agent"),
    (str(REPO_ROOT / ".env"), "."),
]

hidden_imports = [
    "PySide6.QtCore",
    "PySide6.QtGui",
    "PySide6.QtWidgets",
    "agentshield",
    "agentshield.contracts",
    "agentshield.contracts.action",
    "agentshield.contracts.decision",
    "agentshield.contracts.enums",
    "agentshield.contracts.provenance",
    "agentshield.contracts.threat",
    "agentshield.core.config",
    "agentshield.core.exceptions",
    "agentshield.threat_detection.engine",
    "agentshield.security.engine",
    "agentshield.security.permissions",
    "agentshield.services.notification_service",
    "agentshield.database.models",
    "agentshield.database.session",
    "demos.agent.icons",
    "demos.agent.config",
    "demos.agent.llm_client",
    "demos.agent.agent",
    "demos.agent.agentshield_adapter",
    "httpx",
    "pydantic",
    "pydantic_settings",
    "email_validator",
    "dotenv",
    "sqlite3",
] + collect_submodules("agentshield")

a = Analysis(
    [str(REPO_ROOT / "demos" / "agent" / "chatbot_ui.py")],
    pathex=[str(REPO_ROOT), str(REPO_ROOT / "demos" / "agent")],
    binaries=[],
    datas=added_datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "scipy"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SubwayCodersAgent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(REPO_ROOT / "demos" / "agent" / "subway_coders.ico"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="SubwayCodersAgent",
)
