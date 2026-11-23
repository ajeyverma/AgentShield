# -*- mode: python ; coding: utf-8 -*-
# ==============================================================================
# AgentShield AI — PyInstaller Specification File
# ==============================================================================

import os
from pathlib import Path

block_cipher = None
project_root = Path(os.path.abspath(".")).resolve()

# Static assets to bundle
datas = [
    (str(project_root / "apps" / "desktop" / "assets"), "apps/desktop/assets"),
    (str(project_root / "config"), "config"),
]

# Hidden imports needed for runtime reflection
hiddenimports = [
    "PySide6.QtCore",
    "PySide6.QtWidgets",
    "PySide6.QtGui",
    "agentshield.contracts",
    "agentshield.contracts.enums",
    "agentshield.contracts.execution",
    "agentshield.contracts.events",
    "agentshield.core.config",
    "agentshield.core.logging",
    "agentshield.security.sanitization",
    "httpx",
    "pydantic",
    "pydantic_settings",
]

# Excluded packages to keep binary lean and secure
excludes = [
    "pytest",
    "hypothesis",
    "tkinter",
    "unittest",
    "matplotlib",
    "numpy",
    "scipy",
    "IPython",
]

a = Analysis(
    [str(project_root / "apps" / "desktop" / "main.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
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
    name="AgentShield",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # Windowed GUI mode (no command prompt window)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(project_root / "apps" / "desktop" / "assets" / "icon.ico"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="AgentShield",
)
