# -*- mode: python ; coding: utf-8 -*-
# ==============================================================================
# AgentShield AI — PyInstaller Specification File
# ==============================================================================

import os
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None
project_root = Path(os.path.abspath(".")).resolve()
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Static assets to bundle
datas = [
    (str(project_root / "apps" / "desktop" / "assets"), "apps/desktop/assets"),
    (str(project_root / "config"), "config"),
    (str(project_root / "demos" / "agent" / "data"), "demos/agent/data"),
]
if (project_root / "demos" / "agent" / ".env").exists():
    datas.append((str(project_root / "demos" / "agent" / ".env"), "demos/agent"))
if (project_root / "agentshield_dev.db").exists():
    datas.append((str(project_root / "agentshield_dev.db"), "."))

# Hidden imports needed for runtime reflection
hiddenimports = (
    collect_submodules("agentshield")
    + collect_submodules("demos.agent")
    + collect_submodules("apps.desktop")
    + collect_submodules("sqlalchemy")
    + [
        "PySide6.QtCore",
        "PySide6.QtWidgets",
        "PySide6.QtGui",
        "httpx",
        "pydantic",
        "pydantic_settings",
        "dotenv",
        "openai",
        "sqlite3",
        "uuid",
        "json",
        "logging",
    ]
)

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
    upx=False,
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
    upx=False,
    upx_exclude=[],
    name="AgentShield",
)
