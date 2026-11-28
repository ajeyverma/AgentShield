"""
AgentShield AI — Desktop Packaging Script.

Automates PyInstaller standalone build and checksum generation.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path


def compute_sha256(filepath: Path) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def build_desktop():
    root = Path(__file__).resolve().parent.parent
    spec_path = root / "apps" / "desktop" / "packaging" / "agentshield.spec"
    dist_dir = root / "dist" / "AgentShield"
    checksums_file = root / "dist" / "checksums.txt"

    print("=" * 60)
    print("AgentShield AI — Packaging Desktop Application")
    print("=" * 60)

    # 1. Ensure icons exist
    icon_script = root / "scripts" / "generate_icons.py"
    if icon_script.exists():
        subprocess.run([sys.executable, str(icon_script)], check=True, cwd=str(root))

    # 2. Verify pyinstaller is available
    try:
        import PyInstaller
        print(f"Using PyInstaller version: {PyInstaller.__version__}")
    except ImportError:
        print("Installing PyInstaller...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)

    # 3. Clean previous builds
    build_dir = root / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir, ignore_errors=True)
    if dist_dir.exists():
        shutil.rmtree(dist_dir, ignore_errors=True)

    # 4. Run PyInstaller
    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", str(spec_path)]
    print(f"Executing: {' '.join(cmd)}")
    res = subprocess.run(cmd, cwd=str(root))
    if res.returncode != 0:
        print("Error: PyInstaller build failed!")
        sys.exit(res.returncode)

    # 5. Verify artifact
    exe_name = "AgentShield.exe" if sys.platform == "win32" else "AgentShield"
    built_exe = dist_dir / exe_name
    if not built_exe.exists():
        print(f"Error: Target executable {built_exe} was not produced!")
        sys.exit(1)

    # 5b. Guarantee all environment files are directly bundled in distribution
    if (root / ".env").exists():
        shutil.copy2(root / ".env", dist_dir / ".env")
        print("Copied root .env to distribution root.")
    agent_env = root / "demos" / "agent" / ".env"
    if agent_env.exists():
        target_agent_dir = dist_dir / "demos" / "agent"
        target_agent_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(agent_env, target_agent_dir / ".env")
        print("Copied demos/agent/.env to distribution.")

    # 6. Generate Checksums
    checksum = compute_sha256(built_exe)
    with open(checksums_file, "w", encoding="utf-8") as f:
        f.write(f"{checksum}  {built_exe.name}\n")

    print("\n" + "=" * 60)
    print(f"SUCCESS: Desktop application built at: {dist_dir}")
    print(f"Executable: {built_exe}")
    print(f"SHA-256: {checksum}")
    print(f"Checksums saved to: {checksums_file}")
    print("=" * 60)


if __name__ == "__main__":
    build_desktop()
