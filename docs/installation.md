# AgentShield AI — Installation Guide

This document describes the prerequisites and step-by-step installation instructions for installing AgentShield AI in various environments.

---

## 1. System Requirements

### Hardware Requirements
- **CPU**: 2+ cores (4+ cores recommended for high-volume agent clusters)
- **RAM**: 4 GB minimum (8 GB recommended)
- **Disk**: 2 GB free disk space

### Software Prerequisites
- **Python**: Version 3.11, 3.12, 3.13, or 3.14 (64-bit)
- **Database**: PostgreSQL 14+ (or SQLite 3.35+ for local development)
- **Operating Systems**: Windows 10/11, macOS 12+, Ubuntu 22.04 LTS / Debian 12 / RHEL 9

---

## 2. Local Python Environment Installation

### Step 1: Clone Repository
```bash
git clone https://github.com/ajayver110125/AgentShield.git
cd AgentShield
```

### Step 2: Create and Activate Virtual Environment
```bash
# On Linux / macOS:
python3 -m venv .venv
source .venv/bin/activate

# On Windows (PowerShell):
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Ensure `AGENTSHIELD_ENV=LOCAL` and `AGENTSHIELD_JWT_SECRET` is set to a secure string.

### Step 5: Initialize the Database
Run the automated database initialization script:
```bash
python scripts/db_init.py
```

### Step 6: Verify Configuration
```bash
python scripts/validate_config.py --env local
```

---

## 3. Windows Native Installation (Pre-Built)

For Windows workstation operators, AgentShield provides a standalone installer:

1. Download `AgentShield-Setup-v1.0.0.exe` from the GitHub Releases page.
2. Run the installer. By default, it installs into `C:\Program Files\AgentShield`.
3. The installer creates Start Menu shortcuts and a Desktop shortcut.
4. On first launch, the **First-Run Setup Wizard** guides you through configuring the backend URL and logging into your tenant.

---

## 4. Docker Container Installation

For containerized server environments:

```bash
# Build and run using Docker Compose
docker compose up -d

# Verify containers are healthy
docker compose ps
```
The backend API and documentation will be accessible at `http://localhost:8000/docs`.
