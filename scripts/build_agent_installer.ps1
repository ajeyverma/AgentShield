param (
    [string]$InnoSetupCompiler = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Subway Coders Agent — Standalone Inno Setup Builder" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Compile agent via PyInstaller
Write-Host "`n[1/3] Building SubwayCodersAgent standalone binary via PyInstaller..." -ForegroundColor Yellow
python -m PyInstaller --noconfirm deployment/windows/subway_coders_agent.spec
if ($LASTEXITCODE -ne 0) {
    Write-Error "PyInstaller build failed."
    exit 1
}

# 2. Copy .env with all AI API keys and assets to dist folder
Write-Host "`n[2/3] Bundling .env with all AI API keys and icons..." -ForegroundColor Yellow
if (Test-Path "demos\agent\.env") {
    Copy-Item "demos\agent\.env" "dist\SubwayCodersAgent\.env" -Force
    if (Test-Path "dist\SubwayCodersAgent\demos\agent") {
        Copy-Item "demos\agent\.env" "dist\SubwayCodersAgent\demos\agent\.env" -Force
    }
}
Copy-Item "demos\agent\subway_coders.ico" "dist\SubwayCodersAgent\subway_coders.ico" -Force

# 3. Compile Inno Setup Installer
Write-Host "`n[3/3] Compiling Inno Setup Windows Installer..." -ForegroundColor Yellow
if (Test-Path $InnoSetupCompiler) {
    & "$InnoSetupCompiler" "deployment\windows\subway_coders_agent.iss"
    Write-Host "`nInstaller compiled successfully in dist/installer/" -ForegroundColor Green
} else {
    Write-Error "Inno Setup compiler not found at: $InnoSetupCompiler"
    exit 1
}

Write-Host "`nDone! Installer: dist/installer/SubwayCodersAgent-Setup-v0.1.0.exe" -ForegroundColor Cyan
