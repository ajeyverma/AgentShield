<#
.SYNOPSIS
    Automated Windows installer builder for AgentShield AI.
.DESCRIPTION
    Compiles desktop executable and packages an Inno Setup installer executable.
#>

param (
    [string]$InnoSetupCompiler = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "AgentShield AI — Windows Installer Packaging Automation" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Build desktop application distribution
Write-Host "`n[1/3] Building desktop application distribution via PyInstaller..." -ForegroundColor Yellow
& python scripts/build_desktop.py
if ($LASTEXITCODE -ne 0) {
    Write-Error "Desktop packaging failed."
    exit 1
}

# 2. Check for Inno Setup compiler
Write-Host "`n[2/3] Checking Inno Setup Compiler..." -ForegroundColor Yellow
if (Test-Path $InnoSetupCompiler) {
    Write-Host "Found Inno Setup at: $InnoSetupCompiler" -ForegroundColor Green
    & "$InnoSetupCompiler" "deployment\windows\installer.iss"
    Write-Host "`n[3/3] Windows Installer successfully compiled in dist/" -ForegroundColor Green
} else {
    Write-Host "Inno Setup compiler not found at default location ($InnoSetupCompiler)." -ForegroundColor Yellow
    Write-Host "Packaging distribution directory into portable ZIP installer archive..." -ForegroundColor Yellow
    
    $distPath = "dist\AgentShield"
    $zipPath = "dist\AgentShield-v0.1.0-windows-x64.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath }
    Compress-Archive -Path "$distPath\*" -DestinationPath $zipPath
    
    Write-Host "`n[3/3] Portable archive created successfully at: $zipPath" -ForegroundColor Green
}

Write-Host "`nPackaging complete!" -ForegroundColor Cyan
