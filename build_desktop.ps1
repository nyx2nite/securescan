# Builds the SecureScan Windows desktop app -> Backend\dist\SecureScan\SecureScan.exe
# Usage (from repo root):  powershell -ExecutionPolicy Bypass -File .\build_desktop.ps1
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$py = Join-Path $root "Backend\venv\Scripts\python.exe"

Write-Host "==> Building frontend" -ForegroundColor Cyan
Push-Location (Join-Path $root "Frontend")
npm install
npm run build
Pop-Location

Write-Host "==> Installing Python dependencies" -ForegroundColor Cyan
& $py -m pip install -q -r (Join-Path $root "Backend\requirements.txt") pywebview pyinstaller pillow

Write-Host "==> Packaging with PyInstaller" -ForegroundColor Cyan
Push-Location (Join-Path $root "Backend")
# --onedir (not --onefile): no self-extraction to %TEMP% on every launch, so startup is much faster
& $py -m PyInstaller desktop.py `
    --name SecureScan `
    --onedir `
    --windowed `
    --noconfirm `
    --clean `
    --icon (Join-Path $root "Frontend\public\icon.png") `
    --add-data "$(Join-Path $root 'Frontend\dist');frontend_dist" `
    --collect-submodules app `
    --collect-submodules uvicorn `
    --collect-submodules dns `
    --collect-all webview `
    --exclude-module tkinter
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }
Pop-Location

Write-Host "==> Done: Backend\dist\SecureScan\SecureScan.exe  (ship the whole SecureScan folder)" -ForegroundColor Green
