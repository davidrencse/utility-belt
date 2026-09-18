$ErrorActionPreference = "Stop"

# Build EXE first
.\build_exe.ps1

# Build installer (requires Inno Setup)
if (-not (Get-Command iscc.exe -ErrorAction SilentlyContinue)) {
    Write-Host "Inno Setup not found. Install it, then run:" -ForegroundColor Yellow
    Write-Host "  iscc.exe .\\installer\\Asphalt.iss" -ForegroundColor Yellow
    exit 1
}

iscc.exe .\installer\Asphalt.iss
