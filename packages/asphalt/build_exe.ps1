$ErrorActionPreference = "Stop"

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install -r requirements-build.txt

pyinstaller --noconfirm --clean --onefile --windowed --name Asphalt `
  --icon "icon\\icon.ico" `
  --add-data "src;src" `
  --collect-all PySide6 `
  --collect-all scapy `
  ui_app.py
