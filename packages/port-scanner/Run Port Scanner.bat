@echo off
setlocal
cd /d "%~dp0"

where pythonw >nul 2>nul
if %ERRORLEVEL%==0 (
    start "" pythonw gui.py
    goto :eof
)

where python >nul 2>nul
if %ERRORLEVEL%==0 (
    start "" python gui.py
    goto :eof
)

echo Python was not found on PATH. Install Python 3.8+ from https://www.python.org/downloads/
echo and make sure "Add python.exe to PATH" is checked during install.
pause
