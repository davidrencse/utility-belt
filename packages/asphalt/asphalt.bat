@echo off
REM Asphalt CLI launcher for Windows
REM Try to use installed command first, fall back to direct execution
where asphalt >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    asphalt %*
) else (
    python "%~dp0src\asphalt_cli\main.py" %*
)