@echo off
REM === Build Advanced_Net_Scanner.exe ===
cd /d "%~dp0"
setlocal enabledelayedexpansion

REM --- Clean previous build ---
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist advanced_net_scanner.spec del /q Advanced_Net_Scanner.spec

REM --- Ensure version.txt exists ---
if not exist version.txt (
    echo [!] version.txt not found! Cannot embed version info.
    pause
    exit /b 1
)

REM --- Remove old EXE if exists ---
if exist dist\Advanced_Net_Scanner.exe del /q dist\Advanced_Net_Scanner.exe

echo [*] Building Advanced_Net_Scanner.exe with PyInstaller...
REM --- Removed --icon option to use default Python icon ---
call pyinstaller --onefile --windowed --version-file=version.txt Advanced_Net_Scanner.py

if %ERRORLEVEL% neq 0 (
    echo [!] Build failed. Check output above.
    pause
    exit /b 1
) else (
    echo [*] Build complete! EXE is in dist\Advanced_Net_Scanner.exe
)

pause
