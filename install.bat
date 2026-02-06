@echo off
REM Multi-Room Clipboard Sync - Installation Script (Windows)
REM Installs dependencies, sets up the TUI, and configures autostart

echo ================================================
echo   Multi-Room Clipboard Sync - Installation
echo ================================================
echo.

REM Check Python
echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [X] Python not found. Please install Python 3.8 or higher.
    echo     Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)
echo [+] Python found

REM Get script directory
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

REM Create virtual environment
echo.
echo Creating virtual environment...
if exist "venv\" (
    echo [!] Virtual environment already exists, skipping...
) else (
    python -m venv venv
    echo [+] Virtual environment created
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip --quiet

REM Install dependencies
echo.
echo Installing dependencies...
if exist "requirements.txt" (
    pip install -r requirements.txt --quiet
) else (
    echo requirements.txt not found, installing packages manually...
    pip install cryptography pyperclip pillow rich requests python-whois --quiet
)
echo [+] All dependencies installed

REM Create startup batch file
echo.
echo Creating startup script...

(
echo @echo off
echo REM Auto-generated startup script for Multi-Room Clipboard Sync
echo.
echo cd /d "%%~dp0"
echo call venv\Scripts\activate.bat
echo start "Clipboard Sync" python tui_agent.py
) > start_clipboard_sync.bat

echo [+] Startup script created: start_clipboard_sync.bat

REM Create VBS script for silent startup
(
echo Set WshShell = CreateObject^("WScript.Shell"^)
echo WshShell.Run """%%SCRIPT_DIR%%start_clipboard_sync.bat""", 0, False
) > start_clipboard_sync_silent.vbs

REM Add to Windows startup
echo.
echo Configuring autostart...

set "STARTUP_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "SHORTCUT=%STARTUP_DIR%\Clipboard Sync.lnk"

REM Create shortcut using PowerShell
powershell -Command "$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%SHORTCUT%'); $Shortcut.TargetPath = '%SCRIPT_DIR%start_clipboard_sync_silent.vbs'; $Shortcut.WorkingDirectory = '%SCRIPT_DIR%'; $Shortcut.Description = 'Multi-Room Clipboard Sync'; $Shortcut.Save()"

echo [+] Autostart configured

REM Final instructions
echo.
echo ================================================
echo   Installation Complete!
echo ================================================
echo.
echo Next steps:
echo.
echo 1. Start the ClipHub server (on one machine^):
echo    python ClipHub.py
echo.
echo 2. Run the clipboard sync client:
echo    start_clipboard_sync.bat
echo.
echo 3. In the TUI, type this command to join a room:
echo    /join personal YOUR_PASSWORD
echo.
echo 4. The service will auto-start on system boot
echo.
echo    Shortcut location: %STARTUP_DIR%
echo.
echo Security Features:
echo   [+] End-to-end encryption (AES-256-GCM^)
echo   [+] URL threat detection enabled
echo   [+] Automatic typosquatting detection
echo.
echo Note: Make sure the ClipHub server is running before starting clients!
echo.
pause
