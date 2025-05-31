# 🔐 Secure File Transfer with Fingerprint Verification

This project implements a secure client-server file transfer system in Python. It ensures the authenticity and integrity of transmitted files using SHA-256, HMAC, timestamps, nonces, and fingerprint-based verification. A simulated replay attack client is also included to test the system's defense mechanisms.

---

## 📁 Project Structure

├── secure_client.py # Main client script for sending files securely
├── secure_server.py # Main server script for receiving files
├── replay_attack_client.py # Client simulating a replay attack
├── fingerprint_sample.png # Sample fingerprint image for verification
├── received_fingerprint_sample.png # Received fingerprint sample for matching
├── Fingerprint_PNG_Clipart.png # Example fingerprint image


---

## 🔧 Features

✅ Secure file transfer using socket communication  
✅ HMAC-SHA256 message authentication  
✅ Timestamp and nonce to prevent replay attacks  
✅ Fingerprint image comparison to validate identity  
✅ Replay attack simulation for testing security robustness

---

## 🛠️ Technologies Used

- Python 3.x
- `socket` for client-server communication
- `hashlib`, `hmac` for security
- `PIL` (Pillow) for image processing
- `datetime`, `uuid` for timestamp and nonce generation

---

## 🚀 How to Run

### 1. Start the Server
```bash
python secure_server.py

2. Run the Secure Client
python secure_client.py

3. Simulate a Replay Attack
python replay_attack_client.py
