import socket
import os
import hashlib
import hmac
import time

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5001
BUFFER_SIZE = 4096
SECRET_KEY = b'shared_secret_key'
REPLAY_WINDOW = 60  # seconds

def verify_hmac(message, received_hmac):
    expected_hmac = hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(received_hmac, expected_hmac)

def save_file(conn, filename, filesize):
    with open(f"received_{filename}", "wb") as f:
        total = 0
        while total < filesize:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break
            f.write(data)
            total += len(data)
    return f"received_{filename}"

def get_file_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(BUFFER_SIZE):
            sha256.update(chunk)
    return sha256.hexdigest()

def receive_secure_file():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((SERVER_HOST, SERVER_PORT))
        s.listen(1)
        print(f"[*] Listening on {SERVER_HOST}:{SERVER_PORT}...")

        conn, addr = s.accept()
        with conn:
            print(f"[+] Connected by {addr}")

            metadata = conn.recv(BUFFER_SIZE).decode()
            try:
                filename, filesize, filehash, timestamp, nonce, file_hmac = metadata.split("|")
                filesize = int(filesize)

                current_time = int(time.time())
                if abs(current_time - int(timestamp)) > REPLAY_WINDOW:
                    print("[-] Replay attack detected: expired timestamp.")
                    conn.send("REJECT".encode())
                    return

                message = f"{filename}|{filesize}|{filehash}|{timestamp}|{nonce}"
                if not verify_hmac(message, file_hmac):
                    print("[-] HMAC verification failed.")
                    conn.send("REJECT".encode())
                    return

                conn.send("READY".encode())
                saved_path = save_file(conn, filename, filesize)

                # Verify file integrity
                actual_hash = get_file_hash(saved_path)
                if actual_hash != filehash:
                    print("[-] File integrity check failed.")
                else:
                    print(f"[+] File received and verified: {saved_path}")
            except Exception as e:
                print(f"[-] Error processing file: {e}")
                conn.send("REJECT".encode())

if __name__== '__main__':
    receive_secure_file()