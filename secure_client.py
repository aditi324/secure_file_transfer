import socket
import os
import hashlib
import hmac
import time
import uuid

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5001
BUFFER_SIZE = 4096
SECRET_KEY = b'shared_secret_key'
FILENAME = 'Fingerprint_PNG_Clipart.png'

def get_file_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(BUFFER_SIZE):
            sha256.update(chunk)
    return sha256.hexdigest()

def send_file_securely(filename):
    filesize = os.path.getsize(filename)
    filehash = get_file_hash(filename)
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())

    message = f"{filename}|{filesize}|{filehash}|{timestamp}|{nonce}"
    file_hmac = hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        print(f"[+] Connected to {SERVER_HOST}:{SERVER_PORT}")

        header = f"{filename}|{filesize}|{filehash}|{timestamp}|{nonce}|{file_hmac}"
        s.send(header.encode())

        ack = s.recv(BUFFER_SIZE).decode()
        if ack != "READY":
            print("[-] Server rejected the file.")
            return

        with open(filename, "rb") as f:
            while chunk := f.read(BUFFER_SIZE):
                s.sendall(chunk)

        print("[+] File sent securely.")

if __name__ == '__main__':
    send_file_securely(FILENAME)