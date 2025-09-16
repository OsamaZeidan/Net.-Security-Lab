# client.py – AES-256-CBC

import socket
import hashlib  # [+] Used to derive AES key
from Crypto.Cipher import (
    AES,
)  # for encryption and decryption
from Crypto.Random import (
    get_random_bytes,
)  # to generate random IVs


# [+] Derive AES key
def sha256_key(student_id):
    return hashlib.sha256(student_id.encode()).digest()


# [+] Apply padding
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


# [+] Remove padding after decryption
def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]


# [+] Encrypt message
def encrypt_message(message, key):
    iv = get_random_bytes(16)  # [+]random IV (128-bit)
    cipher = AES.new(key, AES.MODE_CBC, iv)  # [+] Create AES cipher
    padded = pad(message.encode())  # [+] Padding
    ciphertext = cipher.encrypt(padded)
    print(f"[+] Sending: {message}")
    print(f"[+]Used IV: {iv.hex()}")
    print(f"[+] Ciphertext: {ciphertext.hex()}")
    print("")
    return iv + ciphertext  # [+] Prepend IV to ciphertext


# [+] Decrypt a received msg
# [+] Extracts IV and decrypt
def decrypt_message(data, key):
    iv = data[:16]  # [+] Extract IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data[16:])
    return unpad(decrypted).decode()


# [+] Main function
def main():
    student_id = "1210601"
    key = sha256_key(student_id)  # [+] Create AES key
    print("[+] Used Key: ", key.hex())
    print()

    host = input("Enter server IP (e.g., 127.0.0.1): ")
    port = 12345

    client = socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    )  # [+] Create a TCP socket
    client.connect((host, port))
    print("[+] Connected to server.")

    waiting_for_input = False

    while True:
        try:
            data = client.recv(1024)  # [+] Receive encrypted response
            if not data:
                print("[!] Connection lost.")
                break

            message = decrypt_message(data, key)  # [+] Decrypt message
            print(message, end="\n")

            if (
                message.strip().endswith(":")
                or "Higher" in message
                or "Lower" in message
            ):
                waiting_for_input = True

            elif "Goodbye" in message:
                break  # [+] Exit

            else:
                waiting_for_input = False

            if waiting_for_input:
                user_input = input()  # [+] Get user input
                client.send(encrypt_message(user_input, key))  # [+] Encrypt and send
                waiting_for_input = False

        except Exception as e:
            print(f"[!] Client error: {e}")
            break

    client.close()
    print("[+] Disconnected.")


if __name__ == "__main__":
    main()
