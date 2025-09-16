# server.py – AES-256-CBC

import time  # [+] to generate a small delay
import socket
import threading  # [+] Used to handle multiple clients
import hashlib  # [+] Used to generate AES key
from Crypto.Cipher import AES  # [+] AES implementation
from Crypto.Random import (
    get_random_bytes,
)  # [+]  random IV generation


# [+] Hash the student ID
def sha256_key(student_id):
    return hashlib.sha256(student_id.encode()).digest()


# [+] Pad the plaintext
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


# [+] Remove padding after decryption
def unpad(data):
    pad_len = data[-1]  # the last byte in array
    return data[:-pad_len]  # slice the padding out


# [+] Encrypt a string
def encrypt_message(message, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(message.encode())
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext  # [+] Prepend IV


# [+] Decrypt the message
def decrypt_message(data, key):
    iv = data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data[16:])
    return unpad(decrypted).decode()


# [+] Handle connections
def handle_client(conn, addr, key):
    print(f"[+] Client thread started for {addr}")
    try:
        while True:
            # Send main menu
            menu = "\n--- MENU ---\n1. Start a new guessing game\n2. Exit\nChoose an option: "
            conn.send(encrypt_message(menu, key))
            time.sleep(0.1)

            data = conn.recv(1024)
            if not data:
                print(f"[!] Client {addr} disconnected at menu.")
                break

            choice = decrypt_message(data, key).strip()
            print(f"Menu choice from {addr}: {choice}")

            if choice == "1":
                import random

                number = random.randint(1, 100)
                print(f"Secret number for {addr}: {number}")
                conn.send(encrypt_message("Guess the number (1-100):\n", key))
                time.sleep(0.1)
                while True:
                    guess_data = conn.recv(1024)
                    if not guess_data:
                        print(f"[!] Client {addr} disconnected during guessing.")
                        return

                    try:
                        print(f"Raw guess from {addr}: {guess_data}")
                        guess = int(decrypt_message(guess_data, key).strip())
                        print(f"Decrypted guess from {addr}: {guess}")
                    except Exception as e:
                        print(f"[!] Error from {addr}: {e}")
                        conn.send(
                            encrypt_message("Invalid input. Enter a number:\n", key)
                        )
                        time.sleep(0.1)
                        continue

                    if guess < number:
                        conn.send(encrypt_message("Higher\n", key))
                        time.sleep(0.1)
                    elif guess > number:
                        conn.send(encrypt_message("Lower\n", key))
                        time.sleep(0.1)
                    else:
                        conn.send(encrypt_message("Correct! You won!\n", key))
                        time.sleep(0.1)
                        break

                # Return to Menu
                continue

            elif choice == "2":
                conn.send(encrypt_message("Goodbye!\n", key))
                time.sleep(0.1)
                break
            else:
                conn.send(encrypt_message("Invalid option.\n", key))
                time.sleep(0.1)

    except (ConnectionResetError, BrokenPipeError):
        print(f"[!] Client {addr} forcefully disconnected.")
    except Exception as e:
        print(f"[!] Unexpected error from {addr}: {e}")
    finally:
        conn.close()
        print(f"[+] Connection with {addr} closed.")


# [+] Main server entry point
def main():
    student_id = "1210601"
    key = sha256_key(student_id)
    print("[+] Used Key: ", key.hex())
    print()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 12345))
    server.listen(5)  # [+] Accept up to 5 queued clients
    print("[+] Server running on port 12345")

    while True:
        conn, addr = server.accept()
        print(f"[+] Client connected from {addr}")
        client_thread = threading.Thread(target=handle_client, args=(conn, addr, key))
        client_thread.start()


if __name__ == "__main__":
    main()
