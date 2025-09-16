# By Osama Zeidan
# server.py – Phase III

# - RSA Auth + DH Key Exchange
# - AES-256-CBC Secure Guessing Game

import socket
import threading
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from utils import *

# =========================
# CONFIGURATION
# =========================
HOST = "0.0.0.0"  # Listen on all interfaces
PORT = 65432  # Port for incoming client connections

# =========================
# Server RSA Key Generation (Hardcoded)
# =========================
p = 2357111317192329313741434753596167717379838997101103107109113127131137139149151157163167173179181191193197199211223227229233239241251257263269271277281283293307311313317331337347349353359367373379383389397401409419421431433439443449457461463467479487491499503509521523541547557563569571577587593599601607613617619631641643647653659661673677683691701709719
q = 7891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891
N = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = modinv(e, phi)  # Private exponent

# =========================
# Client Public Key (Hardcoded)
# =========================
client_e = 65537
client_N = 9817766666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666670379887169999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999874799999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999581325509666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666555969


# =========================
# AES-CBC Logic (as phase 2)
# =========================
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def unpad(data):
    return data[: -data[-1]]


def encrypt_message(message, key):
    iv = get_random_bytes(16)
    print(f"[+] AES IV used for encryption: {iv.hex()}")  # [TESTCASE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(message.encode()))


def decrypt_message(data, key):
    assert len(data) >= 16, "[!] Invalid ciphertext length"
    iv = data[:16]
    print(f"[+] AES IV used for decryption: {iv.hex()}")  # [TESTCASE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[16:])).decode()


# =========================
# AES-CBC Protected Game Logic (as phase 2)
# =========================
def guessing_game(conn, addr, session_key):
    try:
        menu = (
            "\n--- MENU ---\n1. Start a new guessing game\n2. Exit\nChoose an option: "
        )
        conn.send(encrypt_message(menu, session_key))
        choice_data = conn.recv(4096)
        assert choice_data, "[!] Client disconnected before menu"
        choice = decrypt_message(choice_data, session_key).strip()

        if choice == "1":
            import random

            secret = random.randint(1, 100)
            conn.send(encrypt_message("Guess the number (1-100):\n", session_key))

            while True:
                guess_data = conn.recv(4096)
                if not guess_data:
                    break
                try:
                    guess = int(decrypt_message(guess_data, session_key).strip())
                except:
                    conn.send(
                        encrypt_message("Invalid input. Try again:\n", session_key)
                    )
                    continue

                if guess < secret:
                    conn.send(encrypt_message("Higher\n", session_key))
                elif guess > secret:
                    conn.send(encrypt_message("Lower\n", session_key))
                else:
                    conn.send(encrypt_message("Correct! You won!\n", session_key))
                    break
        else:
            conn.send(encrypt_message("Goodbye!\n", session_key))

    except Exception as e:
        print(f"[!] Game error with {addr}: {e}")
    finally:
        conn.close()


# =========================
# Threaded RSA + DH + AES Handler
# =========================
def handle_client(conn, addr):
    try:
        print(f"[*] Connected from {addr}")

        # === Step 1: Receive RA, A ===
        data = conn.recv(4096)
        assert data, "[!] No data received from client"
        parts = data.split(b"||")
        assert len(parts) == 2, "[!] Invalid handshake format"

        RA = bytes_to_int(parts[0])
        A = bytes_to_int(parts[1])
        print(f"[+] RA (client nonce): {RA}")  # [TESTCASE]
        print(f"[+] A (client DH public): {A}")

        # === Step 2: Generate RB, B, gab ===
        b = generate_secure_random(2048)
        RB = generate_secure_random(256)
        g, m = get_dh_params()
        B = mod_exp(g, b, m)
        gab = mod_exp(A, b, m)
        print(f"[+] b (server DH secret): {b}")  # [TESTCASE]
        print(f"[+] RB (server nonce): {RB}")  # [TESTCASE]
        print(f"[+] B (server DH public): {B}")
        print(f"[+] gab (shared secret): {gab}")  # [TESTCASE]

        # === Step 3: Send signed response ===
        identity_B = "192.168.1.13".encode()  # addr[0].encode()
        H = sha256_digest(
            int_to_bytes(RA)
            + int_to_bytes(RB)
            + int_to_bytes(A)
            + int_to_bytes(B)
            + identity_B
        )
        SB = rsa_sign(int_to_bytes(H), d, N)
        conn.sendall(
            int_to_bytes(RB) + b"||" + int_to_bytes(B) + b"||" + int_to_bytes(SB)
        )

        # === Step 4: Receive client's signature and verify ===
        SA_data = conn.recv(4096)
        assert SA_data, "[!] No signature from client"
        SA = bytes_to_int(SA_data)

        identity_A = "192.168.1.6".encode()  # addr[0].encode()

        H2 = sha256_digest(
            int_to_bytes(RB)
            + int_to_bytes(RA)
            + int_to_bytes(B)
            + int_to_bytes(A)
            + identity_A
        )

        if not rsa_verify(int_to_bytes(H2), SA, client_e, client_N):
            print("[!] Client authentication failed.")
            conn.close()
            return

        print("[+] Client authenticated.")  # [TESTCASE]

        # === Step 5: Derive session key and launch game ===
        session_key = hashlib.sha256(int_to_bytes(gab)).digest()
        print(f"[+] Session key (K): {session_key.hex()}")  # [TESTCASE]
        guessing_game(conn, addr, session_key)

    except Exception as e:
        print(f"[!] Connection error with {addr}: {e}")
    finally:
        destroy_sensitive_data("b")
        destroy_sensitive_data("gab")
        conn.close()
        print(f"[+] Connection with {addr} closed")


# =========================
# MAIN SERVER LOOP (Multi-threaded)
# =========================
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[*] Server is listening on {HOST}:{PORT}...")

        while True:
            conn, addr = s.accept()
            threading.Thread(
                target=handle_client, args=(conn, addr), daemon=True
            ).start()


if __name__ == "__main__":
    main()
