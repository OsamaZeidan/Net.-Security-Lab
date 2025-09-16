# By Osama Zeidan
import socket
import hashlib
from utils import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# =========================
# CLIENT – PHASE III

# - RSA Auth + DH Key Exchange
# - AES-256-CBC Secure Guessing Game
# =========================

HOST = "192.168.1.13"  # Server IP
PORT = 65432  # Server port

# -------------------------
# Client RSA Key Pair (Hardcoded)
# -------------------------
p = 3136666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666313
q = 3130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001183811000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000313
N = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = modinv(e, phi)  # Client private key

# -------------------------
# Server RSA Public Key (Hardcoded)
# -------------------------
server_e = 65537
server_N = 18600518306595749554093242385656405360600503501760468154703283354470186399023497005093473361142533049588258424899067895485126275286436374245797866335095271900392543636721256932967678874590770791138584985041296561244544496176772171992296505142679256710463265298780442834415356516544586116742039056782450065014588551676733559564302581596979814376828519293773627079783101043054599237385134079657986006778516445908908314135796748416634758495258784828565712531440656490874572994933197980457279232839935728111316981275432350845787064220237286947979566378111754873580374664092433444480890447354737445525038105314571463395605687833409440171955552559118824294420400646882264818964830441746626775701356207596878880032629


# -------------------------
# AES-CBC Helper Functions (as phase 2)
# -------------------------
def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)


def unpad(data):
    return data[: -data[-1]]


def aes_encrypt(message, key):
    iv = get_random_bytes(16)
    print(f"[+] AES IV used for encryption: {iv.hex()}")  # [TESTCASE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(message.encode()))


def aes_decrypt(data, key):
    assert len(data) >= 16, "[!] Encrypted data too short"
    iv = data[:16]
    print(f"[+] AES IV used for decryption: {iv.hex()}")  # [TESTCASE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[16:])).decode()


# -------------------------
# Begin Secure Protocol
# -------------------------
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("[*] Connected to server.")

    # === Step 1: DH Challenge and Key Exchange ===
    a = generate_secure_random(2048)
    RA = generate_secure_random(256)
    g, m = get_dh_params()
    A = mod_exp(g, a, m)

    print(f"[+] Client DH secret (a): {a}")  # [TESTCASE]
    print(f"[+] Client nonce (RA): {RA}")  # [TESTCASE]
    print(f"[+] Client DH public value (A): {A}")

    s.sendall(int_to_bytes(RA) + b"||" + int_to_bytes(A))

    # === Step 2: Receive RB, B, SB from server ===
    data = s.recv(8192)
    assert data, "[!] No data received from server."
    parts = data.split(b"||")
    assert len(parts) == 3, "[!] Invalid data structure."

    RB = bytes_to_int(parts[0])
    B = bytes_to_int(parts[1])
    SB = bytes_to_int(parts[2])

    print(f"[+] Server nonce (RB): {RB}")  # [TESTCASE]
    print(f"[+] Server DH public value (B): {B}")
    print(f"[+] Server signature (SB): {SB}")

    # === Step 3: Verify server signature ===
    # identity_B = HOST.encode()
    identity_B = HOST.encode()
    print(identity_B)
    H = sha256_digest(
        int_to_bytes(RA)
        + int_to_bytes(RB)
        + int_to_bytes(A)
        + int_to_bytes(B)
        + identity_B
    )
    if not rsa_verify(int_to_bytes(H), SB, server_e, server_N):
        print("[!] Server authentication failed.")
        exit()
    print("[+] Server authenticated.")  # [TESTCASE]

    # === Step 4: Send client signature SA ===
    identity_A = "192.168.1.6".encode()  # HOST.encode()
    # identity_A = s.getsockname()[0].encode()
    H2 = sha256_digest(
        int_to_bytes(RB)
        + int_to_bytes(RA)
        + int_to_bytes(B)
        + int_to_bytes(A)
        + identity_A
    )
    SA = rsa_sign(int_to_bytes(H2), d, N)
    s.sendall(int_to_bytes(SA))
    print("[+] Client authenticated.")  # [TESTCASE]

    # === Step 5: Compute shared secret and AES key ===
    gab = mod_exp(B, a, m)
    K = hashlib.sha256(int_to_bytes(gab)).digest()
    print(f"[+] Shared secret (g^ab): {gab}")  # [TESTCASE]
    print(f"[+] Session key (K): {K.hex()}")  # [TESTCASE]
    print("[+] Session key derived successfully.")

    # -------------------------
    # Encrypted Game Loop (Phase IV)
    # -------------------------
    while True:
        enc_data = s.recv(4096)
        if not enc_data:
            break
        try:
            message = aes_decrypt(enc_data, K)
            print(message, end="")
        except:
            print("[!] Failed to decrypt server message.")
            break

        if message.strip().endswith(":") or "Higher" in message or "Lower" in message:
            user_input = input(">> ")
            s.sendall(aes_encrypt(user_input, K))
        elif "Correct" in message or "Goodbye" in message:
            break

    print("[*] Session ended.")
    destroy_sensitive_data("a")
    destroy_sensitive_data("K")
