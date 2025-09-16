import secrets
import hashlib

# =========================
# Secure Modular Exponentiation (Repeated Squaring)
# Used for:
#   - RSA encryption/decryption
#   - RSA signing/verifying
#   - Diffie-Hellman (DH) key exchange
# =========================
def mod_exp(base: int, exponent: int, modulus: int) -> int:
    return pow(base, exponent, modulus)


# =========================
# Extended Euclidean Algorithm
# Used to compute:
#   - Modular inverse
# Returns: (gcd, x, y) such that a*x + b*y = gcd(a, b)
# =========================
def egcd(a: int, b: int) -> tuple:
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)


# =========================
# Modular Inverse
# Finds `d` such that: (e * d) ≡ 1 mod φ
# Used for:
#   - RSA private key generation
# =========================
def modinv(e: int, phi: int) -> int:
    g, x, _ = egcd(e, phi)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return x % phi


# =========================
# SHA256 Digest → Integer
# Used for:
#   - RSA signing (message hash)
#   - DH session key derivation
# =========================
def sha256_digest(message: bytes) -> int:
    digest = hashlib.sha256(message).digest()
    return int.from_bytes(digest, byteorder="big")


# =========================
# RSA Signature Generation
#   sig = (hash(msg))^d mod N
# Inputs:
#   - message: original bytes
#   - d: private key exponent
#   - N: modulus
# Returns:
#   - Signature as integer
# =========================
def rsa_sign(message: bytes, d: int, N: int) -> int:
    h = sha256_digest(message)
    return mod_exp(h, d, N)


# =========================
# RSA Signature Verification
#   Valid if: (sig^e mod N) == hash(msg)
# Inputs:
#   - message: original bytes
#   - signature: signature received
#   - e: public key exponent
#   - N: modulus
# Returns:
#   - True if valid, False otherwise
# =========================
def rsa_verify(message: bytes, signature: int, e: int, N: int) -> bool:
    h = sha256_digest(message)
    h_from_sig = mod_exp(signature, e, N)
    return h == h_from_sig


# =========================
# Integer to Byte Conversion
#   Used for transmitting numbers over sockets
#   or preparing RSA/DH parameters
# =========================
def int_to_bytes(i: int) -> bytes:
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder="big")


# =========================
# Byte to Integer Conversion
#   Used for converting received socket data
# =========================
def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


# =========================
# Secure Random Integer Generator
#   Used for:
#     - Diffie-Hellman exponents
#     - Nonces (RA, RB)
# =========================
def generate_secure_random(bits: int) -> int:
    return secrets.randbits(bits)


# =========================
# Diffie-Hellman Group Parameters
#   RFC 3526 MODP Group 14 (2048-bit)
# Returns:
#   - g (generator)
#   - m (prime modulus)
# =========================
def get_dh_params() -> tuple:
    g = 2
    m_hex = """
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
        C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
        83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
        E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
        DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
        15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
    """
    m = int("".join(m_hex.strip().split()), 16)
    return g, m


# =========================
# Debugging Utility: Print RSA Key Info
# Helpful for manually verifying key setup
# =========================
def print_rsa_key_info(name: str, e: int, d: int, N: int):
    print(f"[{name}] Public Key (N, e):\n  N = {N}\n  e = {e}")
    print(f"[{name}] Private Key d:\n  d = {d}")


# =========================
# Secure Ephemeral Variable Destruction
# In real implementations, this should wipe from memory.
# In Python, memory management is automatic, so this
# just logs the action.
# =========================
def destroy_sensitive_data(var_name: str):
    print(f"[*] Destroying sensitive value: {var_name} (placeholder)")
    # In C/C++: memset(&var, 0, sizeof(var));
    # In Python, you can’t force overwrite due to GC.
    return None
