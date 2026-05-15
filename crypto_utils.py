"""
crypto_utils.py — WolfCrypt Cryptographic Primitives
=====================================================
Bridges the custom RSA implementation (myRSA.py) with the secure
pycryptodome library for proper padded encryption and signing.

Key generation  : Custom myRSA.rsaKeyGen() — Miller-Rabin primes,
                  square-and-multiply exponentiation, extended Euclidean
Encryption      : PKCS1_OAEP (RSA + OAEP padding) — pycryptodome
Signing         : PKCS1 v1.5 + SHA-256 — pycryptodome
Symmetric enc   : AES-EAX (authenticated encryption) — pycryptodome
Hashing         : SHA-256 — pycryptodome
Commitments     : SHA-256(canonical JSON) — for integrity verification

Key storage format (JSON dicts):
    Public key  : {"e": int, "n": int}
    Private key : {"d": int, "n": int, "e": int}  (e stored for construct)
"""

import json
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from Crypto.PublicKey    import RSA
from Crypto.Cipher       import PKCS1_OAEP, AES
from Crypto.Signature    import pkcs1_15
from Crypto.Hash         import SHA256
from Crypto.Random       import get_random_bytes
import myRSA


# ── Helpers ────────────────────────────────────────────────────────────────

def canonical(obj: dict) -> bytes:
    """Deterministic UTF-8 JSON bytes — used everywhere for signing/hashing."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')

def _build_rsa_key(key_dict: dict):
    """
    Construct a pycryptodome RSAKey from our custom key dict.
    Custom key gen stores (e, n) or (d, n, e).
    RSA.construct expects (n, e) or (n, e, d).
    """
    n = key_dict['n']
    e = key_dict['e']
    if 'd' in key_dict:
        return RSA.construct((n, e, key_dict['d']))
    return RSA.construct((n, e))


# ── SHA-256 / Commitments ──────────────────────────────────────────────────

def sha256_hex(data: bytes) -> str:
    """Return hex-encoded SHA-256 digest."""
    h = SHA256.new(data)
    return h.hexdigest()

def commitment(obj: dict) -> str:
    """SHA-256 commitment to any JSON-serialisable object."""
    return sha256_hex(canonical(obj))


# ── AES-EAX (authenticated symmetric encryption) ───────────────────────────

def aes_encrypt(plaintext: bytes, key: bytes) -> dict:
    """
    AES-EAX authenticated encryption.
    Returns dict: {nonce, ciphertext, tag} — all base64-encoded.
    The tag authenticates the ciphertext; any tampering raises ValueError
    on decryption.
    """
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        'nonce':      base64.b64encode(cipher.nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag':        base64.b64encode(tag).decode(),
    }

def aes_decrypt(packet: dict, key: bytes) -> bytes:
    """
    AES-EAX authenticated decryption.
    Raises ValueError if the MAC tag fails — catches any ciphertext tampering.
    """
    nonce      = base64.b64decode(packet['nonce'])
    ciphertext = base64.b64decode(packet['ciphertext'])
    tag        = base64.b64decode(packet['tag'])
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ── Hybrid Encryption (RSA-OAEP wraps AES session key) ─────────────────────

def hybrid_encrypt(plaintext: bytes, pub_key: dict) -> dict:
    """
    Hybrid encryption — mirrors the PGP/friend's approach:

    Step 1: Sign the plaintext with... (signing done separately, passed in)
    Step 2: Generate a random 128-bit AES session key
    Step 3: AES-EAX encrypt the plaintext with the session key
    Step 4: RSA-OAEP encrypt the session key with recipient's public key

    Returns a single dict with all components for transmission.
    """
    # Step 2 — random session key
    session_key = get_random_bytes(16)

    # Step 3 — AES-EAX encrypt the message
    aes_packet = aes_encrypt(plaintext, session_key)

    # Step 4 — RSA-OAEP encrypt the session key
    rsa_key = _build_rsa_key(pub_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    enc_sk = cipher_rsa.encrypt(session_key)
    aes_packet['enc_session_key'] = base64.b64encode(enc_sk).decode()
    return aes_packet

def hybrid_decrypt(packet: dict, priv_key: dict) -> bytes:
    """
    Step 1: RSA-OAEP decrypt the session key using recipient's private key
    Step 2: AES-EAX decrypt + verify the ciphertext
    Raises ValueError on AES MAC failure (tampered ciphertext).
    """
    # Step 1 — RSA-OAEP decrypt session key
    rsa_key = _build_rsa_key(priv_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    enc_sk      = base64.b64decode(packet['enc_session_key'])
    session_key = cipher_rsa.decrypt(enc_sk)

    # Step 2 — AES-EAX decrypt
    return aes_decrypt(packet, session_key)


# ── RSA Digital Signatures (PKCS1 v1.5 + SHA-256) ──────────────────────────

def rsa_sign(data: bytes, priv_key: dict) -> str:
    """
    Sign data using PKCS1 v1.5 + SHA-256 (same as friend's approach).

    Process:
      1. Compute SHA-256 hash of data
      2. Sign hash with private key using PKCS1 v1.5
      3. Return base64-encoded signature

    This is equivalent to the custom:  sig = SHA256(data)^d mod n
    but uses proper PKCS1 v1.5 padding for security.
    """
    h   = SHA256.new(data)
    rsa_key = _build_rsa_key(priv_key)
    sig = pkcs1_15.new(rsa_key).sign(h)
    return base64.b64encode(sig).decode()

def rsa_verify(data: bytes, signature: str, pub_key: dict) -> bool:
    """
    Verify a PKCS1 v1.5 + SHA-256 signature.
    Returns True iff the signature was produced by the holder of pub_key.
    """
    try:
        h   = SHA256.new(data)
        rsa_key = _build_rsa_key(pub_key)
        pkcs1_15.new(rsa_key).verify(h, base64.b64decode(signature))
        return True
    except Exception:
        return False
