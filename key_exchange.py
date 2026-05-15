"""
key_exchange.py — Per-game RSA Key Management
==============================================
Uses the CUSTOM myRSA.rsaKeyGen() for key generation:
  - Miller-Rabin prime generation (primeGenerator.py)
  - Extended Euclidean for computing d (mulInverseByExtendedEuclidean.py)
  - Square-and-multiply modular exponentiation (myRSA.py)

Keys are stored as JSON dicts and reconstructed into pycryptodome RSA
objects in crypto_utils when needed for PKCS1_OAEP / pkcs1_15 operations.

Directory layout:
    games/<GAME-ID>/gm/gm_private.json
    games/<GAME-ID>/gm/gm_public.json
    games/<GAME-ID>/players/<name>/<name>_private.json
    games/<GAME-ID>/players/<name>/<name>_public.json
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import myRSA

KEY_BITS = 512   # Use 512-bit for demo speed; increase for production


def generate_keypair(bits: int = KEY_BITS):
    """
    Generate RSA key pair using the CUSTOM implementation.
    Returns (priv_dict, pub_dict).

    Custom rsaKeyGen() runs:
      1. Generate two primes p, q (Miller-Rabin)
      2. Compute n = p*q, phi(n) = (p-1)(q-1)
      3. Choose e with gcd(e, phi(n)) = 1
      4. Compute d = e^(-1) mod phi(n)  via Extended Euclidean

    We store e in the private key dict so crypto_utils can reconstruct
    the pycryptodome RSA key with RSA.construct((n, e, d)).
    """
    (d, n), (e, _) = myRSA.rsaKeyGen(bits)
    priv = {'d': d, 'n': n, 'e': e}   # e stored so we can do RSA.construct
    pub  = {'e': e, 'n': n}
    return priv, pub


def _save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f)

def _load(path):
    with open(path) as f:
        return json.load(f)


# ── GM keys ────────────────────────────────────────────────────────────────

def generate_gm_keys(game_dir):
    priv, pub = generate_keypair()
    _save(os.path.join(game_dir, 'gm', 'gm_private.json'), priv)
    _save(os.path.join(game_dir, 'gm', 'gm_public.json'),  pub)
    return priv, pub

def load_gm_private(game_dir):
    return _load(os.path.join(game_dir, 'gm', 'gm_private.json'))

def load_gm_public(game_dir):
    return _load(os.path.join(game_dir, 'gm', 'gm_public.json'))


# ── Player keys ────────────────────────────────────────────────────────────

def generate_player_keys(game_dir, name):
    priv, pub = generate_keypair()
    base = os.path.join(game_dir, 'players', name)
    _save(os.path.join(base, f'{name}_private.json'), priv)
    _save(os.path.join(base, f'{name}_public.json'),  pub)
    return priv, pub

def load_player_private(game_dir, name):
    return _load(os.path.join(game_dir, 'players', name, f'{name}_private.json'))

def load_player_public(game_dir, name):
    return _load(os.path.join(game_dir, 'players', name, f'{name}_public.json'))
