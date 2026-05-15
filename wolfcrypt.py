"""
wolfcrypt.py — Secure Role Distribution System for Board Games
==============================================================
Extends the PGP hybrid encryption approach (wolf.py) with:
  1. Custom RSA key generation  (myRSA.py — Miller-Rabin + Extended Euclidean)
  2. SHA-256 commitment scheme  (integrity — roles cannot be changed after publish)
  3. Seer verdict               (role-based access control — only Seer can read)
  4. Signed votes               (non-repudiation — votes are permanently attributed)

Cryptographic libraries used:
  - Custom : RSA key generation (primeGenerator, mulInverse, myRSA)
  - PKCS1_OAEP  : RSA encryption of session keys
  - pkcs1_15    : RSA digital signatures
  - AES-EAX     : authenticated symmetric encryption (upgrade over CBC: detects tampering)
  - SHA-256     : hashing and commitments
"""

import json
import base64
import hashlib
import datetime

from Crypto.PublicKey import RSA
from Crypto.Cipher    import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash      import SHA256
from Crypto.Random    import get_random_bytes

import myRSA  # custom RSA key generation

KEY_BITS = 512   # 512-bit for demo speed; set to 1024+ for production


# ══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def canonical(obj: dict) -> bytes:
    """
    Deterministic JSON serialisation.
    Sorted keys and no extra whitespace guarantee the same bytes every time,
    regardless of insertion order or platform — essential for signing and hashing.
    """
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def build_rsa_key(key_dict: dict):
    """
    Construct a pycryptodome RSAKey from our custom key dict.
    Custom key gen stores {"e": int, "n": int} or {"d": int, "n": int, "e": int}.
    RSA.construct bridges these into pycryptodome for PKCS1_OAEP / pkcs1_15.
    """
    n = key_dict['n']
    e = key_dict['e']
    if 'd' in key_dict:
        return RSA.construct((n, e, key_dict['d']))
    return RSA.construct((n, e))

def generate_keypair() -> tuple:
    """
    Generate RSA key pair using the CUSTOM myRSA implementation.
    Steps performed inside myRSA.rsaKeyGen():
      1. Miller-Rabin prime generation for p and q
      2. n = p * q,  phi(n) = (p-1)(q-1)
      3. Choose e with gcd(e, phi) = 1
      4. d = e^(-1) mod phi  via Extended Euclidean algorithm
    Returns (private_dict, public_dict).
    """
    (d, n), (e, _) = myRSA.rsaKeyGen(KEY_BITS)
    return {'d': d, 'n': n, 'e': e}, {'e': e, 'n': n}


# ══════════════════════════════════════════════════════════════════════════════
# HYBRID ENCRYPTION  (mirrors wolf.py structure, upgraded to AES-EAX)
# ══════════════════════════════════════════════════════════════════════════════

def hybrid_encrypt(plaintext: bytes, pub_key: dict) -> dict:
    """
    Hybrid encryption — same architecture as wolf.py / PGP:
      Step 1: Generate a random 128-bit AES session key
      Step 2: AES-EAX encrypt the message with the session key
              (EAX provides a MAC tag — detects any tampering, unlike CBC)
      Step 3: RSA-OAEP encrypt the session key with the recipient's public key
    """
    session_key = get_random_bytes(16)

    # Step 2 — AES-EAX (authenticated encryption)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

    # Step 3 — RSA-OAEP
    rsa_key   = build_rsa_key(pub_key)
    enc_sk    = PKCS1_OAEP.new(rsa_key).encrypt(session_key)

    return {
        'enc_session_key': base64.b64encode(enc_sk).decode(),
        'nonce':           base64.b64encode(cipher_aes.nonce).decode(),
        'ciphertext':      base64.b64encode(ciphertext).decode(),
        'tag':             base64.b64encode(tag).decode(),
    }

def hybrid_decrypt(package: dict, priv_key: dict) -> bytes:
    """
    Step 1: RSA-OAEP decrypt the session key with recipient's private key
    Step 2: AES-EAX decrypt + verify MAC tag
    Raises ValueError if the ciphertext was tampered with (MAC failure).
    """
    rsa_key    = build_rsa_key(priv_key)
    enc_sk     = base64.b64decode(package['enc_session_key'])
    session_key = PKCS1_OAEP.new(rsa_key).decrypt(enc_sk)

    nonce      = base64.b64decode(package['nonce'])
    ciphertext = base64.b64decode(package['ciphertext'])
    tag        = base64.b64decode(package['tag'])

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag)


# ══════════════════════════════════════════════════════════════════════════════
# DIGITAL SIGNATURES  (same as wolf.py: pkcs1_15 + SHA-256)
# ══════════════════════════════════════════════════════════════════════════════

def rsa_sign(data: bytes, priv_key: dict) -> str:
    h   = SHA256.new(data)
    sig = pkcs1_15.new(build_rsa_key(priv_key)).sign(h)
    return base64.b64encode(sig).decode()

def rsa_verify(data: bytes, signature: str, pub_key: dict) -> bool:
    try:
        h = SHA256.new(data)
        pkcs1_15.new(build_rsa_key(pub_key)).verify(h, base64.b64decode(signature))
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# PLAYER CLASS
# ══════════════════════════════════════════════════════════════════════════════

class Player:
    """
    Represents a game participant.
    Key pair is generated using the custom RSA implementation (myRSA.py).
    """

    def __init__(self, name: str):
        self.name = name
        self._priv, self.pub_key = generate_keypair()
        self.role_card    = None   # set after decrypt_role()
        self.role_verified = False

    # ── Role decryption ────────────────────────────────────────────────────

    def decrypt_role(self, package: dict, commitment: str, host_pub_key: dict) -> dict:
        """
        Decrypt and verify the player's own role card.

        Step 1 — Check commitment
            SHA-256(package) must match the hash published before the game started.
            If it does not, the package was tampered with after commitment.

        Step 2 — Hybrid decrypt (RSA-OAEP session key + AES-EAX message)

        Step 3 — Verify GM signature (pkcs1_15 + SHA-256)
            Confirms the Host signed this role card.

        Raises ValueError if any check fails.
        """
        # Step 1 — Commitment check
        current_hash = sha256_hex(canonical(package))
        if current_hash != commitment:
            raise ValueError(
                f'Commitment mismatch for {self.name}!\n'
                f'  Expected : {commitment}\n'
                f'  Got      : {current_hash}\n'
                f'The role packet was modified after the commitment was published.'
            )

        # Step 2 — Decrypt
        card_bytes = hybrid_decrypt(package, self._priv)
        card = json.loads(card_bytes)

        # Step 3 — Verify GM signature
        sig = card.pop('gm_signature')
        if not rsa_verify(canonical(card), sig, host_pub_key):
            raise ValueError(f'GM signature invalid for {self.name}!')
        card['gm_signature'] = sig

        self.role_card     = card
        self.role_verified = True
        return card

    # ── Vote signing ───────────────────────────────────────────────────────

    def cast_vote(self, target: str, game_id: str = 'GAME-0001') -> dict:
        """
        Cast a signed elimination vote.
        The vote is signed with this player's private key — non-repudiable.
        """
        vote = {
            'type':      'elimination_vote',
            'game_id':   game_id,
            'voter':     self.name,
            'target':    target,
            'timestamp': datetime.datetime.utcnow().isoformat(),
        }
        vote['signature'] = rsa_sign(canonical(vote), self._priv)
        return vote

    # ── Seer: read verdict ─────────────────────────────────────────────────

    def read_seer_verdict(self, verdict_package: dict, host_pub_key: dict) -> dict:
        """
        Seer decrypts and verifies their investigation verdict.
        Only works for the Seer — other players' private keys will fail decryption.
        """
        plain   = hybrid_decrypt(verdict_package, self._priv)
        verdict = json.loads(plain)

        sig   = verdict.pop('gm_signature')
        valid = rsa_verify(canonical(verdict), sig, host_pub_key)
        verdict['gm_signature']    = sig
        verdict['signature_valid'] = valid
        return verdict


# ══════════════════════════════════════════════════════════════════════════════
# HOST CLASS
# ══════════════════════════════════════════════════════════════════════════════

class Host:
    """
    The Game Master. Assigns roles, signs role cards, publishes commitments,
    and produces seer investigation verdicts.
    Key pair is generated using the custom RSA implementation (myRSA.py).
    """

    def __init__(self, name: str = 'GameHost'):
        self.name = name
        self._priv, self.pub_key = generate_keypair()

    # ── Role encryption ────────────────────────────────────────────────────

    def encrypt_role_for_player(self, player: Player, role: str,
                                 allies: list = None, game_id: str = 'GAME-0001') -> dict:
        """
        Create, sign, and encrypt a role card for one player.

        Step 1 — Build role card with metadata
        Step 2 — GM signs the role card (pkcs1_15 + SHA-256)
        Step 3 — Generate random AES session key
        Step 4 — AES-EAX encrypt the signed role card
        Step 5 — RSA-OAEP encrypt the session key with the player's public key
        """
        # Step 1 — Role card
        card = {
            'game_id':   game_id,
            'player':    player.name,
            'role':      role,
            'allies':    allies or [],
            'timestamp': datetime.datetime.utcnow().isoformat(),
        }

        # Step 2 — GM signature
        card['gm_signature'] = rsa_sign(canonical(card), self._priv)

        # Steps 3-5 — Hybrid encrypt for this player
        return hybrid_encrypt(canonical(card), player.pub_key)

    # ── Commitment ─────────────────────────────────────────────────────────

    def compute_commitment(self, package: dict) -> str:
        """
        SHA-256 hash of the encrypted package.
        Published to ALL players before anyone decrypts their role.
        This prevents the Host from changing a role after assignment.
        """
        return sha256_hex(canonical(package))

    # ── Seer verdict ───────────────────────────────────────────────────────

    def seer_verdict(self, seer: Player, target_name: str,
                     role_map: dict, game_id: str = 'GAME-0001') -> dict:
        """
        Produce a signed investigation verdict, encrypted only for the Seer.

        Step 1 — Build verdict: target name + Wolf/Not Wolf result
        Step 2 — GM signs the verdict (pkcs1_15 + SHA-256)
        Step 3 — Hybrid-encrypt the signed verdict with the Seer's public key

        Only the Seer can decrypt it.
        The GM signature proves the result is authentic — the Seer cannot fabricate it.
        Raises PermissionError if the requesting player does not have the Seer role.
        """
        # Step 1 — Role authorisation check
        if role_map.get(seer.name) != 'Seer':
            raise PermissionError(
                f'{seer.name} does not have the Seer role and cannot request an investigation.'
            )

        # Step 2 — Verdict
        verdict = {
            'type':         'seer_verdict',
            'game_id':      game_id,
            'target':       target_name,
            'result':       'Wolf' if role_map.get(target_name) == 'Wolf' else 'Not Wolf',
            'requested_by': seer.name,
            'timestamp':    datetime.datetime.utcnow().isoformat(),
        }

        # Step 3 — GM signature
        verdict['gm_signature'] = rsa_sign(canonical(verdict), self._priv)

        # Step 4 — Encrypt for Seer only
        return hybrid_encrypt(canonical(verdict), seer.pub_key)


# ══════════════════════════════════════════════════════════════════════════════
# STANDALONE VERIFY FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def verify_vote(vote: dict, players: dict) -> bool:
    """
    Verify that a vote was signed by the stated voter.
    players = {name: Player}
    """
    voter = vote.get('voter', '')
    if voter not in players:
        return False
    sig  = vote.pop('signature')
    ok   = rsa_verify(canonical(vote), sig, players[voter].pub_key)
    vote['signature'] = sig
    return ok


# ══════════════════════════════════════════════════════════════════════════════
# MAIN — command-line demo
# ══════════════════════════════════════════════════════════════════════════════

def run_demo():
    SEP = '─' * 56

    print(f'\n{"═"*56}')
    print('  WolfCrypt — Secure Role Distribution Demo')
    print(f'{"═"*56}')

    # ── Setup ────────────────────────────────────────────────────────────
    print(f'\n[1/5] KEY GENERATION  (custom Miller-Rabin + Extended Euclidean)')
    print(SEP)

    host  = Host('GameHost')
    names = ['Alice', 'Bob', 'Charlie', 'Diana', 'Eve', 'Frank']
    players = {name: Player(name) for name in names}

    print(f'  Host  : {host.name}')
    print(f'  e (GM public exponent) : {str(host.pub_key["e"])[:30]}...')
    print(f'  n (GM modulus)         : {str(host.pub_key["n"])[:30]}...')
    for name, p in players.items():
        print(f'  {name:8s}: n = {str(p.pub_key["n"])[:24]}...')

    # ── Role assignment ──────────────────────────────────────────────────
    print(f'\n[2/5] ROLE ASSIGNMENT  (sign → AES-EAX → RSA-OAEP → commit)')
    print(SEP)

    role_map = {
        'Alice':   'Wolf',
        'Bob':     'Wolf',
        'Charlie': 'Seer',
        'Diana':   'Doctor',
        'Eve':     'Villager',
        'Frank':   'Villager',
    }
    wolf_allies = ['Alice', 'Bob']

    packages    = {}
    commitments = {}

    for name, player in players.items():
        role    = role_map[name]
        allies  = [w for w in wolf_allies if w != name] if role == 'Wolf' else []
        pkg     = host.encrypt_role_for_player(player, role, allies)
        commit  = host.compute_commitment(pkg)
        packages[name]    = pkg
        commitments[name] = commit

    print('  SHA-256 commitments published to ALL players:')
    for name, h in commitments.items():
        print(f'    {name:8s}: {h[:40]}...')

    # ── Role decryption ──────────────────────────────────────────────────
    print(f'\n[3/5] ROLE DECRYPTION  (commitment check → decrypt → verify GM sig)')
    print(SEP)

    role_icons = {'Wolf':'🐺','Seer':'🔮','Doctor':'💊','Villager':'🧑‍🌾'}
    for name, player in players.items():
        card = player.decrypt_role(packages[name], commitments[name], host.pub_key)
        icon = role_icons.get(card['role'], '?')
        allies_str = f"  allies: {card['allies']}" if card['allies'] else ''
        print(f'  {icon} {name:8s} → {card["role"]}{allies_str}')
        print(f'     commitment: ✅  GM signature: ✅')

    # ── Seer verdict ─────────────────────────────────────────────────────
    print(f'\n[4/5] SEER VERDICT  (GM signs + encrypts for Seer only)')
    print(SEP)

    seer         = players['Charlie']
    investigate  = 'Alice'
    verdict_pkg  = host.seer_verdict(seer, investigate, role_map)
    verdict      = seer.read_seer_verdict(verdict_pkg, host.pub_key)

    print(f'  Seer ({seer.name}) investigates: {investigate}')
    print(f'  Result (private to {seer.name}): {verdict["result"]}')
    print(f'  GM signature: {"✅ VALID" if verdict["signature_valid"] else "❌ INVALID"}')
    print(f'  (Other players cannot decrypt this verdict)')

    # ── Signed votes ─────────────────────────────────────────────────────
    print(f'\n[5/5] SIGNED VOTES  (pkcs1_15 + SHA-256 — non-repudiable)')
    print(SEP)

    votes = []
    for name, player in players.items():
        vote = player.cast_vote(target='Alice')
        votes.append(vote)
        ok   = verify_vote(dict(vote), players)
        print(f'  {name:8s} votes to eliminate Alice — sig: {"✅ VALID" if ok else "❌"}')

    print(f'\n{"═"*56}')
    print('  All security checks passed.')
    print(f'{"═"*56}\n')

    return host, players, packages, commitments, votes


if __name__ == '__main__':
    run_demo()
