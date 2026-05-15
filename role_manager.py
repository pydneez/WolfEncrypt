"""
role_manager.py — Cryptographic Role Assignment
================================================
Implements the Host.encrypt_role_for_player() pattern from the friend's code,
extended to a multi-player game with commitments.

For each player the flow is (mirroring friend's code):
  Step 1 — GM signs the role card with pkcs1_15 + SHA-256
  Step 2 — Package {role_card + signature} as JSON
  Step 3 — Generate random 128-bit AES session key
  Step 4 — AES-EAX encrypt the package with the session key
  Step 5 — RSA-OAEP encrypt the session key with player's public key
  Step 6 — Compute SHA-256 commitment of the encrypted packet (new)
  Step 7 — Publish all commitments before game starts (new)

Role assignment (by player count):
  4 players : 1 Wolf, 1 Seer, 2 Villagers
  5 players : 1 Wolf, 1 Seer, 1 Doctor, 2 Villagers
  6 players : 2 Wolves, 1 Seer, 1 Doctor, 2 Villagers
  7+ players: 2 Wolves, 1 Seer, 1 Doctor, rest Villagers
"""

import json, os, random, datetime, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crypto_utils as cu
import key_exchange as kx
import game_state   as gs


# ── Role assignment rules ──────────────────────────────────────────────────

def _assign_roles(names):
    """Return ({name: role}, [wolf_names])."""
    n = len(names)
    shuffled = names[:]
    random.shuffle(shuffled)

    wolves_n = 1 if n <= 5 else 2
    has_doctor = n >= 5

    roles, wolves = {}, []
    i = 0
    for _ in range(wolves_n):
        roles[shuffled[i]] = 'Wolf'; wolves.append(shuffled[i]); i += 1
    roles[shuffled[i]] = 'Seer'; i += 1
    if has_doctor:
        roles[shuffled[i]] = 'Doctor'; i += 1
    while i < n:
        roles[shuffled[i]] = 'Villager'; i += 1

    return roles, wolves


# ── Assign, sign, encrypt ──────────────────────────────────────────────────

def assign_roles(gdir, state):
    """
    Assign roles to all players cryptographically.
    Returns updated state with commitments filled in.
    """
    gm_priv = kx.load_gm_private(gdir)
    gm_pub  = kx.load_gm_public(gdir)
    players = list(state['players'].keys())
    role_map, wolves = _assign_roles(players)
    ts = datetime.datetime.utcnow().isoformat()

    for name in players:
        role    = role_map[name]
        allies  = [w for w in wolves if w != name] if role == 'Wolf' else []

        # Build role card
        card = {
            'game_id':   state['game_id'],
            'player':    name,
            'role':      role,
            'allies':    allies,
            'timestamp': ts,
        }

        # Step 1 — GM signs the role card (pkcs1_15 + SHA-256)
        sig = cu.rsa_sign(cu.canonical(card), gm_priv)
        card['gm_signature'] = sig

        # Steps 2-5 — Hybrid encrypt for this player
        player_pub = kx.load_player_public(gdir, name)
        packet = cu.hybrid_encrypt(cu.canonical(card), player_pub)

        # Save encrypted packet
        p_dir = os.path.join(gdir, 'players', name)
        os.makedirs(p_dir, exist_ok=True)
        with open(os.path.join(p_dir, 'encrypted_role.json'), 'w') as f:
            json.dump(packet, f)

        # Step 6 — Commitment
        state['commitments'][name] = cu.commitment(packet)

    # Store GM role manifest (encrypted for GM) for night resolution
    gm_manifest = json.dumps(role_map, sort_keys=True).encode()
    enc_manifest = cu.hybrid_encrypt(gm_manifest, gm_pub)
    with open(os.path.join(gdir, 'gm', 'roles_manifest.json'), 'w') as f:
        json.dump(enc_manifest, f)

    state['gm_public_key'] = gm_pub
    state['status']        = 'night'
    state['round']         = 1
    gs.add_event(state, f'Roles assigned and committed for {len(players)} players.')
    return state


# ── Player: decrypt own role ───────────────────────────────────────────────

def decrypt_my_role(gdir, player_name, state):
    """
    Decrypt and verify a player's own role card.
    Mirrors friend's receive_role() function.

    Step 1 — RSA-OAEP decrypt the session key (player's private key)
    Step 2 — AES-EAX decrypt the role package
    Step 3 — Verify GM signature (pkcs1_15 + SHA-256)

    Raises ValueError on commitment mismatch or invalid GM signature.
    """
    priv   = kx.load_player_private(gdir, player_name)
    gm_pub = state['gm_public_key']

    with open(os.path.join(gdir, 'players', player_name, 'encrypted_role.json')) as f:
        packet = json.load(f)

    # Commitment check — integrity of the encrypted packet
    expected = state['commitments'].get(player_name)
    if expected and cu.commitment(packet) != expected:
        raise ValueError('Commitment mismatch — the role packet was tampered with after assignment!')

    # Step 1+2 — Hybrid decrypt
    card_bytes = cu.hybrid_decrypt(packet, priv)
    card = json.loads(card_bytes)

    # Step 3 — Verify GM signature
    sig = card.pop('gm_signature')
    if not cu.rsa_verify(cu.canonical(card), sig, gm_pub):
        raise ValueError('GM signature invalid — role card may be forged!')
    card['gm_signature'] = sig
    return card


# ── GM: get plaintext role map ─────────────────────────────────────────────

def gm_role_map(gdir):
    """Decrypt the GM's role manifest to get {name: role}."""
    gm_priv = kx.load_gm_private(gdir)
    with open(os.path.join(gdir, 'gm', 'roles_manifest.json')) as f:
        enc = json.load(f)
    return json.loads(cu.hybrid_decrypt(enc, gm_priv))


# ── Commitment verification ────────────────────────────────────────────────

def verify_commitment(gdir, player_name, state):
    """Anyone can verify that a player's encrypted packet matches its commitment."""
    with open(os.path.join(gdir, 'players', player_name, 'encrypted_role.json')) as f:
        packet = json.load(f)
    return cu.commitment(packet) == state['commitments'].get(player_name)
