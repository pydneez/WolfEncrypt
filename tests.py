"""
tests.py — WolfCrypt Automated Test Suite (10 tests)
=====================================================
Run:  python tests.py
"""

import sys, os, json, base64, traceback
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wolfcrypt import (
    Host, Player, verify_vote,
    sha256_hex, canonical, rsa_sign, rsa_verify,
    hybrid_decrypt
)


# ── Shared setup ──────────────────────────────────────────────────────────────

def make_game():
    host    = Host()
    players = {n: Player(n) for n in ['Alice', 'Bob', 'Charlie', 'Diana', 'Eve', 'Frank']}
    role_map = {
        'Alice': 'Wolf', 
        'Bob': 'Wolf',
        'Charlie': 'Seer',
        'Diana': 'Doctor',
        'Eve': 'Villager',
        'Frank': 'Villager',
    }
    packages = {}
    commitments = {}
    for name, player in players.items():
        role    = role_map[name]
        allies  = [w for w in ['Alice','Bob'] if w != name] if role == 'Wolf' else []
        pkg     = host.encrypt_role_for_player(player, role, allies)
        commit  = host.compute_commitment(pkg)
        packages[name]    = pkg
        commitments[name] = commit
    return host, players, role_map, packages, commitments


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_1_valid_role_decryption():
    """Player decrypts role card and GM signature verifies."""
    host, players, role_map, packages, commitments = make_game()
    card = players['Alice'].decrypt_role(packages['Alice'], commitments['Alice'], host.pub_key)
    assert card['role'] == 'Wolf'
    assert card['player'] == 'Alice'
    assert 'gm_signature' in card


def test_2_commitment_mismatch_detected():
    """Tampered encrypted packet — commitment check raises ValueError."""
    host, players, role_map, packages, commitments = make_game()
    pkg = json.loads(json.dumps(packages['Alice']))  # deep copy
    ct  = base64.b64decode(pkg['ciphertext'])
    ct  = bytes([ct[0] ^ 0xFF]) + ct[1:]            # flip one byte
    pkg['ciphertext'] = base64.b64encode(ct).decode()

    raised = False
    try:
        players['Alice'].decrypt_role(pkg, commitments['Alice'], host.pub_key)
    except ValueError:
        raised = True
    assert raised, 'Should raise ValueError on commitment mismatch'


def test_3_tampered_role_card_gm_sig_fails():
    """Role card with altered role field — GM signature must fail."""
    host, players, role_map, packages, commitments = make_game()
    # Manually decrypt to get the card, then tamper
    priv = players['Alice']._priv
    card_bytes = hybrid_decrypt(packages['Alice'], priv)
    card = json.loads(card_bytes)
    sig  = card.pop('gm_signature')
    card['role'] = 'Villager'   # tamper: change Wolf → Villager
    assert not rsa_verify(canonical(card), sig, host.pub_key), \
        'Tampered role card should fail GM signature check'


def test_4_valid_day_vote_signature():
    """Signed vote verifies with the voter's own public key."""
    host, players, _, _, _ = make_game()
    vote = players['Charlie'].cast_vote('Alice')
    sig  = vote.pop('signature')
    ok   = rsa_verify(canonical(vote), sig, players['Charlie'].pub_key)
    assert ok, 'Vote signature should verify with voter\'s public key'


def test_5_forged_vote_rejected():
    """Vote signed by the wrong player — must not verify."""
    host, players, _, _, _ = make_game()
    vote = players['Bob'].cast_vote('Alice')   # Bob signs
    sig  = vote.pop('signature')
    ok   = rsa_verify(canonical(vote), sig, players['Charlie'].pub_key)  # check with Charlie
    assert not ok, 'Bob\'s signature should not verify with Charlie\'s public key'


def test_6_seer_verdict_gm_signature_valid():
    """Seer verdict is GM-signed and result is Wolf or Not Wolf."""
    host, players, role_map, _, _ = make_game()
    seer    = players['Charlie']
    pkg     = host.seer_verdict(seer, 'Alice', role_map)
    verdict = seer.read_seer_verdict(pkg, host.pub_key)
    assert verdict['signature_valid'],              'GM signature on verdict should be valid'
    assert verdict['result'] in ('Wolf', 'Not Wolf'), 'Result must be Wolf or Not Wolf'
    assert verdict['result'] == 'Wolf',             'Alice is a Wolf'


def test_7_non_seer_cannot_decrypt_verdict():
    """Villager cannot decrypt a seer verdict — wrong private key raises exception."""
    host, players, role_map, _, _ = make_game()
    seer     = players['Charlie']
    villager = players['Frank']
    pkg      = host.seer_verdict(seer, 'Alice', role_map)

    raised = False
    try:
        hybrid_decrypt(pkg, villager._priv)   # wrong key
    except Exception:
        raised = True
    assert raised, 'Non-Seer should not be able to decrypt the seer verdict'


def test_8_role_proof_valid():
    """Player can prove their role by showing the GM-signed card to any verifier."""
    host, players, role_map, packages, commitments = make_game()
    card = players['Charlie'].decrypt_role(packages['Charlie'], commitments['Charlie'], host.pub_key)
    sig  = card.pop('gm_signature')
    ok   = rsa_verify(canonical(card), sig, host.pub_key)
    assert ok,                     'Role proof should verify against GM public key'
    assert card['role'] == 'Seer', 'Card should say Seer'


def test_9_fake_role_claim_rejected():
    """Villager cannot forge a Wolf role card signed by the GM."""
    host, players, role_map, packages, commitments = make_game()
    fake_card = {
        'game_id': 'GAME-0001', 'player': 'Frank',
        'role': 'Wolf', 'allies': [], 'timestamp': '2026-01-01T00:00:00',
    }
    # Frank signs with his own private key
    fake_sig = rsa_sign(canonical(fake_card), players['Frank']._priv)
    # Must NOT verify against GM public key
    ok = rsa_verify(canonical(fake_card), fake_sig, host.pub_key)
    assert not ok, 'Villager-signed fake Wolf card should not verify with GM public key'


def test_10_verify_vote_helper():
    """verify_vote() correctly validates all signed votes in a round."""
    host, players, _, _, _ = make_game()
    votes = [p.cast_vote('Alice') for p in players.values()]
    for vote in votes:
        assert verify_vote(dict(vote), players), f'{vote["voter"]}\'s vote failed verification'


# ── Runner ────────────────────────────────────────────────────────────────────

TESTS = [
    (1,  'Valid role card decryption + GM signature',           test_1_valid_role_decryption),
    (2,  'Commitment mismatch detected (tampered packet)',       test_2_commitment_mismatch_detected),
    (3,  'Tampered role card field — GM signature fails',       test_3_tampered_role_card_gm_sig_fails),
    (4,  'Valid day vote signature (pkcs1_15 + SHA-256)',        test_4_valid_day_vote_signature),
    (5,  'Forged vote (wrong key) rejected',                    test_5_forged_vote_rejected),
    (6,  'Seer verdict: GM signature valid + correct result',   test_6_seer_verdict_gm_signature_valid),
    (7,  'Non-Seer cannot decrypt seer verdict',               test_7_non_seer_cannot_decrypt_verdict),
    (8,  'Role proof: GM-signed card proves player identity',   test_8_role_proof_valid),
    (9,  'Fake role claim rejected (player key ≠ GM key)',      test_9_fake_role_claim_rejected),
    (10, 'verify_vote() validates all signed votes',            test_10_verify_vote_helper),
]

def run_tests(verbose=True):
    passed = 0
    if verbose:
        print(f'\n{"="*58}\n  WolfCrypt Test Suite\n{"="*58}')
    for num, name, fn in TESTS:
        try:
            fn(); status = '✅ PASS'; passed += 1
        except Exception as e:
            status = f'❌ FAIL — {e}'
            if verbose: traceback.print_exc()
        if verbose:
            print(f'  [{num:2d}] {status}')
            print(f'       {name}')
    if verbose:
        print(f'\n  Result: {passed}/{len(TESTS)} passed\n{"="*58}\n')
    return passed, len(TESTS)

if __name__ == '__main__':
    # sys.exit removed — runs cleanly in Python IDLE
    run_tests()