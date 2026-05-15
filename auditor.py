"""
auditor.py — End-Game Cryptographic Audit
==========================================
Independent verification of all cryptographic guarantees.

Check 1 — Role card commitments
    SHA-256(encrypted_packet) == commitment published at game start

Check 2 — GM signatures on role cards
    Decrypt each role card and verify pkcs1_15 signature from GM

Check 3 — Day vote signatures
    Every signed vote verifies with the stated voter's public key

Check 4 — Night action signatures
    Wolf kills and doctor protections carry valid player signatures

Check 5 — Seer verdict GM signatures
    Each seer verdict decrypts and verifies against GM public key

Check 6 — Game outcome consistency
    Final alive/dead player roles match the declared winner
"""

import json, os, glob, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crypto_utils as cu
import key_exchange as kx
import role_manager as rm
import game_state   as gs


class AuditResult:
    def __init__(self, num, name):
        self.check_num = num
        self.name      = name
        self.passed    = True
        self.issues    = []

    def fail(self, msg):
        self.passed = False
        self.issues.append(msg)

    def __str__(self):
        s = '✅ PASS' if self.passed else '❌ FAIL'
        lines = [f'  [{self.check_num}] {s} — {self.name}']
        for i in self.issues: lines.append(f'       ⚠  {i}')
        return '\n'.join(lines)


def audit_game(gdir):
    state   = gs.load(gdir)
    gm_pub  = state['gm_public_key']
    players = list(state['players'].keys())
    results = []

    # ── Check 1: Commitment integrity ──────────────────────────────────────
    r1 = AuditResult(1, 'Role card commitments match published SHA-256 hashes')
    for name in players:
        enc_path = os.path.join(gdir, 'players', name, 'encrypted_role.json')
        if not os.path.exists(enc_path):
            r1.fail(f'{name}: encrypted_role.json missing'); continue
        with open(enc_path) as f: packet = json.load(f)
        if cu.commitment(packet) != state['commitments'].get(name, ''):
            r1.fail(f'{name}: commitment mismatch')
    results.append(r1)

    # ── Check 2: GM signatures on role cards ───────────────────────────────
    r2 = AuditResult(2, 'GM signatures on all role cards are valid (pkcs1_15 + SHA-256)')
    for name in players:
        try:
            priv = kx.load_player_private(gdir, name)
            with open(os.path.join(gdir, 'players', name, 'encrypted_role.json')) as f:
                packet = json.load(f)
            card_bytes = cu.hybrid_decrypt(packet, priv)
            card = json.loads(card_bytes)
            sig  = card.pop('gm_signature')
            if not cu.rsa_verify(cu.canonical(card), sig, gm_pub):
                r2.fail(f'{name}: GM signature invalid')
        except Exception as e:
            r2.fail(f'{name}: {e}')
    results.append(r2)

    # ── Check 3: Day vote signatures ───────────────────────────────────────
    r3 = AuditResult(3, 'All day vote signatures are valid (pkcs1_15 + SHA-256)')
    for rnd_dir in sorted(glob.glob(os.path.join(gdir, 'rounds', '*'))):
        day_dir = os.path.join(rnd_dir, 'day')
        if not os.path.isdir(day_dir): continue
        for fname in os.listdir(day_dir):
            if not fname.startswith('vote_'): continue
            with open(os.path.join(day_dir, fname)) as f: vote = json.load(f)
            voter = vote.get('voter', '')
            sig   = vote.pop('signature', None)
            try:
                pub = kx.load_player_public(gdir, voter)
                if not sig or not cu.rsa_verify(cu.canonical(vote), sig, pub):
                    r3.fail(f'Round {vote.get("round")} vote by {voter}: invalid')
            except Exception as e:
                r3.fail(f'{voter}: {e}')
            vote['signature'] = sig
    results.append(r3)

    # ── Check 4: Night action signatures ───────────────────────────────────
    r4 = AuditResult(4, 'All night action signatures are valid')
    for rnd_dir in sorted(glob.glob(os.path.join(gdir, 'rounds', '*'))):
        night_dir = os.path.join(rnd_dir, 'night')
        if not os.path.isdir(night_dir): continue
        for fname in os.listdir(night_dir):
            if not (fname.startswith('wolf_kill_') or fname.startswith('doctor_protect_')): continue
            with open(os.path.join(night_dir, fname)) as f: action = json.load(f)
            sig    = action.pop('signature', None)
            signer = action.get('wolf') or action.get('doctor', '')
            try:
                pub = kx.load_player_public(gdir, signer)
                if not sig or not cu.rsa_verify(cu.canonical(action), sig, pub):
                    r4.fail(f'{fname}: invalid signature for {signer}')
            except Exception as e:
                r4.fail(f'{fname}: {e}')
            action['signature'] = sig
    results.append(r4)

    # ── Check 5: Seer verdict GM signatures ────────────────────────────────
    r5 = AuditResult(5, 'Seer verdict GM signatures are valid')
    for rnd_dir in sorted(glob.glob(os.path.join(gdir, 'rounds', '*'))):
        night_dir = os.path.join(rnd_dir, 'night')
        if not os.path.isdir(night_dir): continue
        for fname in os.listdir(night_dir):
            if not fname.startswith('seer_verdict_'): continue
            seer_name = fname.replace('seer_verdict_', '').replace('.json', '')
            try:
                priv = kx.load_player_private(gdir, seer_name)
                with open(os.path.join(night_dir, fname)) as f: enc = json.load(f)
                plain   = cu.hybrid_decrypt(enc, priv)
                verdict = json.loads(plain)
                sig     = verdict.pop('gm_signature')
                if not cu.rsa_verify(cu.canonical(verdict), sig, gm_pub):
                    r5.fail(f'{fname}: GM signature invalid')
            except Exception as e:
                r5.fail(f'{fname}: {e}')
    results.append(r5)

    # ── Check 6: Game outcome consistency ──────────────────────────────────
    r6 = AuditResult(6, 'Game outcome is consistent with role assignments')
    try:
        roles    = rm.gm_role_map(gdir)
        alive    = [n for n in players if n not in state.get('eliminated', [])]
        winner   = state.get('winner')
        alive_w  = [n for n in alive if roles.get(n) == 'Wolf']
        alive_v  = [n for n in alive if roles.get(n) != 'Wolf']
        if winner == 'Villagers' and alive_w:
            r6.fail(f'Winner=Villagers but wolves {alive_w} still alive')
        if winner == 'Wolves' and len(alive_w) < len(alive_v):
            r6.fail('Winner=Wolves but villagers still outnumber wolves')
    except Exception as e:
        r6.fail(f'Could not verify: {e}')
    results.append(r6)

    return results


def print_audit(gdir):
    state = gs.load(gdir)
    print(f"\n{'='*60}")
    print(f"  WolfCrypt Cryptographic Audit — {state['game_id']}")
    print(f"{'='*60}")
    results = audit_game(gdir)
    passed  = sum(1 for r in results if r.passed)
    for r in results: print(r)
    print(f"\n  Result: {passed}/{len(results)} checks passed")
    print(f"{'='*60}\n")
    return results
