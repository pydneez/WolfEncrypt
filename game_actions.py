"""
game_actions.py — Signed Game Actions
======================================
All game actions are RSA-signed (pkcs1_15 + SHA-256) for non-repudiation.

Night phase:
  wolf_kill_vote    — wolf casts a signed kill vote
  seer_investigate  — GM produces signed verdict encrypted for Seer only
  seer_read_verdict — Seer decrypts and verifies the verdict
  doctor_protect    — doctor casts a signed protection action
  resolve_night     — apply wolf kill (unless doctor saved), advance to day

Day phase:
  day_vote          — player casts a signed elimination vote
  get_day_votes     — retrieve all votes for current round
  resolve_day       — tally votes, eliminate plurality, check win condition
"""

import json, os, datetime, collections, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crypto_utils as cu
import key_exchange as kx
import role_manager as rm
import game_state   as gs


def _ts():    return datetime.datetime.utcnow().isoformat()
def _alive(s): return [n for n, p in s['players'].items() if p['status'] == 'alive']

def _rdir(gdir, rnd, phase):
    d = os.path.join(gdir, 'rounds', f'round_{rnd:02d}', phase)
    os.makedirs(d, exist_ok=True)
    return d

def _save(path, obj):
    with open(path, 'w') as f: json.dump(obj, f, indent=2)

def _load(path):
    with open(path) as f: return json.load(f)


# ── Night: Wolf Kill ───────────────────────────────────────────────────────

def wolf_kill_vote(gdir, wolf_name, target, state):
    """
    Wolf casts a signed kill vote.
    Non-repudiable: wolf's private key signs the action.
    """
    rnd  = state['round']
    priv = kx.load_player_private(gdir, wolf_name)
    action = {
        'type':    'wolf_kill',
        'game_id': state['game_id'],
        'round':   rnd,
        'wolf':    wolf_name,
        'target':  target,
        'timestamp': _ts(),
    }
    action['signature'] = cu.rsa_sign(cu.canonical(action), priv)
    _save(os.path.join(_rdir(gdir, rnd, 'night'), f'wolf_kill_{wolf_name}.json'), action)
    return action


# ── Night: Seer Investigation ──────────────────────────────────────────────

def seer_investigate(gdir, seer_name, target, state):
    """
    GM produces a signed investigation verdict, encrypted only for the Seer.

    Step 1 — GM signs the verdict (pkcs1_15 + SHA-256)
    Step 2 — Hybrid-encrypt the signed verdict for the Seer's public key
    Result  — Only the Seer can decrypt; GM signature proves authenticity.
    """
    rnd      = state['round']
    gm_priv  = kx.load_gm_private(gdir)
    seer_pub = kx.load_player_public(gdir, seer_name)
    roles    = rm.gm_role_map(gdir)

    verdict = {
        'type':         'seer_verdict',
        'game_id':      state['game_id'],
        'round':        rnd,
        'target':       target,
        'result':       'Wolf' if roles.get(target) == 'Wolf' else 'Not Wolf',
        'requested_by': seer_name,
        'timestamp':    _ts(),
    }
    verdict['gm_signature'] = cu.rsa_sign(cu.canonical(verdict), gm_priv)

    # Encrypt signed verdict for Seer only
    encrypted = cu.hybrid_encrypt(cu.canonical(verdict), seer_pub)
    _save(os.path.join(_rdir(gdir, rnd, 'night'), f'seer_verdict_{seer_name}.json'), encrypted)
    return encrypted


def seer_read_verdict(gdir, seer_name, state):
    """
    Seer decrypts and verifies their investigation verdict.
    Returns the verdict dict with 'signature_valid' field added.
    """
    rnd       = state['round']
    gm_pub    = state['gm_public_key']
    seer_priv = kx.load_player_private(gdir, seer_name)

    enc = _load(os.path.join(_rdir(gdir, rnd, 'night'), f'seer_verdict_{seer_name}.json'))
    plain   = cu.hybrid_decrypt(enc, seer_priv)
    verdict = json.loads(plain)

    sig   = verdict.pop('gm_signature')
    valid = cu.rsa_verify(cu.canonical(verdict), sig, gm_pub)
    verdict['gm_signature']    = sig
    verdict['signature_valid'] = valid
    return verdict


# ── Night: Doctor Protection ───────────────────────────────────────────────

def doctor_protect(gdir, doctor_name, target, state):
    """Doctor casts a signed protection action."""
    rnd  = state['round']
    priv = kx.load_player_private(gdir, doctor_name)
    action = {
        'type':    'doctor_protect',
        'game_id': state['game_id'],
        'round':   rnd,
        'doctor':  doctor_name,
        'target':  target,
        'timestamp': _ts(),
    }
    action['signature'] = cu.rsa_sign(cu.canonical(action), priv)
    _save(os.path.join(_rdir(gdir, rnd, 'night'), f'doctor_protect_{doctor_name}.json'), action)
    return action


# ── Night: Resolve ─────────────────────────────────────────────────────────

def resolve_night(gdir, state):
    """
    Tally wolf kill votes, apply doctor protection, eliminate target.
    Returns (updated_state, event_message).
    """
    rnd   = state['round']
    d     = _rdir(gdir, rnd, 'night')
    alive = _alive(state)

    kill_votes = {}
    for fname in os.listdir(d):
        if fname.startswith('wolf_kill_'):
            a = _load(os.path.join(d, fname))
            t = a.get('target')
            kill_votes[t] = kill_votes.get(t, 0) + 1

    kill_target = max(kill_votes, key=kill_votes.get) if kill_votes else None
    protected   = None
    for fname in os.listdir(d):
        if fname.startswith('doctor_protect_'):
            protected = _load(os.path.join(d, fname)).get('target')

    if kill_target and kill_target != protected and kill_target in alive:
        state['players'][kill_target]['status'] = 'eliminated'
        state['eliminated'].append(kill_target)
        event = f'Round {rnd} night: {kill_target} was killed by the wolves.'
    elif kill_target and kill_target == protected:
        event = f'Round {rnd} night: {kill_target} was targeted but the Doctor saved them!'
    else:
        event = f'Round {rnd} night: no one was killed.'

    gs.add_event(state, event)
    state['status']        = 'day'
    state['night_actions'] = {}
    _save(os.path.join(d, 'night_result.json'),
          {'kill_target': kill_target, 'protected': protected, 'event': event})
    return state, event


# ── Day: Vote ──────────────────────────────────────────────────────────────

def day_vote(gdir, voter, target, state):
    """
    Cast a signed day vote. Non-repudiable: voter's private key signs.
    Stored permanently for audit.
    """
    rnd  = state['round']
    priv = kx.load_player_private(gdir, voter)
    vote = {
        'type':    'day_vote',
        'game_id': state['game_id'],
        'round':   rnd,
        'voter':   voter,
        'target':  target,
        'timestamp': _ts(),
    }
    vote['signature'] = cu.rsa_sign(cu.canonical(vote), priv)
    _save(os.path.join(_rdir(gdir, rnd, 'day'), f'vote_{voter}.json'), vote)
    return vote

def get_day_votes(gdir, state):
    rnd = state['round']
    d   = _rdir(gdir, rnd, 'day')
    return [_load(os.path.join(d, f))
            for f in os.listdir(d) if f.startswith('vote_')]


# ── Day: Resolve ───────────────────────────────────────────────────────────

def resolve_day(gdir, state):
    """
    Tally votes, eliminate plurality, check win condition.
    Returns (updated_state, event, winner_or_None).
    """
    rnd   = state['round']
    d     = _rdir(gdir, rnd, 'day')
    alive = _alive(state)

    tally = collections.Counter()
    for fname in os.listdir(d):
        if fname.startswith('vote_'):
            tally[_load(os.path.join(d, fname))['target']] += 1

    if not tally:
        event = f'Round {rnd} day: no votes, no elimination.'
        gs.add_event(state, event)
        state['round'] += 1; state['status'] = 'night'; state['night_actions'] = {}
        return state, event, None

    eliminated = tally.most_common(1)[0][0]
    state['players'][eliminated]['status'] = 'eliminated'
    state['eliminated'].append(eliminated)
    event = f'Round {rnd} day: {eliminated} eliminated ({tally[eliminated]} votes).'
    gs.add_event(state, event)
    _save(os.path.join(d, 'day_result.json'), {'tally': dict(tally), 'eliminated': eliminated})

    winner = _check_winner(gdir, state)
    if winner:
        state['winner'] = winner; state['status'] = 'ended'
        gs.add_event(state, f'Game over — {winner} win!')
    else:
        state['round'] += 1; state['status'] = 'night'; state['night_actions'] = {}

    return state, event, winner


def _check_winner(gdir, state):
    alive = _alive(state)
    try:
        roles = rm.gm_role_map(gdir)
    except Exception:
        return None
    alive_wolves    = [n for n in alive if roles.get(n) == 'Wolf']
    alive_villagers = [n for n in alive if roles.get(n) != 'Wolf']
    if not alive_wolves:       return 'Villagers'
    if len(alive_wolves) >= len(alive_villagers): return 'Wolves'
    return None
