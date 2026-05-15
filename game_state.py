"""
game_state.py — Game State Lifecycle
=====================================
Manages game.json — the single source of truth for a running game.

game.json schema:
{
  "game_id":       "GAME-0001",
  "status":        "setup" | "night" | "day" | "ended",
  "round":         1,
  "players":       { "<name>": {"status": "alive"|"eliminated", "public_key": {...}} },
  "commitments":   { "<name>": "<sha256hex>" },
  "gm_public_key": {...},
  "eliminated":    ["frank", ...],
  "winner":        null | "Wolves" | "Villagers",
  "events":        [...]
}
"""

import json, os, glob

GAMES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'games')

def _gdir_base():
    os.makedirs(GAMES_DIR, exist_ok=True)
    return GAMES_DIR

def game_dir(game_id):
    return os.path.join(_gdir_base(), game_id)

def _next_id():
    existing = sorted(glob.glob(os.path.join(_gdir_base(), 'GAME-*')))
    if not existing:
        return 'GAME-0001'
    last = int(os.path.basename(existing[-1]).split('-')[1])
    return f'GAME-{last+1:04d}'

def load(gdir):
    with open(os.path.join(gdir, 'game.json')) as f:
        return json.load(f)

def save(gdir, state):
    with open(os.path.join(gdir, 'game.json'), 'w') as f:
        json.dump(state, f, indent=2)

def create(player_names):
    gid  = _next_id()
    gdir = game_dir(gid)
    os.makedirs(gdir, exist_ok=True)
    state = {
        'game_id':      gid,
        'status':       'setup',
        'round':        0,
        'players':      {n: {'status': 'alive', 'public_key': None} for n in player_names},
        'commitments':  {},
        'gm_public_key': None,
        'eliminated':   [],
        'winner':       None,
        'events':       [],
        'night_actions': {},
    }
    save(gdir, state)
    return gid, gdir, state

def add_event(state, msg):
    state.setdefault('events', []).append(msg)
    return state

def list_games():
    return sorted([
        os.path.basename(d)
        for d in glob.glob(os.path.join(_gdir_base(), 'GAME-*'))
        if os.path.isdir(d)
    ])
