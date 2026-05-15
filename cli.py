#!/usr/bin/env python3
"""
cli.py — WolfCrypt Terminal Interface
======================================
Run with: python cli.py <command> [args]

Commands:
  new-game  <p1,p2,...>               Create game & assign roles
  my-role   <GAME-ID> <name>          Decrypt your role card
  night-kill   <GAME-ID> <wolf> <target>
  night-seer   <GAME-ID> <seer> <target>
  night-protect <GAME-ID> <doctor> <target>
  resolve-night <GAME-ID>
  day-vote  <GAME-ID> <voter> <target>
  resolve-day <GAME-ID>
  status    <GAME-ID>
  audit     <GAME-ID>
  run-tests
  demo
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import game_state   as gs
import key_exchange as kx
import role_manager as rm
import game_actions as ga
import auditor
import tests as ts
import crypto_utils as cu


def header(title):
    w = 58
    print(f'\n{"─"*w}')
    print(f'  {title}')
    print(f'{"─"*w}')


def cmd_new_game(player_str):
    names = [p.strip() for p in player_str.split(',') if p.strip()]
    if len(names) < 4:
        print('  ✗  Need at least 4 players.'); return

    header(f'New Game — {len(names)} players')
    print(f'  Players : {", ".join(names)}')
    print('  [1/4] Generating GM RSA key pair (custom miller-rabin + ext-euclidean)...')
    gid, gdir, state = gs.create(names)
    gm_priv, gm_pub  = kx.generate_gm_keys(gdir)
    state['gm_public_key'] = gm_pub
    gs.save(gdir, state)

    print('  [2/4] Generating player RSA key pairs...')
    for name in names:
        priv, pub = kx.generate_player_keys(gdir, name)
        state['players'][name]['public_key'] = pub
        print(f'         {name}: n={str(pub["n"])[:18]}...')
    gs.save(gdir, state)

    print('  [3/4] Assigning and encrypting roles (PKCS1-OAEP + AES-EAX)...')
    state = rm.assign_roles(gdir, state)

    print('  [4/4] Publishing SHA-256 commitments...')
    for name, h in state['commitments'].items():
        print(f'         {name}: {h[:32]}...')
    gs.save(gdir, state)

    print(f'\n  ✓  Game {gid} ready. Status: NIGHT — Round 1')
    print(f'     Run: python cli.py my-role {gid} <name>\n')


def cmd_my_role(game_id, player):
    gdir  = gs.game_dir(game_id)
    state = gs.load(gdir)
    header(f'Role Card — {player} in {game_id}')
    try:
        card = rm.decrypt_my_role(gdir, player, state)
    except ValueError as e:
        print(f'  ✗  {e}'); return
    role    = card['role']
    allies  = ', '.join(card.get('allies', [])) or 'none'
    icons   = {'Wolf':'🐺','Seer':'🔮','Doctor':'💊','Villager':'🧑‍🌾'}
    print(f'\n  {icons.get(role,"?")} Role    : {role}')
    print(f'  Player  : {player}')
    print(f'  Allies  : {allies}')
    print(f'  Game    : {card["game_id"]}')
    print(f'\n  ✓  GM signature   : VERIFIED (pkcs1_15 + SHA-256)')
    print(f'  ✓  Commitment     : MATCHES\n')


def cmd_night_kill(game_id, wolf, target):
    gdir  = gs.game_dir(game_id)
    state = gs.load(gdir)
    if state['status'] != 'night':
        print(f'  ✗  Not night phase (current: {state["status"]})'); return
    action = ga.wolf_kill_vote(gdir, wolf, target, state)
    header('Wolf Kill Vote')
    print(f'  Wolf   : {wolf}')
    print(f'  Target : {target}')
    print(f'  Signature : {action["signature"][:40]}...')
    print(f'  ✓  Signed and recorded.\n')


def cmd_night_seer(game_id, seer, target):
    gdir  = gs.game_dir(game_id)
    state = gs.load(gdir)
    if state['status'] != 'night':
        print(f'  ✗  Not night phase'); return
    ga.seer_investigate(gdir, seer, target, state)
    verdict = ga.seer_read_verdict(gdir, seer, state)
    header(f'Seer Investigation — Private to {seer}')
    print(f'  Target  : {target}')
    print(f'  Result  : {verdict["result"]}')
    print(f'  GM sig  : {"✓  VALID" if verdict["signature_valid"] else "✗  INVALID"}\n')


def cmd_night_protect(game_id, doctor, target):
    gdir  = gs.game_dir(game_id)
    state = gs.load(gdir)
    if state['status'] != 'night':
        print(f'  ✗  Not night phase'); return
    ga.doctor_protect(gdir, doctor, target, state)
    header('Doctor Protection')
    print(f'  Doctor  : {doctor}')
    print(f'  Protect : {target}')
    print(f'  ✓  Signed and recorded.\n')


def cmd_resolve_night(game_id):
    gdir  = gs.game_dir(game_id)
    state = gs.load(gdir)
    if state['status'] != 'night':
        print('  ✗  Not night phase'); return
    state, event = ga.resolve_night(gdir, state)
    gs.save(gdir, state)
    header('Night Resolved')
    print(f'  {event}')
    _show_status(state)


def cmd_day_vote(game_id, voter, target):
    gdir  = gs.game_dir(game_id)
    state = gs.load(gdir)
    if state['status'] != 'day':
        print(f'  ✗  Not day phase (current: {state["status"]})'); return
    vote = ga.day_vote(gdir, voter, target, state)
    header('Day Vote')
    print(f'  {voter}  →  eliminate  {target}')
    print(f'  Signature : {vote["signature"][:40]}...')
    print(f'  ✓  Non-repudiable vote recorded.\n')


def cmd_resolve_day(game_id):
    gdir  = gs.game_dir(game_id)
    state = gs.load(gdir)
    if state['status'] != 'day':
        print('  ✗  Not day phase'); return
    votes = ga.get_day_votes(gdir, state)
    tally = {}
    for v in votes: tally[v['target']] = tally.get(v['target'], 0) + 1
    header(f'Day {state["round"]} Vote Tally')
    for t, c in sorted(tally.items(), key=lambda x: -x[1]):
        print(f'  {t:16s} : {"█"*c} ({c})')
    state, event, winner = ga.resolve_day(gdir, state)
    gs.save(gdir, state)
    print(f'\n  {event}')
    if winner: print(f'\n  ══  GAME OVER — {winner.upper()} WIN!  ══\n')
    _show_status(state)


def cmd_status(game_id):
    gdir  = gs.game_dir(game_id)
    state = gs.load(gdir)
    _show_status(state)


def _show_status(state):
    header(f'Status — {state["game_id"]}')
    print(f'  Phase : {state["status"].upper()}   Round : {state["round"]}')
    print(f'  Players:')
    for name, info in state['players'].items():
        icon = '●' if info['status'] == 'alive' else '○'
        print(f'    {icon} {name:16s} ({info["status"]})')
    if state.get('winner'):
        print(f'\n  WINNER : {state["winner"]}')
    if state.get('events'):
        print(f'  Recent events:')
        for e in state['events'][-3:]: print(f'    · {e}')
    print()


def cmd_audit(game_id):
    gdir = gs.game_dir(game_id)
    auditor.print_audit(gdir)


def cmd_demo():
    print('\n' + '═'*58)
    print('  WolfCrypt — Cryptographic Werewolf Demo')
    print('═'*58)

    players = ['alice', 'bob', 'charlie', 'diana', 'eve', 'frank']
    print(f'\n  Players: {", ".join(players)}')

    # Setup
    gid, gdir, state = gs.create(players)
    gm_priv, gm_pub  = kx.generate_gm_keys(gdir)
    state['gm_public_key'] = gm_pub
    gs.save(gdir, state)
    for name in players:
        priv, pub = kx.generate_player_keys(gdir, name)
        state['players'][name]['public_key'] = pub
    gs.save(gdir, state)
    state = rm.assign_roles(gdir, state)
    gs.save(gdir, state)

    roles     = rm.gm_role_map(gdir)
    wolves    = [n for n, r in roles.items() if r == 'Wolf']
    seer      = next((n for n, r in roles.items() if r == 'Seer'),   None)
    doctor    = next((n for n, r in roles.items() if r == 'Doctor'), None)
    villagers = [n for n, r in roles.items() if r == 'Villager']

    print(f'\n  [GM only] Role assignments:')
    for n, r in roles.items(): print(f'    {n:10s} → {r}')

    print(f'\n  SHA-256 commitments (public, everyone sees):')
    for n, h in state['commitments'].items(): print(f'    {n}: {h[:32]}...')

    round_num, winner = 1, None
    while not winner and round_num <= 5:
        print(f'\n{"─"*58}')
        print(f'  ROUND {round_num} — NIGHT')
        print(f'{"─"*58}')
        alive = [n for n, p in state['players'].items() if p['status'] == 'alive']
        rw    = [n for n in alive if roles.get(n) == 'Wolf']
        ro    = [n for n in alive if roles.get(n) != 'Wolf']

        if rw:
            kill_t = villagers[0] if round_num == 1 and villagers else (ro[0] if ro else None)
            if kill_t:
                for w in rw: ga.wolf_kill_vote(gdir, w, kill_t, state)
                print(f'  Wolves {rw} vote to kill: {kill_t}')

        if seer and seer in alive and rw:
            ga.seer_investigate(gdir, seer, rw[0], state)
            v = ga.seer_read_verdict(gdir, seer, state)
            print(f'  Seer ({seer}) investigates {rw[0]} → {v["result"]} [GM sig: {"✓" if v["signature_valid"] else "✗"}]')

        if doctor and doctor in alive and ro:
            ga.doctor_protect(gdir, doctor, ro[0], state)
            print(f'  Doctor ({doctor}) protects: {ro[0]}')

        state, event = ga.resolve_night(gdir, state)
        gs.save(gdir, state)
        print(f'  ► {event}')

        print(f'\n{"─"*58}')
        print(f'  ROUND {round_num} — DAY')
        print(f'{"─"*58}')
        state = gs.load(gdir)
        alive = [n for n, p in state['players'].items() if p['status'] == 'alive']
        rw2   = [n for n in alive if roles.get(n) == 'Wolf']

        if seer and seer in alive and rw2:
            card  = rm.decrypt_my_role(gdir, seer, state)
            sig   = card.pop('gm_signature')
            valid = cu.rsa_verify(cu.canonical(card), sig, state['gm_public_key'])
            print(f'  {seer} shows role proof — GM sig: {"✓ VALID" if valid else "✗"}')

        vote_t = rw2[0] if rw2 else alive[0]
        print(f'  All players vote to eliminate: {vote_t}')
        for voter in alive: ga.day_vote(gdir, voter, vote_t, state)
        state, event, winner = ga.resolve_day(gdir, state)
        gs.save(gdir, state)
        print(f'  ► {event}')
        round_num += 1

    print(f'\n{"═"*58}')
    if winner: print(f'  🏆  GAME OVER — {winner.upper()} WIN!')
    print(f'{"═"*58}')

    print('\n  Running cryptographic audit...')
    results = auditor.audit_game(gdir)
    passed  = sum(1 for r in results if r.passed)
    for r in results:
        print(f'  [{"✓" if r.passed else "✗"}] {r.name}')
    print(f'\n  Audit: {passed}/{len(results)} checks passed\n')


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); return
    cmd = args[0]
    try:
        if   cmd == 'new-game'       and len(args) >= 2: cmd_new_game(args[1])
        elif cmd == 'my-role'        and len(args) >= 3: cmd_my_role(args[1], args[2])
        elif cmd == 'night-kill'     and len(args) >= 4: cmd_night_kill(args[1], args[2], args[3])
        elif cmd == 'night-seer'     and len(args) >= 4: cmd_night_seer(args[1], args[2], args[3])
        elif cmd == 'night-protect'  and len(args) >= 4: cmd_night_protect(args[1], args[2], args[3])
        elif cmd == 'resolve-night'  and len(args) >= 2: cmd_resolve_night(args[1])
        elif cmd == 'day-vote'       and len(args) >= 4: cmd_day_vote(args[1], args[2], args[3])
        elif cmd == 'resolve-day'    and len(args) >= 2: cmd_resolve_day(args[1])
        elif cmd == 'status'         and len(args) >= 2: cmd_status(args[1])
        elif cmd == 'audit'          and len(args) >= 2: cmd_audit(args[1])
        elif cmd == 'run-tests': ts.run_tests()
        elif cmd == 'demo':      cmd_demo()
        else: print(f'  Unknown command: {cmd}\n'); print(__doc__)
    except Exception as e:
        import traceback; print(f'\n  Error: {e}'); traceback.print_exc()

if __name__ == '__main__':
    main()
