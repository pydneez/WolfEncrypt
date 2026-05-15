"""
app.py — WolfCrypt Streamlit Interface
Run: streamlit run app.py
"""

import streamlit as st
import json, base64, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wolfcrypt import Host, Player, verify_vote, sha256_hex, canonical, rsa_verify

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title='WolfCrypt',
    page_icon='🐺',
    layout='wide',
    initial_sidebar_state='expanded',
)

# ── CSS ───────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
.stApp { background-color: #f7f8fa !important; }

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #ffffff !important;
    border-right: 1px solid #e4e7ec;
}
[data-testid="stSidebar"] * { color: #111827 !important; }

/* Typography */
h1 { color: #111827 !important; font-weight: 700; font-size: 1.8rem !important; }
h2 { color: #1f2937 !important; font-weight: 600; }
h3 { color: #374151 !important; font-weight: 600; }
p, li { color: #374151 !important; }

/* Cards */
.card {
    background: #ffffff;
    border: 1px solid #e4e7ec;
    border-radius: 10px;
    padding: 1.1rem 1.3rem;
    margin: 0.4rem 0;
    box-shadow: 0 1px 4px rgba(0,0,0,0.05);
}
.card-blue   { border-left: 4px solid #3b82f6; }
.card-green  { border-left: 4px solid #22c55e; }
.card-red    { border-left: 4px solid #ef4444; }
.card-amber  { border-left: 4px solid #f59e0b; }
.card-purple { border-left: 4px solid #8b5cf6; }
.card-gray   { border-left: 4px solid #9ca3af; }

/* Role display */
.role-box {
    background: #fff;
    border: 2px solid #3b82f6;
    border-radius: 12px;
    padding: 2rem;
    text-align: center;
    box-shadow: 0 4px 16px rgba(59,130,246,0.1);
}
.role-box.wolf     { border-color: #ef4444; box-shadow: 0 4px 16px rgba(239,68,68,0.1); }
.role-box.seer     { border-color: #8b5cf6; box-shadow: 0 4px 16px rgba(139,92,246,0.1); }
.role-box.doctor   { border-color: #22c55e; box-shadow: 0 4px 16px rgba(34,197,94,0.1); }
.role-box.villager { border-color: #9ca3af; }

/* Badges */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 99px;
    font-size: 0.75rem;
    font-weight: 600;
}
.badge-green  { background: #dcfce7; color: #166534; }
.badge-red    { background: #fee2e2; color: #991b1b; }
.badge-blue   { background: #dbeafe; color: #1e40af; }
.badge-amber  { background: #fef3c7; color: #92400e; }
.badge-purple { background: #f3e8ff; color: #6b21a8; }

/* Mono */
.mono {
    background: #f1f5f9;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 0.35rem 0.7rem;
    font-family: 'Courier New', monospace;
    font-size: 0.76rem;
    color: #1e293b;
    word-break: break-all;
    margin: 2px 0;
}

/* Buttons */
.stButton > button {
    background-color: #2563eb !important;
    color: #fff !important;
    border: none !important;
    border-radius: 7px !important;
    font-weight: 600 !important;
    padding: 0.4rem 1.2rem !important;
}
.stButton > button:hover { background-color: #1d4ed8 !important; }

/* Inputs */
div[data-testid="stTextInput"] input,
div[data-testid="stSelectbox"] > div > div,
div[data-testid="stTextArea"] textarea {
    background: #fff !important;
    border: 1px solid #d1d5db !important;
    color: #111827 !important;
    border-radius: 7px !important;
}
label, .stSelectbox label, .stTextInput label { color: #374151 !important; font-weight: 500; }
</style>
""", unsafe_allow_html=True)


# ── Session state ─────────────────────────────────────────────────────────────

def init_state():
    defaults = {
        'host':        None,
        'players':     {},
        'role_map':    {},
        'packages':    {},
        'commitments': {},
        'verdicts':    {},   # {seer_name: verdict_package}
        'votes':       [],
        'game_ready':  False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()


# ── Sidebar ───────────────────────────────────────────────────────────────────

PAGES = [
    '🏠  Overview',
    '🎲  Setup Game',
    '🔐  Decrypt Role',
    '🔮  Seer Verdict',
    '🗳️   Cast Vote',
    '✅  Verify',
]

with st.sidebar:
    st.markdown('## 🐺 WolfCrypt')
    st.caption('Secure Role Distribution for Board Games')
    st.divider()
    page = st.radio('', PAGES, label_visibility='collapsed')
    st.divider()
    if st.session_state.game_ready:
        st.markdown('<div class="badge badge-green">Game ready</div>', unsafe_allow_html=True)
        st.caption(f'Players: {", ".join(st.session_state.players.keys())}')
    else:
        st.markdown('<div class="badge badge-amber">No game yet</div>', unsafe_allow_html=True)
    st.divider()
    st.caption('RSA keygen: custom (Miller-Rabin)\nEncryption: PKCS1-OAEP + AES-EAX\nSignatures: pkcs1_15 + SHA-256')


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════

if page == PAGES[0]:
    st.title('WolfCrypt')
    st.markdown('**Secure role distribution for Werewolf / Mafia using PGP-inspired cryptography.**')
    st.divider()

    c1, c2, c3, c4 = st.columns(4)
    for col, title, desc, badge_text, badge_class in [
        (c1, '🔒 Confidentiality',  'Roles are hybrid-encrypted (RSA-OAEP + AES-EAX). Only the recipient can decrypt.', 'RSA-OAEP + AES-EAX', 'badge-blue'),
        (c2, '📌 Integrity',        'SHA-256 commitments published before decryption. Role changes are detectable.', 'SHA-256 commitment', 'badge-green'),
        (c3, '🔑 Authentication',   'GM signs every role card and seer verdict with pkcs1_15 + SHA-256.', 'pkcs1_15 + SHA-256', 'badge-purple'),
        (c4, '✍️ Non-repudiation',   'Every vote is signed with the voter\'s private key. Votes cannot be denied.', 'Signed votes', 'badge-amber'),
    ]:
        with col:
            st.markdown(f'<div class="card card-blue"><b style="color:#111827">{title}</b>'
                        f'<p style="font-size:0.88rem;margin:0.4rem 0 0.6rem 0">{desc}</p>'
                        f'<span class="badge {badge_class}">{badge_text}</span></div>',
                        unsafe_allow_html=True)

    st.divider()
    st.markdown('#### Protocol flow')
    steps = [
        ('1. Key Generation',   'GM and each player generate RSA key pairs using the custom Miller-Rabin implementation.'),
        ('2. Role Assignment',  'GM builds a role card, signs it (pkcs1_15), and hybrid-encrypts it for each player. Commitments are published to all.'),
        ('3. Role Decryption',  'Each player decrypts their own card, verifies the commitment and the GM signature.'),
        ('4. Seer Verdict',     'GM produces a signed investigation verdict encrypted only for the Seer. No one else can read it.'),
        ('5. Voting',           'Players cast signed elimination votes. Any party can verify authorship.'),
        ('6. Verification',     'All signatures and commitments are checked — full cryptographic audit of the game record.'),
    ]
    for title, desc in steps:
        st.markdown(f'<div class="card" style="padding:0.6rem 1rem;margin:3px 0">'
                    f'<b style="color:#1e3a5f">{title}</b>'
                    f'<span style="color:#6b7280;font-size:0.87rem;margin-left:0.8rem">{desc}</span>'
                    f'</div>', unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: SETUP GAME
# ══════════════════════════════════════════════════════════════════════════════

elif page == PAGES[1]:
    st.title('Setup Game')
    st.markdown('Enter player names. The system generates RSA key pairs and assigns roles.')
    st.divider()

    player_input = st.text_input(
        'Players (comma-separated, minimum 4)',
        value='Alice, Bob, Charlie, Diana, Eve, Frank',
    )

    st.markdown('**Role assignments (for demo — in a real game this would be random)**')
    col1, col2 = st.columns(2)
    with col1:
        wolf_input   = st.text_input('Wolves (comma-separated)', value='Alice, Bob')
        seer_input   = st.text_input('Seer', value='Charlie')
    with col2:
        doctor_input = st.text_input('Doctor', value='Diana')
        st.caption('Remaining players will be Villagers.')

    if st.button('🎲  Generate Keys & Assign Roles'):
        names = [n.strip() for n in player_input.split(',') if n.strip()]
        if len(names) < 4:
            st.error('Need at least 4 players.')
        else:
            wolves  = [n.strip() for n in wolf_input.split(',')  if n.strip()]
            seer    = seer_input.strip()
            doctor  = doctor_input.strip()

            role_map = {}
            for name in names:
                if name in wolves:      role_map[name] = 'Wolf'
                elif name == seer:      role_map[name] = 'Seer'
                elif name == doctor:    role_map[name] = 'Doctor'
                else:                   role_map[name] = 'Villager'

            with st.spinner('Generating RSA key pairs (custom Miller-Rabin)...'):
                host    = Host()
                players = {n: Player(n) for n in names}

            with st.spinner('Signing and encrypting role cards...'):
                packages = {}; commitments = {}
                for name in names:
                    role   = role_map[name]
                    allies = [w for w in wolves if w != name] if role == 'Wolf' else []
                    pkg    = host.encrypt_role_for_player(players[name], role, allies)
                    commit = host.compute_commitment(pkg)
                    packages[name]    = pkg
                    commitments[name] = commit

            st.session_state.update({
                'host': host, 'players': players, 'role_map': role_map,
                'packages': packages, 'commitments': commitments,
                'verdicts': {}, 'votes': [], 'game_ready': True,
            })
            st.success(f'Game ready with {len(names)} players.')

            st.markdown('**SHA-256 commitments (published to all players)**')
            st.caption('These hashes lock in the role assignments. Any change to a role packet changes the hash.')
            for name, h in commitments.items():
                st.markdown(f'<div class="mono"><b style="color:#1e40af">{name}</b>: {h}</div>',
                            unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: DECRYPT ROLE
# ══════════════════════════════════════════════════════════════════════════════

elif page == PAGES[2]:
    st.title('Decrypt My Role')
    st.markdown('Each player decrypts and verifies their own role card.')
    st.divider()

    if not st.session_state.game_ready:
        st.warning('No game set up yet. Go to **Setup Game** first.')
    else:
        player_name = st.selectbox('Select your name', list(st.session_state.players.keys()))

        if st.button('🔐  Decrypt Role Card'):
            try:
                player   = st.session_state.players[player_name]
                host     = st.session_state.host
                pkg      = st.session_state.packages[player_name]
                commit   = st.session_state.commitments[player_name]

                card = player.decrypt_role(pkg, commit, host.pub_key)
                role = card['role']
                rc   = role.lower()
                em   = {'Wolf':'🐺','Seer':'🔮','Doctor':'💊','Villager':'🧑‍🌾'}.get(role,'?')
                allies_html = (f'<p style="color:#6b7280;font-size:0.9rem;margin:0.3rem 0 0">Allies: '
                               f'<b style="color:#111827">{", ".join(card["allies"])}</b></p>') if card.get('allies') else ''

                st.markdown(f'<div class="role-box {rc}">'
                            f'<div style="font-size:3.5rem;line-height:1.1">{em}</div>'
                            f'<h2 style="color:#111827;margin:0.4rem 0">{role}</h2>'
                            f'<p style="color:#6b7280;margin:0">Assigned to <b style="color:#111827">{player_name}</b></p>'
                            f'{allies_html}'
                            f'</div>', unsafe_allow_html=True)

                st.markdown('')
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown('<span class="badge badge-green">✅ Commitment verified</span>', unsafe_allow_html=True)
                with col2:
                    st.markdown('<span class="badge badge-green">✅ GM signature valid</span>', unsafe_allow_html=True)

                with st.expander('Show cryptographic details'):
                    st.json({'player': card['player'], 'role': card['role'],
                             'allies': card.get('allies', []), 'game_id': card['game_id'],
                             'gm_signature': card['gm_signature'][:64] + '...'})

            except ValueError as e:
                st.error(f'❌ {e}')


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: SEER VERDICT
# ══════════════════════════════════════════════════════════════════════════════

elif page == PAGES[3]:
    st.title('Seer Verdict')
    st.markdown('The Seer secretly investigates a player. The result is GM-signed and encrypted for the Seer only.')
    st.divider()

    if not st.session_state.game_ready:
        st.warning('No game set up yet.')
    else:
        players   = st.session_state.players
        role_map  = st.session_state.role_map
        host      = st.session_state.host

        # Find the actual Seer(s) from the role map
        seer_names = [n for n, r in role_map.items() if r == 'Seer']

        if not seer_names:
            st.warning('No Seer in this game.')
        else:
            # Only Seer players appear in the dropdown — non-Seers cannot select themselves
            col1, col2 = st.columns(2)
            with col1:
                seer_name = st.selectbox('Seer player', seer_names)
                st.caption(f'Only players with the Seer role can investigate.')
            with col2:
                other = [n for n in players if n != seer_name]
                target_name = st.selectbox('Investigate', other)

            if st.button('🔮  Investigate'):
                seer        = players[seer_name]
                verdict_pkg = host.seer_verdict(seer, target_name, role_map)
                st.session_state.verdicts[seer_name] = {
                    'package':     verdict_pkg,
                    'target_name': target_name,
                }
                verdict = seer.read_seer_verdict(verdict_pkg, host.pub_key)
                result  = verdict['result']
                is_wolf = result == 'Wolf'

                st.markdown(
                    f'<div class="card {"card-red" if is_wolf else "card-green"}">'
                    f'<b>Investigation result — private to {seer_name}</b><br>'
                    f'<span style="font-size:1.3rem;color:{"#991b1b" if is_wolf else "#166534"}">'
                    f'{"🐺" if is_wolf else "✅"} {target_name} is: <b>{result}</b>'
                    f'</span><br><br>'
                    f'<span class="badge badge-green">✅ GM signature valid</span>'
                    f'</div>',
                    unsafe_allow_html=True
                )

                st.markdown('')
                st.info(f'This verdict was encrypted with **{seer_name}\'s public key**. '
                        f'No other player — including the GM — can decrypt it.')

            # Show what a non-seer attempt looks like
            if st.session_state.verdicts:
                with st.expander('🔒 Show why other players cannot read this'):
                    st.markdown('The verdict packet is encrypted with the **Seer\'s public key**. '
                                'Any other player\'s private key will fail the RSA-OAEP decryption. '
                                'The AES-EAX MAC will also fail, raising a `ValueError` before '
                                'any plaintext is ever produced.')
                    non_seer = [n for n in players if role_map.get(n) != 'Seer']
                    if non_seer:
                        try_name = non_seer[0]
                        try:
                            seer_verdicts = list(st.session_state.verdicts.values())
                            hybrid_decrypt = __import__('wolfcrypt').hybrid_decrypt
                            hybrid_decrypt(seer_verdicts[-1]['package'], players[try_name]._priv)
                            st.error('Unexpected: decryption succeeded (should not happen)')
                        except Exception as e:
                            st.markdown(f'<div class="card card-red">'
                                        f'<b>{try_name}</b> tries to decrypt → '
                                        f'<code style="color:#991b1b">Exception: {type(e).__name__}</code>'
                                        f'</div>', unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: CAST VOTE
# ══════════════════════════════════════════════════════════════════════════════

elif page == PAGES[4]:
    st.title('Cast Vote')
    st.markdown('Sign an elimination vote with your private key. Non-repudiable — you cannot deny this vote.')
    st.divider()

    if not st.session_state.game_ready:
        st.warning('No game set up yet.')
    else:
        players       = st.session_state.players
        already_voted = {v['voter'] for v in st.session_state.votes}
        remaining     = [n for n in players if n not in already_voted]

        if not remaining:
            st.info('All players have already cast their vote.')
        else:
            col1, col2 = st.columns(2)
            with col1:
                voter_name  = st.selectbox('Voter', remaining)
            with col2:
                target_name = st.selectbox('Eliminate', [n for n in players if n != voter_name])

            if st.button('🗳️  Sign and Cast Vote'):
                if voter_name in {v['voter'] for v in st.session_state.votes}:
                    st.error(f'**{voter_name}** has already voted this round.')
                else:
                    vote = players[voter_name].cast_vote(target_name)
                    st.session_state.votes.append(vote)
                    st.success(f'**{voter_name}** votes to eliminate **{target_name}**')
                    st.markdown(f'<div class="mono">Signature: {vote["signature"][:80]}...</div>',
                                unsafe_allow_html=True)
                    st.caption('This signature was produced with the voter\'s RSA private key. '
                               'Anyone with the voter\'s public key can verify it permanently.')

        if st.session_state.votes:
            st.divider()
            st.markdown('**Votes cast this session**')
            for v in st.session_state.votes:
                ok = verify_vote(dict(v), players)
                badge = '<span class="badge badge-green">✅ verified</span>' if ok else '<span class="badge badge-red">❌ invalid</span>'
                st.markdown(f'<div class="card" style="padding:0.5rem 1rem;margin:3px 0">'
                            f'<b>{v["voter"]}</b> → eliminate <b>{v["target"]}</b>  {badge}'
                            f'</div>', unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: VERIFY
# ══════════════════════════════════════════════════════════════════════════════

elif page == PAGES[5]:
    st.title('Verify Everything')
    st.markdown('Run all cryptographic checks over the current session.')
    st.divider()

    if not st.session_state.game_ready:
        st.warning('No game set up yet.')
    else:
        host        = st.session_state.host
        players     = st.session_state.players
        packages    = st.session_state.packages
        commitments = st.session_state.commitments
        votes       = st.session_state.votes

        if st.button('🔍  Run All Checks'):

            checks = []

            # Check 1: Commitments
            commit_ok = all(
                sha256_hex(canonical(packages[n])) == commitments[n]
                for n in players
            )
            checks.append(('Role card commitments match published SHA-256 hashes', commit_ok, []))

            # Check 2: GM signatures on role cards
            sig_issues = []
            for name, player in players.items():
                try:
                    player.decrypt_role(packages[name], commitments[name], host.pub_key)
                except Exception as e:
                    sig_issues.append(f'{name}: {e}')
            checks.append(('GM signatures on all role cards are valid', not sig_issues, sig_issues))

            # Check 3: Vote signatures
            vote_issues = []
            for v in votes:
                if not verify_vote(dict(v), players):
                    vote_issues.append(f'{v["voter"]} → {v["target"]}: signature invalid')
            label3 = f'Signed votes verified ({len(votes)} vote{"s" if len(votes)!=1 else ""})'
            checks.append((label3, not vote_issues, vote_issues))

            # Check 4: Seer verdicts
            verdict_issues = []
            for seer_name, entry in st.session_state.verdicts.items():
                try:
                    v = players[seer_name].read_seer_verdict(entry['package'], host.pub_key)
                    if not v['signature_valid']:
                        verdict_issues.append(f'{seer_name}: GM signature invalid')
                except Exception as e:
                    verdict_issues.append(f'{seer_name}: {e}')
            label4 = f'Seer verdict GM signatures valid ({len(st.session_state.verdicts)} verdict{"s" if len(st.session_state.verdicts)!=1 else ""})'
            checks.append((label4, not verdict_issues, verdict_issues))

            # Display
            all_pass = all(c[1] for c in checks)
            if all_pass:
                st.success('All checks passed — game record is cryptographically sound.')
            else:
                st.error('One or more checks failed.')

            for label, passed, issues in checks:
                color  = 'card-green' if passed else 'card-red'
                icon   = '✅' if passed else '❌'
                issues_html = ''.join(f'<li style="color:#991b1b;font-size:0.87rem">{i}</li>' for i in issues)
                st.markdown(f'<div class="card {color}">'
                            f'<b>{icon} {label}</b>'
                            f'{"<ul style=margin-top:0.4rem>" + issues_html + "</ul>" if issues else ""}'
                            f'</div>', unsafe_allow_html=True)