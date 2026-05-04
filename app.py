import streamlit as st
import pandas as pd
import textwrap
import secrets as secrets_mod
import hashlib

def _html(markup: str) -> None:
    clean = textwrap.dedent(markup)
    if hasattr(st, "html"):
        st.html(clean)
    else:
        st.markdown(clean, unsafe_allow_html=True)

from crypto_algorithms import (
    Caesar, Affine, SimpleSubstitution, Vigenere, OTP, Playfair, Hill,
    RC4, AES,
    RSA, ElGamal, DiffieHellman,
    HashFunctions, DSA,
    ShamirSecretSharing, Paillier,
    Schnorr, FeigeFiatShamir,
    gcd,
)

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CryptoLab — Cryptography Studio",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# DESIGN SYSTEM
# ─────────────────────────────────────────────────────────────────────────────
_html("""
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
    <style>
      :root {
        --bg: #07080F;
        --bg-2: #0E1120;
        --panel: rgba(20, 24, 42, 0.55);
        --panel-2: rgba(28, 32, 56, 0.6);
        --border: rgba(255,255,255,0.07);
        --border-strong: rgba(255,255,255,0.14);
        --text: #ECEFF7;
        --text-dim: #9CA3B8;
        --text-faint: #6B7390;
        --accent: #8B5CF6;
        --accent-2: #06B6D4;
        --accent-3: #F472B6;
        --success: #34D399;
        --danger: #F87171;
      }
      html, body, [class*="css"], .stApp, .stMarkdown, .stText, .stTextInput, .stTextArea {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
      }
      code, pre, .stCodeBlock, .stCode {
        font-family: 'JetBrains Mono', ui-monospace, monospace !important;
      }
      .stApp {
        background:
          radial-gradient(900px 500px at 8% -10%, rgba(139,92,246,0.22), transparent 55%),
          radial-gradient(800px 500px at 110% 5%, rgba(6,182,212,0.16), transparent 55%),
          radial-gradient(700px 500px at 50% 110%, rgba(244,114,182,0.10), transparent 55%),
          var(--bg);
        background-attachment: fixed;
      }
      #MainMenu, footer { visibility: hidden; height: 0; }
      header[data-testid="stHeader"] {
        background: transparent !important;
        height: 2.5rem !important;
      }
      header[data-testid="stHeader"] button[kind="header"],
      header[data-testid="stHeader"] [data-testid="stBaseButton-headerNoPadding"] {
        color: #ECEFF7 !important;
      }
      .block-container { padding-top: 0.6rem !important; padding-bottom: 4rem !important; max-width: 1240px !important; }
      .hero {
        position: relative;
        padding: 30px 36px 28px 36px;
        border-radius: 22px;
        background: linear-gradient(135deg, rgba(139,92,246,0.18), rgba(6,182,212,0.12) 60%, rgba(244,114,182,0.10));
        border: 1px solid var(--border-strong);
        margin-bottom: 22px;
        overflow: hidden;
        box-shadow: 0 30px 80px -30px rgba(139,92,246,0.35), 0 1px 0 rgba(255,255,255,0.04) inset;
      }
      .hero::before {
        content: "";
        position: absolute; inset: -1px;
        background: radial-gradient(600px 200px at 100% 0%, rgba(255,255,255,0.06), transparent 60%);
        pointer-events: none;
      }
      .hero .eyebrow {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 11.5px; font-weight: 600; letter-spacing: 0.18em;
        text-transform: uppercase; color: #B4A4FF;
        display: flex; align-items: center; gap: 10px;
      }
      .hero .eyebrow .dot {
        width: 7px; height: 7px; border-radius: 50%;
        background: #8B5CF6; box-shadow: 0 0 0 4px rgba(139,92,246,0.18);
        animation: pulse 2s ease-in-out infinite;
      }
      @keyframes pulse {
        0%,100% { box-shadow: 0 0 0 4px rgba(139,92,246,0.18); }
        50%     { box-shadow: 0 0 0 8px rgba(139,92,246,0.05); }
      }
      .hero h1 {
        margin: 8px 0 6px 0;
        font-family: 'Space Grotesk', sans-serif;
        font-size: 38px; font-weight: 700; letter-spacing: -0.025em;
        line-height: 1.05;
        background: linear-gradient(180deg, #FFFFFF 30%, #B6BCD2 100%);
        -webkit-background-clip: text; background-clip: text;
        -webkit-text-fill-color: transparent;
      }
      .hero p.tagline { margin: 4px 0 14px 0; color: var(--text-dim); font-size: 15px; max-width: 720px; }
      .hero .badge-row { display: flex; gap: 8px; flex-wrap: wrap; }
      .badge {
        font-size: 11px; font-weight: 500; padding: 5px 11px; border-radius: 999px;
        background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.08);
        color: #C8CFE2; backdrop-filter: blur(10px);
      }
      .badge.accent { background: rgba(139,92,246,0.14); border-color: rgba(139,92,246,0.35); color: #D8CDFF; }
      .badge.cyan   { background: rgba(6,182,212,0.12);  border-color: rgba(6,182,212,0.32);  color: #B6EAF6; }
      .howto {
        position: relative; padding: 16px 18px 16px 46px; border-radius: 14px;
        background: linear-gradient(180deg, rgba(6,182,212,0.07), rgba(6,182,212,0.02));
        border: 1px solid rgba(6,182,212,0.22); margin: 6px 0 22px 0;
        font-size: 14px; color: #D6DEEC;
      }
      .howto::before { content: "📘"; position: absolute; left: 14px; top: 14px; font-size: 18px; }
      .howto .title {
        font-family: 'Space Grotesk', sans-serif; font-weight: 600; color: #FFFFFF;
        font-size: 13.5px; text-transform: uppercase; letter-spacing: 0.12em; margin-bottom: 6px;
      }
      .howto ol { margin: 0 0 0 18px; padding: 0; }
      .howto li { margin: 3px 0; line-height: 1.55; }
      .howto b { color: #FFFFFF; }
      /* Theory box */
      .theory-box {
        padding: 14px 18px 14px 46px; border-radius: 14px; position: relative;
        background: linear-gradient(180deg, rgba(139,92,246,0.08), rgba(139,92,246,0.02));
        border: 1px solid rgba(139,92,246,0.22); margin: 0 0 18px 0;
        font-size: 13.5px; color: #D6DEEC; line-height: 1.7;
      }
      .theory-box::before { content: "📐"; position: absolute; left: 14px; top: 14px; font-size: 18px; }
      .theory-box .title {
        font-family: 'Space Grotesk', sans-serif; font-weight: 600; color: #FFFFFF;
        font-size: 12px; text-transform: uppercase; letter-spacing: 0.12em; margin-bottom: 6px;
      }
      /* Answer box — green highlight for "expected by teacher" answers */
      .answer-box {
        padding: 14px 18px 14px 46px; border-radius: 14px; position: relative;
        background: linear-gradient(180deg, rgba(52,211,153,0.10), rgba(52,211,153,0.02));
        border: 1px solid rgba(52,211,153,0.30); margin: 16px 0 0 0;
        font-size: 13.5px; color: #D6DEEC; line-height: 1.7;
      }
      .answer-box::before { content: "✅"; position: absolute; left: 14px; top: 14px; font-size: 18px; }
      .answer-box .title {
        font-family: 'Space Grotesk', sans-serif; font-weight: 600; color: #34D399;
        font-size: 12px; text-transform: uppercase; letter-spacing: 0.12em; margin-bottom: 6px;
      }
      .section {
        font-family: 'Space Grotesk', sans-serif; font-size: 12px; font-weight: 600;
        letter-spacing: 0.14em; text-transform: uppercase; color: var(--text-faint);
        margin: 22px 0 8px 0; display: flex; align-items: center; gap: 10px;
      }
      .section::after { content: ""; flex: 1; height: 1px; background: linear-gradient(90deg, var(--border-strong), transparent); }
      .result-label { font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.14em; color: var(--text-faint); margin: 14px 0 4px 0; font-weight: 600; }
      section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #050610 0%, #0A0C18 100%);
        border-right: 1px solid var(--border);
      }
      section[data-testid="stSidebar"] > div { padding-top: 8px; }
      .brand { padding: 10px 4px 18px 4px; border-bottom: 1px solid var(--border); margin-bottom: 14px; }
      .brand .logo { display: flex; align-items: center; gap: 12px; }
      .brand .logo .mark {
        width: 38px; height: 38px; border-radius: 11px; display: grid; place-items: center;
        font-size: 19px; background: linear-gradient(135deg, #8B5CF6, #06B6D4);
        box-shadow: 0 8px 24px -8px rgba(139,92,246,0.6);
      }
      .brand h2 { margin: 0; font-family: 'Space Grotesk', sans-serif; font-size: 19px; font-weight: 700; letter-spacing: -0.01em; }
      .brand .sub { margin: 2px 0 0 0; font-size: 11.5px; color: var(--text-faint); letter-spacing: 0.04em; }
      .cat-label {
        font-family: 'Space Grotesk', sans-serif; font-size: 15px; font-weight: 700;
        letter-spacing: -0.005em; color: #FFFFFF; padding: 22px 8px 10px 8px; margin-top: 6px;
        display: flex; align-items: center; gap: 10px; border-top: 1px solid var(--border); position: relative;
      }
      .cat-label::after { content: ""; position: absolute; left: 8px; bottom: 4px; width: 22px; height: 2px; border-radius: 2px; background: linear-gradient(90deg, #8B5CF6, #06B6D4); }
      .cat-label .ic { font-size: 18px; width: 30px; height: 30px; display: grid; place-items: center; background: linear-gradient(135deg, rgba(139,92,246,0.20), rgba(6,182,212,0.14)); border: 1px solid rgba(139,92,246,0.30); border-radius: 9px; }
      section[data-testid="stSidebar"] .stButton > button {
        width: 100%; border-radius: 10px; border: 1px solid transparent; background: transparent;
        color: var(--text-dim); font-weight: 500; font-size: 13.5px; padding: 8px 12px;
        text-align: left; justify-content: flex-start !important; transition: all .15s ease;
      }
      section[data-testid="stSidebar"] .stButton > button:hover { background: rgba(139,92,246,0.10); color: #FFFFFF; border-color: rgba(139,92,246,0.25); }
      section[data-testid="stSidebar"] .stButton > button p { font-weight: 500 !important; }
      section[data-testid="stSidebar"] .nav-active .stButton > button {
        background: linear-gradient(90deg, rgba(139,92,246,0.22), rgba(139,92,246,0.04));
        color: #FFFFFF; border-color: rgba(139,92,246,0.38);
        box-shadow: 0 0 0 1px rgba(139,92,246,0.18) inset;
      }
      .main .stButton > button, div[data-testid="stHorizontalBlock"] .stButton > button {
        border-radius: 11px; border: 1px solid var(--border-strong);
        background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.01));
        color: #E6EAF5; font-weight: 500; padding: 9px 16px; transition: all .18s ease;
      }
      .main .stButton > button:hover, div[data-testid="stHorizontalBlock"] .stButton > button:hover {
        border-color: rgba(139,92,246,0.55);
        background: linear-gradient(180deg, rgba(139,92,246,0.18), rgba(139,92,246,0.04));
        color: #FFFFFF; transform: translateY(-1px);
        box-shadow: 0 8px 22px -10px rgba(139,92,246,0.6);
      }
      .stButton > button:focus { box-shadow: none !important; outline: none !important; }
      .stButton > button:active { transform: translateY(0); }
      .stTextInput > div > div, .stTextArea > div > div, .stNumberInput > div > div,
      .stSelectbox > div > div, .stMultiSelect > div > div {
        background: rgba(20, 24, 42, 0.6) !important; border: 1px solid var(--border) !important; border-radius: 11px !important;
      }
      .stTextInput input, .stTextArea textarea, .stNumberInput input { color: #ECEFF7 !important; }
      .stTextArea textarea { font-family: 'JetBrains Mono', monospace !important; font-size: 13.5px !important; }
      .stTextInput > label, .stTextArea > label, .stNumberInput > label,
      .stSelectbox > label, .stSlider > label, .stMultiSelect > label {
        font-size: 12px !important; font-weight: 600 !important; text-transform: uppercase;
        letter-spacing: 0.08em; color: var(--text-faint) !important;
      }
      .stCodeBlock, pre { border-radius: 12px !important; border: 1px solid var(--border) !important; background: rgba(8, 10, 22, 0.7) !important; }
      .stCodeBlock code { font-size: 13.5px !important; }
      .stTabs [data-baseweb="tab-list"] { gap: 6px; background: transparent; border-bottom: 1px solid var(--border); margin-bottom: 14px; }
      .stTabs [data-baseweb="tab"] { background: transparent; border-radius: 10px 10px 0 0; padding: 10px 18px; color: var(--text-dim); font-weight: 500; }
      .stTabs [aria-selected="true"] { background: rgba(139,92,246,0.10) !important; color: #FFFFFF !important; border-bottom: 2px solid #8B5CF6 !important; }
      div[data-testid="stAlert"] { border-radius: 12px !important; border: 1px solid var(--border-strong) !important; backdrop-filter: blur(10px); }
      div[data-testid="stMetric"] { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 16px 18px; backdrop-filter: blur(10px); }
      div[data-testid="stMetricLabel"] { color: var(--text-faint) !important; font-size: 11.5px !important; text-transform: uppercase; letter-spacing: 0.1em; }
      div[data-testid="stMetricValue"] { font-family: 'JetBrains Mono', monospace !important; font-size: 18px !important; }
      .streamlit-expanderHeader, [data-testid="stExpander"] summary { background: var(--panel) !important; border-radius: 11px !important; border: 1px solid var(--border) !important; font-weight: 500 !important; }
      .stSlider [data-baseweb="slider"] > div > div { background: linear-gradient(90deg, #8B5CF6, #06B6D4) !important; }
      .stDataFrame { border-radius: 12px; overflow: hidden; border: 1px solid var(--border); }
      .step-row { display: flex; gap: 8px; margin: 10px 0 18px 0; flex-wrap: wrap; }
      .step-chip { display: flex; align-items: center; gap: 8px; padding: 7px 13px; border-radius: 999px; background: rgba(255,255,255,0.03); border: 1px solid var(--border); font-size: 12.5px; color: var(--text-dim); }
      .step-chip .num { width: 20px; height: 20px; border-radius: 50%; background: rgba(255,255,255,0.06); color: var(--text-dim); display: grid; place-items: center; font-size: 11px; font-weight: 700; }
      .step-chip.done { color: #FFFFFF; border-color: rgba(52,211,153,0.4); background: rgba(52,211,153,0.10); }
      .step-chip.done .num { background: #34D399; color: #062117; }
      .step-chip.current { color: #FFFFFF; border-color: rgba(139,92,246,0.5); background: rgba(139,92,246,0.15); box-shadow: 0 0 0 3px rgba(139,92,246,0.10); }
      .step-chip.current .num { background: #8B5CF6; color: #FFFFFF; }
      .party { padding: 16px 18px; border-radius: 14px; background: var(--panel); border: 1px solid var(--border); backdrop-filter: blur(10px); }
      .party h4 { margin: 0 0 8px 0; font-size: 14px; font-family: 'Space Grotesk', sans-serif; display: flex; align-items: center; gap: 8px; }
      .party .role { font-size: 10.5px; color: var(--text-faint); text-transform: uppercase; letter-spacing: 0.12em; }
    </style>
    """)

# ─────────────────────────────────────────────────────────────────────────────
# NAVIGATION DATA
# ─────────────────────────────────────────────────────────────────────────────
PAGES = {
    "Classical Ciphers": {
        "icon": "📜",
        "items": [
            ("Caesar",              "🏛️", "Shift cipher · TP1 Ex1.1"),
            ("Affine",              "📐", "Linear transformation"),
            ("Simple Substitution", "🔤", "Permutation key"),
            ("Vigenere",            "🗝️", "Polyalphabetic · TP1 Ex1.2"),
            ("One-Time Pad",        "📨", "Information-theoretic · TP1 Ex1.4"),
            ("Playfair",            "🎴", "5×5 digram cipher"),
            ("Hill",                "🧮", "Matrix-based cipher · TP1 Ex1.3"),
        ],
    },
    "Modern Symmetric": {
        "icon": "🛡️",
        "items": [
            ("AES",  "🔒", "Advanced Encryption Standard · TP2 Ex2.3"),
            ("RC4",  "🌊", "Stream cipher · TP2 Ex2.1"),
        ],
    },
    "Asymmetric": {
        "icon": "🔑",
        "items": [
            ("RSA",            "🔐", "Rivest–Shamir–Adleman · TP3 Ex3.2"),
            ("ElGamal",        "🧠", "Discrete logarithm · TP3 Ex3.3"),
            ("Diffie-Hellman", "🤝", "Key exchange · TP3 Ex3.1"),
        ],
    },
    "Hash Functions": {
        "icon": "🧬",
        "items": [
            ("Hash Functions", "#️⃣", "MD5 / SHA-256 / SHA-512 · TP4"),
        ],
    },
    "Digital Signatures": {
        "icon": "✍️",
        "items": [
            ("DSA", "✒️", "Digital Signature Algorithm · TP5"),
        ],
    },
    "Secret Sharing": {
        "icon": "🧩",
        "items": [
            ("Shamir (k,n)", "🧩", "Threshold sharing · TP6"),
        ],
    },
    "Homomorphic Encryption": {
        "icon": "➕",
        "items": [
            ("Paillier", "➕", "Additive homomorphism · TP6 Ex6.4"),
        ],
    },
    "Identification Protocols": {
        "icon": "🪪",
        "items": [
            ("Schnorr ZKP",       "🕵️", "Zero-knowledge proof"),
            ("Feige-Fiat-Shamir", "🪪", "Quadratic residues"),
        ],
    },
}

CATEGORY_OF, SUBTITLE_OF, ICON_OF = {}, {}, {}
for cat, data in PAGES.items():
    for algo, icon, sub in data["items"]:
        CATEGORY_OF[algo] = cat
        SUBTITLE_OF[algo] = sub
        ICON_OF[algo] = icon

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
if "page" not in st.session_state:
    st.session_state["page"] = "Caesar"

with st.sidebar:
    _html("""
        <div class="brand">
          <div class="logo">
            <div class="mark">🔐</div>
            <div>
              <h2>CryptoLab</h2>
              <p class="sub">Cryptography studio · TP 1-6</p>
            </div>
          </div>
        </div>
        """)

    search = st.text_input(
        "Search", placeholder="🔍  Search algorithms…",
        label_visibility="collapsed", key="search_box",
    ).strip().lower()

    for category, data in PAGES.items():
        items = [(a, ic, s) for a, ic, s in data["items"]
                 if not search or search in a.lower() or search in s.lower()]
        if not items:
            continue
        _html(f'<div class="cat-label"><span class="ic">{data["icon"]}</span>{category}</div>')
        for algo, icon, _sub in items:
            is_active = st.session_state["page"] == algo
            wrapper_class = "nav-active" if is_active else ""
            _html(f'<div class="{wrapper_class}">')
            label = f"{icon}   {algo}"
            if st.button(label, key=f"nav_{algo}", use_container_width=True):
                st.session_state["page"] = algo
                st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)

page = st.session_state["page"]
category = CATEGORY_OF.get(page, "")
cat_icon = PAGES.get(category, {}).get("icon", "🔐")
subtitle = SUBTITLE_OF.get(page, "")

_html(f"""
    <div class="hero">
      <div class="eyebrow"><span class="dot"></span>{cat_icon}  {category}</div>
      <h1>{page}</h1>
      <p class="tagline">{subtitle}. Interactive playground — try it, break it, understand it.</p>
      <div class="badge-row">
        <span class="badge accent">Interactive</span>
        <span class="badge cyan">Step-by-step</span>
        <span class="badge">Educational</span>
      </div>
    </div>
    """)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def howto(steps):
    items = "".join(f"<li>{s}</li>" for s in steps)
    _html(f'<div class="howto"><div class="title">How to use</div><ol>{items}</ol></div>')

def theory(title, content):
    _html(f'<div class="theory-box"><div class="title">{title}</div>{content}</div>')

def answer_note(title, content):
    _html(f'<div class="answer-box"><div class="title">{title}</div>{content}</div>')

def section(title):
    _html(f'<div class="section">{title}</div>')

def result(label, value, lang=None):
    _html(f'<div class="result-label">{label}</div>')
    st.code(value, language=lang)

def step_indicator(steps, current):
    chips = ""
    for i, s in enumerate(steps, 1):
        cls = "done" if i <= current else ("current" if i == current + 1 else "")
        chips += f'<div class="step-chip {cls}"><div class="num">{i}</div>{s}</div>'
    _html(f'<div class="step-row">{chips}</div>')


# ═════════════════════════════════════════════════════════════════════════════
# PAGES
# ═════════════════════════════════════════════════════════════════════════════

# ─── CAESAR ──────────────────────────────────────────────────────────────────
if page == "Caesar":
    theory("Formula", "<b>Encrypt:</b> C = (P + k) mod 26 &nbsp;|&nbsp; <b>Decrypt:</b> P = (C − k) mod 26<br>Letters only; spaces and punctuation are preserved. k=0 means no shift (identity).")
    howto([
        "Type any plaintext or ciphertext in the text box.",
        "Pick a shift key <b>k</b> between 0 and 25.",
        "Click <b>Encrypt</b> or <b>Decrypt</b>.",
        "Use <b>Brute Force</b> to see all 26 possible decryptions — useful for cryptanalysis.",
    ])
    text = st.text_area("Text", height=120, placeholder="e.g.  HELLO WORLD")
    key = st.slider("Shift key k", 0, 25, 3)
    c1, c2, c3 = st.columns(3)
    enc_clicked = c1.button("🔒  Encrypt", use_container_width=True)
    dec_clicked = c2.button("🔓  Decrypt", use_container_width=True)
    bf_clicked  = c3.button("🔍  Brute Force (all 26)", use_container_width=True)

    if enc_clicked and text:
        r = Caesar.encrypt(text, key)
        result("Ciphertext", r)
        answer_note("What happened?", f"Each letter shifted +{key} positions. &nbsp; <code>{text[:20]}</code> → <code>{r[:20]}</code>")
    if dec_clicked and text:
        r = Caesar.decrypt(text, key)
        result("Plaintext", r)
        answer_note("What happened?", f"Each letter shifted −{key} positions (reverse of encryption).")
    if bf_clicked and text:
        section("All 26 candidate decryptions — k=0 to k=25")
        rows = [{"k": k, "Decryption": v} for k, v in Caesar.brute_force(text)]
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        answer_note("Brute-force attack", "Caesar has only 26 possible keys — trivially broken by trying all shifts and picking the one that looks like readable French/English text (use frequency analysis: IC ≈ 0.074 for French).")


# ─── AFFINE ──────────────────────────────────────────────────────────────────
elif page == "Affine":
    theory("Formula", "<b>Encrypt:</b> C = (a·P + b) mod 26 &nbsp;|&nbsp; <b>Decrypt:</b> P = a⁻¹·(C − b) mod 26<br><b>Constraint:</b> gcd(a, 26) = 1 (a must be invertible mod 26). Valid values of a: 1,3,5,7,9,11,15,17,19,21,23,25.")
    howto([
        "Choose a valid <b>a</b> from the dropdown (all shown options satisfy gcd(a,26)=1).",
        "Choose any <b>b</b> between 0 and 25.",
        "Enter text and click <b>Encrypt</b> or <b>Decrypt</b>.",
    ])
    text = st.text_area("Text", height=120, placeholder="e.g.  HELLO")
    valid_a = [a for a in range(1, 26) if gcd(a, 26) == 1]
    c1, c2 = st.columns(2)
    a = c1.selectbox("a — must be coprime with 26", valid_a, index=valid_a.index(7))
    b = c2.slider("b (shift)", 0, 25, 3)
    cc1, cc2 = st.columns(2)
    if cc1.button("🔒  Encrypt", use_container_width=True) and text:
        r = Affine.encrypt(text, a, b)
        result("Ciphertext", r)
        from math import gcd as mgcd
        answer_note("Formula applied", f"C = ({a}·P + {b}) mod 26")
    if cc2.button("🔓  Decrypt", use_container_width=True) and text:
        from crypto_algorithms import mod_inverse
        a_inv = mod_inverse(a, 26)
        r = Affine.decrypt(text, a, b)
        result("Plaintext", r)
        answer_note("Formula applied", f"P = {a_inv}·(C − {b}) mod 26 &nbsp; (a⁻¹ = {a_inv} because {a}·{a_inv} ≡ 1 mod 26)")


# ─── SIMPLE SUBSTITUTION ─────────────────────────────────────────────────────
elif page == "Simple Substitution":
    theory("How it works", "Each letter A-Z is mapped to a unique permutation of the alphabet. The key is a 26-letter string giving the substitution table. There are 26! ≈ 4×10²⁶ possible keys — brute-force is infeasible, but <b>frequency analysis</b> breaks it.")
    howto([
        "Click <b>Random Key</b> to generate a fresh permutation, or type your own 26-letter key.",
        "Enter text and click <b>Encrypt</b> or <b>Decrypt</b>.",
        "Scroll to <b>Frequency Analysis</b> to see letter distributions — the classic attack vector.",
    ])
    text = st.text_area("Text", height=120, placeholder="e.g.  THE QUICK BROWN FOX")
    if "sub_key" not in st.session_state:
        st.session_state["sub_key"] = SimpleSubstitution.make_key()
    c1, c2 = st.columns([3, 1])
    key = c1.text_input("Substitution key (26 unique letters)", value=st.session_state["sub_key"])
    if c2.button("🎲  Random Key", use_container_width=True):
        st.session_state["sub_key"] = SimpleSubstitution.make_key()
        st.rerun()
    cc1, cc2 = st.columns(2)
    if cc1.button("🔒  Encrypt", use_container_width=True) and text:
        r = SimpleSubstitution.encrypt(text, key)
        result("Ciphertext", r)
    if cc2.button("🔓  Decrypt", use_container_width=True) and text:
        r = SimpleSubstitution.decrypt(text, key)
        result("Plaintext", r)
    if text:
        section("Frequency Analysis — the attack tool")
        freq = SimpleSubstitution.frequency_analysis(text)
        if freq:
            df = pd.DataFrame(list(freq.items()), columns=["Letter", "Frequency (%)"])
            st.bar_chart(df.set_index("Letter"), height=250)
            answer_note("Why this matters", "In French, E≈15%, A≈8%, S≈8%… If ciphertext shows a high-frequency letter X, X likely maps to E. This breaks the cipher despite 26! keyspace.")


# ─── VIGENERE ────────────────────────────────────────────────────────────────
elif page == "Vigenere":
    theory("Formula", "<b>Encrypt:</b> Cᵢ = (Pᵢ + K[i mod |K|]) mod 26 &nbsp;|&nbsp; <b>Decrypt:</b> Pᵢ = (Cᵢ − K[i mod |K|]) mod 26<br>The key repeats cyclically. Security grows with key length. When |K|=|M|, it becomes a One-Time Pad.")
    howto([
        "Enter a keyword (e.g. SECRET). Longer keys are harder to break.",
        "Type plaintext and click <b>Encrypt</b>, or paste ciphertext and click <b>Decrypt</b>.",
        "Use <b>Kasiski Analysis</b> on a ciphertext to estimate key length — the first step of cryptanalysis.",
    ])
    text = st.text_area("Text", height=120, placeholder="e.g.  ATTACKATDAWN")
    key = st.text_input("Keyword", value="SECRET")
    c1, c2 = st.columns(2)
    if c1.button("🔒  Encrypt", use_container_width=True) and text and key:
        r = Vigenere.encrypt(text, key)
        result("Ciphertext", r)
        answer_note("Key length impact", f"Key '{key}' has length {len(key)}. Short keys create repeating patterns detectable by Kasiski. Try a key as long as the message for perfect secrecy.")
    if c2.button("🔓  Decrypt", use_container_width=True) and text and key:
        r = Vigenere.decrypt(text, key)
        result("Plaintext", r)
    if st.button("🔍  Kasiski Analysis", use_container_width=True):
        if text:
            results = Vigenere.kasiski(text)
            if results:
                section("Estimated key lengths (ranked by trigram spacing GCDs)")
                df = pd.DataFrame(results, columns=["Candidate length", "Supporting occurrences"])
                st.dataframe(df, hide_index=True, use_container_width=True)
                answer_note("How Kasiski works", "Repeated trigrams in the ciphertext occur at distances that are multiples of the key length. Taking GCDs of those distances reveals the most likely key length.")
            else:
                st.info("Not enough repeated sequences. Try a longer ciphertext (>100 letters).")


# ─── OTP ─────────────────────────────────────────────────────────────────────
elif page == "One-Time Pad":
    theory("True OTP (Vernam Cipher)", "Operations: <b>C = M XOR K</b> &nbsp;|&nbsp; <b>M = C XOR K</b> (XOR is self-inverse)<br>Key must be: (1) truly random, (2) at least as long as the message, (3) used exactly ONCE.<br>When all three hold, the cipher is <b>information-theoretically secure</b> (Shannon 1949).")
    howto([
        "Type a message. The key length must equal the message byte length.",
        "Click <b>Generate Key</b> to create a cryptographically random key (uses Python <code>secrets</code>).",
        "Click <b>Encrypt</b> (plaintext → bytes → XOR → hex). Click <b>Decrypt</b> to reverse.",
        "Try the <b>Key Reuse Attack</b> below to see why reusing the key is catastrophic.",
    ])

    tab1, tab2 = st.tabs(["🔒  Encrypt / Decrypt", "⚠️  Key Reuse Vulnerability"])

    with tab1:
        text = st.text_area("Message", height=100, placeholder="e.g.  Hello, World!")
        msg_bytes = text.encode() if text else b""

        if st.button("🔑  Generate New Key", use_container_width=True):
            st.session_state["otp_key"] = OTP.generate_key(max(len(msg_bytes), 1))
            st.session_state["otp_enc"] = None

        key_bytes = st.session_state.get("otp_key", b"")
        if key_bytes:
            st.caption(f"Key ({len(key_bytes)} bytes, hex): `{key_bytes.hex()[:60]}{'…' if len(key_bytes.hex()) > 60 else ''}`")

        c1, c2 = st.columns(2)
        if c1.button("🔒  Encrypt", use_container_width=True):
            if not key_bytes:
                st.warning("Generate a key first.")
            elif len(key_bytes) < len(msg_bytes):
                st.error(f"Key too short ({len(key_bytes)} bytes) for message ({len(msg_bytes)} bytes). Regenerate.")
            else:
                enc = OTP.encrypt(msg_bytes, key_bytes)
                st.session_state["otp_enc"] = enc
                result("Ciphertext (hex)", enc.hex())

        if c2.button("🔓  Decrypt", use_container_width=True):
            enc = st.session_state.get("otp_enc")
            if not enc:
                st.warning("Encrypt something first.")
            elif not key_bytes:
                st.warning("No key found.")
            else:
                dec = OTP.decrypt(enc, key_bytes)
                result("Decrypted message", dec.decode(errors='replace'))
                if dec == msg_bytes:
                    st.success("✓ Perfect recovery — D(E(M)) = M")

    with tab2:
        theory("Key Reuse Attack", "If the same key K is used for two messages M1 and M2:<br><b>C1 XOR C2 = M1 XOR M2</b><br>An attacker with both ciphertexts can XOR them to cancel the key and work on M1⊕M2 directly ('crib-dragging').")
        col1, col2 = st.columns(2)
        m1_text = col1.text_input("Message M1", value="ATTACK AT DAWN")
        m2_text = col2.text_input("Message M2", value="DEFEND AT DUSK")
        if st.button("🧪  Demonstrate Key Reuse", use_container_width=True):
            m1b = m1_text.encode()
            m2b = m2_text.encode()
            length = min(len(m1b), len(m2b))
            shared_key = OTP.generate_key(length)
            c1b = OTP.encrypt(m1b[:length], shared_key)
            c2b = OTP.encrypt(m2b[:length], shared_key)
            xor_ct = OTP.xor_ciphertexts(c1b, c2b)
            xor_pt = OTP.xor_ciphertexts(m1b[:length], m2b[:length])
            section("Results")
            cols = st.columns(3)
            with cols[0]: result("C1 (hex)", c1b.hex())
            with cols[1]: result("C2 (hex)", c2b.hex())
            with cols[2]: result("C1 XOR C2 (hex)", xor_ct.hex())
            st.success(f"C1 XOR C2 == M1 XOR M2: **{xor_ct == xor_pt}**")
            answer_note("TP question answer", "The attacker learns C1⊕C2 = M1⊕M2. With frequency analysis (crib-dragging), partial or full recovery of both messages is possible. This is why OTP keys must <b>never</b> be reused.")
        answer_note("Practical obstacles (TP1.4 question)", "1. Key distribution: the key must be as long as all messages combined, requiring a secure channel that already solves the problem. &nbsp;2. Key storage & synchronisation. &nbsp;3. True randomness generation at scale. &nbsp;4. Deletion after use.")


# ─── PLAYFAIR ────────────────────────────────────────────────────────────────
elif page == "Playfair":
    theory("5×5 Matrix Cipher", "Key fills the 5×5 grid (J treated as I). Plaintext split into digrams; each pair encrypted by row/column/rectangle rules. Historically used by British military in WWI/WWII.")
    howto([
        "Choose a keyword — it fills the 5×5 matrix.",
        "Enter letters only (spaces allowed, J→I automatically).",
        "Click <b>Encrypt</b> or <b>Decrypt</b>.",
    ])
    text = st.text_area("Text (letters only)", height=120, placeholder="e.g.  HIDE THE GOLD IN THE TREE STUMP")
    key = st.text_input("Keyword", value="MONARCHY")
    c1, c2 = st.columns(2)
    if c1.button("🔒  Encrypt", use_container_width=True) and text:
        try:
            r = Playfair.encrypt(text, key)
            result("Ciphertext", r)
        except Exception as e:
            st.error(str(e))
    if c2.button("🔓  Decrypt", use_container_width=True) and text:
        try:
            r = Playfair.decrypt(text, key)
            result("Plaintext", r)
        except Exception as e:
            st.error(str(e))


# ─── HILL ────────────────────────────────────────────────────────────────────
elif page == "Hill":
    theory("Matrix Cipher (mod 26)", "<b>Encrypt:</b> C = K · P mod 26 &nbsp; (P = column vector of letter indices, K = key matrix)<br><b>Decrypt:</b> P = K⁻¹ · C mod 26 &nbsp; (K⁻¹ exists iff gcd(det(K), 26) = 1)<br><b>Vulnerability:</b> Known-plaintext attack recovers K by solving K = C · P⁻¹ mod 26.")
    howto([
        "Enter 4 integers for the 2×2 key matrix. The app checks invertibility automatically.",
        "Type your text (letters only; padding X added if needed).",
        "Click <b>Encrypt</b> or <b>Decrypt</b>.",
    ])
    text = st.text_area("Text", height=120, placeholder="e.g.  HELP")
    section("2×2 Key Matrix  K = [[a, b], [c, d]]")
    c1, c2 = st.columns(2)
    a = c1.number_input("a", value=3, step=1)
    b = c2.number_input("b", value=3, step=1)
    c = c1.number_input("c", value=2, step=1)
    d = c2.number_input("d", value=5, step=1)
    key_matrix = [[int(a), int(b)], [int(c), int(d)]]
    det = (int(a)*int(d) - int(b)*int(c)) % 26
    st.info(f"det(K) mod 26 = **{det}**  |  gcd({det}, 26) = **{gcd(det, 26)}**  →  {'✓ Invertible' if gcd(det,26)==1 else '✗ NOT invertible — choose different values'}")
    if gcd(det, 26) == 1:
        cc1, cc2 = st.columns(2)
        if cc1.button("🔒  Encrypt", use_container_width=True) and text:
            r = Hill.encrypt(text, key_matrix)
            result("Ciphertext", r)
        if cc2.button("🔓  Decrypt", use_container_width=True) and text:
            r = Hill.decrypt(text, key_matrix)
            result("Plaintext", r)
        answer_note("Known-plaintext vulnerability (TP1.3)", "If an attacker knows ≥ n plaintext–ciphertext digram pairs for an n×n key, they can set up the linear system C = K·P mod 26 and solve for K directly. Even large matrices are vulnerable because the system remains linear.")


# ─── AES ─────────────────────────────────────────────────────────────────────
elif page == "AES":
    theory("AES — Advanced Encryption Standard", "SPN (Substitution-Permutation Network). Block size = 128 bits. Keys: 128 (10 rounds), 192 (12), 256 (14).<br>Rounds: <b>SubBytes → ShiftRows → MixColumns → AddRoundKey</b> (last round skips MixColumns).<br>Mode used here: <b>ECB</b> (each block encrypted independently — <em>not</em> recommended for patterns).")
    howto([
        "Pick a key size and click <b>Generate Key</b> for a random hex key.",
        "Type plaintext and click <b>Encrypt</b> → output is hex ciphertext.",
        "Paste the hex ciphertext in the second box and click <b>Decrypt</b> to recover the plaintext.",
        "The key must match for decryption (copy it before generating a new one).",
    ])
    key_size = st.selectbox("Key size (bits)", [128, 192, 256], index=0)
    if "aes_key" not in st.session_state:
        st.session_state["aes_key"] = AES.generate_key(128)
    c1, c2 = st.columns([3, 1])
    aes_key = c1.text_input("Key (hex)", value=st.session_state["aes_key"],
                             help="128-bit = 32 hex chars | 192-bit = 48 | 256-bit = 64")
    if c2.button("🎲  New Key", use_container_width=True):
        st.session_state["aes_key"] = AES.generate_key(key_size)
        st.rerun()

    # Validate key length
    expected_hex_len = {128: 32, 192: 48, 256: 64}[key_size]
    if len(aes_key.replace(" ", "")) != expected_hex_len:
        st.warning(f"Key must be {expected_hex_len} hex characters for AES-{key_size}. Current length: {len(aes_key)}")

    text = st.text_area("Plaintext", height=110, placeholder="Type any message to encrypt…")
    cipher_input = st.text_input("Ciphertext (hex) — for decryption", "")
    cc1, cc2 = st.columns(2)
    if cc1.button("🔒  Encrypt", use_container_width=True):
        if not text:
            st.warning("Enter plaintext first.")
        else:
            try:
                ct = AES.encrypt_ecb(text, aes_key)
                st.session_state["aes_ct"] = ct
                result("Ciphertext (hex)", ct)
                answer_note("ECB weakness note", "In ECB mode, identical 16-byte plaintext blocks produce identical ciphertext blocks. This leaks structural patterns — never use ECB for images or repetitive data.")
            except Exception as e:
                st.error(f"Encryption error: {e}")
    if cc2.button("🔓  Decrypt", use_container_width=True):
        ct_to_dec = cipher_input or st.session_state.get("aes_ct", "")
        if not ct_to_dec:
            st.warning("Paste the hex ciphertext in the box above, or encrypt something first.")
        else:
            try:
                pt = AES.decrypt_ecb(ct_to_dec, aes_key)
                result("Plaintext", pt)
            except Exception as e:
                st.error(f"Decryption error: {e}")


# ─── RC4 ─────────────────────────────────────────────────────────────────────
elif page == "RC4":
    theory("RC4 — Stream Cipher", "Two phases: <b>KSA</b> (Key Scheduling Algorithm) initialises permutation S[0..255] from the key. <b>PRGA</b> (Pseudo-Random Generation Algorithm) outputs a keystream byte-by-byte.<br>Ciphertext = Plaintext XOR Keystream. <b>Banned in TLS 1.3</b> due to statistical biases (RC4 bias: 2nd keystream byte biased toward 0).")
    howto([
        "Enter a passphrase as the symmetric key.",
        "Type plaintext and click <b>Encrypt</b> → output is hex.",
        "To decrypt: paste the hex ciphertext in the lower box and click <b>Decrypt</b>.",
    ])
    text = st.text_area("Plaintext", height=110, placeholder="e.g.  Hello RC4!")
    cipher_hex = st.text_input("Ciphertext (hex) — for decryption", "")
    key = st.text_input("Key (passphrase)", value="secretkey")
    c1, c2 = st.columns(2)
    if c1.button("🔒  Encrypt", use_container_width=True) and text:
        ct = RC4.encrypt(text, key)
        st.session_state["rc4_ct"] = ct
        result("Ciphertext (hex)", ct)
    if c2.button("🔓  Decrypt", use_container_width=True):
        ct_to_dec = cipher_hex or st.session_state.get("rc4_ct", "")
        if not ct_to_dec:
            st.warning("Paste hex ciphertext or encrypt something first.")
        else:
            try:
                pt = RC4.decrypt(ct_to_dec, key)
                result("Plaintext", pt)
            except Exception as e:
                st.error(str(e))
    answer_note("WEP Vulnerability (TP2 Ex2.1)", "WEP prepends a 3-byte IV to the key. Weak IVs (starting 0x00,0x03,…) create a correlation between keystream byte 0 and the actual key bytes. After collecting ~40,000 packets, the full WEP key can be recovered — this is the FMS/KoreK attack.")


# ─── RSA ─────────────────────────────────────────────────────────────────────
elif page == "RSA":
    theory("RSA — Rivest Shamir Adleman", "<b>Key generation:</b> p,q large primes → n=pq, φ(n)=(p−1)(q−1), choose e s.t. gcd(e,φ)=1, d=e⁻¹ mod φ<br><b>Encrypt:</b> C = Mᵉ mod n &nbsp;|&nbsp; <b>Decrypt:</b> M = Cᵈ mod n<br><b>Sign:</b> S = H(M)ᵈ mod n &nbsp;|&nbsp; <b>Verify:</b> H(M) ≡ Sᵉ mod n<br>Security relies on hardness of factoring n. Standard sizes: 2048–4096 bits in production.")
    howto([
        "Click <b>Generate Key Pair</b> (uses 512-bit primes for speed — use 2048 in production).",
        "In <b>Encrypt/Decrypt tab</b>: enter an integer smaller than n, encrypt, then decrypt.",
        "In <b>Sign/Verify tab</b>: sign a text message with the private key, then verify with the public key.",
        "Try the <b>Tamper Test</b> — modify the message after signing to see verification fail.",
    ])
    if st.button("🔑  Generate 512-bit Key Pair", use_container_width=True):
        with st.spinner("Generating primes…"):
            st.session_state["rsa_keys"] = RSA.generate_keys(512)
            st.session_state.pop("rsa_ct", None)
            st.session_state.pop("rsa_sig", None)

    if "rsa_keys" in st.session_state:
        keys = st.session_state["rsa_keys"]
        with st.expander("🔍  Key material"):
            st.code(f"n  = {hex(keys['n'])}\ne  = {keys['e']}\nd  = {hex(keys['d'])}\np  = {hex(keys['p'])}\nq  = {hex(keys['q'])}")

        tab1, tab2 = st.tabs(["🔐  Encrypt / Decrypt", "✍️  Sign / Verify"])

        with tab1:
            st.markdown("Message must be an **integer < n** (textbook RSA, no padding).")
            msg_int = st.number_input("Message M (integer)", min_value=1, value=42, step=1,
                                      help="In practice, RSA encrypts a symmetric key, not data directly.")
            c1, c2 = st.columns(2)
            if c1.button("Encrypt with public key (e, n)", use_container_width=True):
                ct = RSA.encrypt(int(msg_int), keys["e"], keys["n"])
                st.session_state["rsa_ct"] = ct
                result("Ciphertext C = Mᵉ mod n", hex(ct))
            if c2.button("Decrypt with private key (d, n)", use_container_width=True):
                ct = st.session_state.get("rsa_ct")
                if ct:
                    pt = RSA.decrypt(ct, keys["d"], keys["n"])
                    result("Recovered M = Cᵈ mod n", str(pt))
                    if pt == int(msg_int):
                        st.success("✓ D(E(M)) = M — perfect recovery")
                else:
                    st.warning("Encrypt a message first.")
            answer_note("TP3 Q: Why can't RSA encrypt arbitrary-size messages?", "RSA operates mod n, so messages must be < n (e.g. < 256 bytes for 2048-bit RSA). For large data, use <b>hybrid encryption</b>: encrypt a random AES key with RSA, then encrypt the data with AES. <b>OAEP padding</b> adds randomness to prevent chosen-plaintext attacks (textbook RSA is deterministic and malleable).")

        with tab2:
            msg_str = st.text_input("Message to sign", value="Hello RSA!")
            c1, c2 = st.columns(2)
            if c1.button("✍️  Sign with private key", use_container_width=True):
                sig = RSA.sign(msg_str, keys["d"], keys["n"])
                st.session_state["rsa_sig"] = (sig, msg_str)
                result("Signature S = H(M)ᵈ mod n", hex(sig))
            if c2.button("✓  Verify with public key", use_container_width=True):
                stored = st.session_state.get("rsa_sig")
                if stored:
                    sig, signed_msg = stored
                    ok = RSA.verify(msg_str, sig, keys["e"], keys["n"])
                    if ok:
                        st.success("✓ Signature valid — message is authentic and unmodified")
                    else:
                        st.error("✗ Invalid signature — message was tampered with!")
                else:
                    st.warning("Sign a message first.")

            if st.session_state.get("rsa_sig"):
                section("Tamper Test")
                bad = st.text_input("Tampered message", value=msg_str + " [TAMPERED]")
                if st.button("🧪  Verify Tampered Message", use_container_width=True):
                    sig, _ = st.session_state["rsa_sig"]
                    ok = RSA.verify(bad, sig, keys["e"], keys["n"])
                    st.success("Valid (unexpected!)") if ok else st.error("✗ Rejected — tampering detected ✓")


# ─── ELGAMAL ─────────────────────────────────────────────────────────────────
elif page == "ElGamal":
    theory("ElGamal Cipher", "<b>Key gen:</b> p prime, g generator, x random secret, y = gˣ mod p<br><b>Encrypt(M):</b> choose random k, C = (gᵏ mod p, M·yᵏ mod p) = (c₁, c₂)<br><b>Decrypt(c₁,c₂):</b> M = c₂ · (c₁ˣ)⁻¹ mod p<br><b>Non-deterministic:</b> same M encrypted twice gives different ciphertexts (different k each time).<br><b>Ciphertext expansion:</b> ciphertext is 2× the size of the message (vs RSA same size).")
    howto([
        "Click <b>Generate Keys</b>.",
        "Enter an integer M (must satisfy 1 < M < p).",
        "Click <b>Encrypt</b> to get the pair (c₁, c₂), then <b>Decrypt</b> to recover M.",
        "Click <b>Encrypt Again</b> to confirm non-determinism (different (c₁,c₂) each time).",
    ])
    if st.button("🔑  Generate Keys", use_container_width=True):
        with st.spinner("Generating prime p…"):
            st.session_state["eg_keys"] = ElGamal.generate_keys(128)
            st.session_state.pop("eg_ct", None)

    if "eg_keys" in st.session_state:
        k = st.session_state["eg_keys"]
        with st.expander("🔍  Key parameters"):
            st.code(f"p (prime)  = {k['p']}\ng (generator) = {k['g']}\ny (public) = {k['y']}\nx (private) = {k['x']}")

        msg = st.number_input("Message M (integer)", min_value=2, value=12345, step=1,
                              help="Must be < p. In practice, M is a symmetric key or hash.")
        c1, c2, c3 = st.columns(3)
        if c1.button("🔒  Encrypt", use_container_width=True):
            if int(msg) >= k["p"]:
                st.error(f"M must be < p = {k['p']}")
            else:
                c1v, c2v = ElGamal.encrypt(int(msg), k["p"], k["g"], k["y"])
                st.session_state["eg_ct"] = (c1v, c2v)
                result("Ciphertext (c₁, c₂)", f"c₁ = {c1v}\nc₂ = {c2v}")

        if c2.button("🔓  Decrypt", use_container_width=True):
            ct = st.session_state.get("eg_ct")
            if ct:
                m_dec = ElGamal.decrypt(ct[0], ct[1], k["x"], k["p"])
                result("Decrypted M", str(m_dec))
                if m_dec == int(msg):
                    st.success("✓ D(E(M)) = M")
                else:
                    st.error(f"Got {m_dec}, expected {msg}")
            else:
                st.warning("Encrypt first.")

        if c3.button("🔄  Encrypt Again (non-det.)", use_container_width=True):
            c1v2, c2v2 = ElGamal.encrypt(int(msg), k["p"], k["g"], k["y"])
            result("New ciphertext (same M, different k)", f"c₁ = {c1v2}\nc₂ = {c2v2}")
            st.info("Both ciphertexts decrypt to the same M — this is probabilistic/non-deterministic encryption.")

        section("Malleability Demo (TP3 Ex3.3)")
        _html("<p style='color:#9CA3B8;font-size:14px'>Given Enc(M)=(c₁,c₂), an attacker can forge Enc(2M) = (c₁, 2·c₂ mod p) <em>without knowing M or the private key x</em>.</p>")
        if st.button("🔧  Forge Enc(2·M) from Enc(M)", use_container_width=True):
            ct = st.session_state.get("eg_ct")
            if not ct:
                st.warning("Encrypt M first.")
            else:
                c1v, c2v = ct
                c2_forged = (2 * c2v) % k["p"]
                m_forged = ElGamal.decrypt(c1v, c2_forged, k["x"], k["p"])
                result("Forged ciphertext", f"c₁ = {c1v}\nc₂ = {c2_forged}")
                result("Decryption of forged ciphertext", str(m_forged))
                if m_forged == (2 * int(msg)) % k["p"]:
                    st.success(f"✓ Got 2·M = {m_forged} (expected {(2*int(msg)) % k['p']}) — malleability confirmed!")
                answer_note("TP3 Q: RSA vs ElGamal size comparison", f"RSA-2048: ciphertext = 256 bytes (same as key). ElGamal-2048: ciphertext = 512 bytes (c₁ + c₂, each 256 bytes) — double the size. Implication: more bandwidth required for ElGamal.")


# ─── DIFFIE-HELLMAN ──────────────────────────────────────────────────────────
elif page == "Diffie-Hellman":
    theory("Diffie-Hellman Key Exchange", "<b>Public params:</b> large prime p, generator g<br><b>Alice:</b> picks private a, sends A = gᵃ mod p<br><b>Bob:</b> picks private b, sends B = gᵇ mod p<br><b>Shared secret:</b> K = Bᵃ mod p = Aᵇ mod p = gᵃᵇ mod p<br>An eavesdropper sees g, p, A, B but cannot compute gᵃᵇ without solving the <b>Discrete Logarithm Problem</b>.")
    howto([
        "Click <b>Run Exchange</b> to simulate Alice & Bob over an insecure channel.",
        "Inspect both parties' private/public values — they must reach the <b>same shared secret</b>.",
        "Try <b>MITM Attack</b> to see what happens without authentication.",
    ])
    tab1, tab2 = st.tabs(["▶️  Key Exchange", "🕵️  MITM Attack Demo"])

    with tab1:
        if st.button("▶️  Run Exchange", use_container_width=True):
            with st.spinner("Generating prime p…"):
                p, g = DiffieHellman.generate_params(128)
                a_priv = DiffieHellman.generate_private(p)
                b_priv = DiffieHellman.generate_private(p)
                a_pub  = DiffieHellman.compute_public(g, a_priv, p)
                b_pub  = DiffieHellman.compute_public(g, b_priv, p)
                shared_a = DiffieHellman.compute_shared(b_pub, a_priv, p)
                shared_b = DiffieHellman.compute_shared(a_pub, b_priv, p)
                st.session_state["dh"] = dict(
                    p=p, g=g, a_priv=a_priv, b_priv=b_priv,
                    a_pub=a_pub, b_pub=b_pub, shared=shared_a,
                    match=(shared_a == shared_b),
                )
        if "dh" in st.session_state:
            dh = st.session_state["dh"]
            with st.expander("🌐  Public channel (visible to attacker)"):
                st.code(f"p = {dh['p']}\ng = {dh['g']}\nA = {dh['a_pub']}\nB = {dh['b_pub']}")
            c1, c2 = st.columns(2)
            with c1:
                _html(f"""<div class="party"><div class="role">Party A</div><h4>👩 Alice</h4>
                  <div class="result-label">Private a</div><code>{dh['a_priv']}</code>
                  <div class="result-label">Computes K = Bᵃ mod p</div><code>{dh['shared']}</code>
                </div>""")
            with c2:
                _html(f"""<div class="party"><div class="role">Party B</div><h4>👨 Bob</h4>
                  <div class="result-label">Private b</div><code>{dh['b_priv']}</code>
                  <div class="result-label">Computes K = Aᵇ mod p</div><code>{DiffieHellman.compute_shared(dh['a_pub'], dh['b_priv'], dh['p'])}</code>
                </div>""")
            st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
            if dh["match"]:
                st.success(f"✓ Shared secret established:  K = {dh['shared']}")
            else:
                st.error("Mismatch!")

    with tab2:
        theory("Man-in-the-Middle Attack", "Without authentication, Eve intercepts A and B, substitutes her own values A′ and B′, and establishes separate sessions with Alice and Bob. She can read and re-encrypt all traffic.")
        if st.button("🕵️  Simulate MITM Attack", use_container_width=True):
            with st.spinner("…"):
                p, g = DiffieHellman.generate_params(128)
                # Legitimate parties
                a_priv = DiffieHellman.generate_private(p)
                b_priv = DiffieHellman.generate_private(p)
                a_pub  = DiffieHellman.compute_public(g, a_priv, p)
                b_pub  = DiffieHellman.compute_public(g, b_priv, p)
                # Eve intercepts and substitutes
                e_priv_a = DiffieHellman.generate_private(p)  # Eve's key towards Alice
                e_priv_b = DiffieHellman.generate_private(p)  # Eve's key towards Bob
                e_pub_a  = DiffieHellman.compute_public(g, e_priv_a, p)
                e_pub_b  = DiffieHellman.compute_public(g, e_priv_b, p)
                # Shared secrets
                k_alice_eve = DiffieHellman.compute_shared(e_pub_a, a_priv, p)   # Alice thinks this is with Bob
                k_eve_alice = DiffieHellman.compute_shared(a_pub,   e_priv_a, p)
                k_bob_eve   = DiffieHellman.compute_shared(e_pub_b, b_priv, p)   # Bob thinks this is with Alice
                k_eve_bob   = DiffieHellman.compute_shared(b_pub,   e_priv_b, p)
            st.error("⚠️ MITM ACTIVE — Eve intercepts both sessions")
            cols = st.columns(3)
            with cols[0]:
                _html(f'<div class="party"><div class="role">Victim A</div><h4>👩 Alice</h4><div class="result-label">Thinks shared with Bob</div><code>{k_alice_eve}</code></div>')
            with cols[1]:
                _html(f'<div class="party" style="border-color:rgba(248,113,113,0.4)"><div class="role" style="color:#F87171">Attacker</div><h4>😈 Eve</h4><div class="result-label">Key with Alice</div><code>{k_eve_alice}</code><div class="result-label">Key with Bob</div><code>{k_eve_bob}</code></div>')
            with cols[2]:
                _html(f'<div class="party"><div class="role">Victim B</div><h4>👨 Bob</h4><div class="result-label">Thinks shared with Alice</div><code>{k_bob_eve}</code></div>')
            st.success(f"Alice↔Eve match: {k_alice_eve == k_eve_alice} | Bob↔Eve match: {k_bob_eve == k_eve_bob}")
            answer_note("Counter-measure (TP3 Ex3.1)", "Authenticate the public keys: each party signs their DH value with a long-term private key (e.g. ECDSA). The other party verifies the signature with the sender's certified public key. This breaks the MITM attack.")


# ─── HASH FUNCTIONS ──────────────────────────────────────────────────────────
elif page == "Hash Functions":
    theory("Cryptographic Hash Functions", "<b>MD5:</b> 128-bit output, Merkle-Damgård, <em>broken</em> (collisions found by Wang & Yu 2004) — only use for checksums.<br><b>SHA-256:</b> 256-bit output, 64 rounds, standard for TLS/Bitcoin/JWT.<br><b>SHA-512:</b> 512-bit output, 80 rounds, 64-bit words — faster than SHA-256 on 64-bit CPUs.<br><b>Properties:</b> pre-image resistance, 2nd pre-image resistance, collision resistance.")
    howto([
        "Type any input — all three digests are computed instantly.",
        "Click <b>Avalanche Effect</b> to see that flipping 1 bit changes ~50% of output bits.",
        "Use <b>Integrity Check</b> to verify a file hash matches a reference.",
    ])

    tab1, tab2, tab3 = st.tabs(["#️⃣  Hash & Compare", "🌊  Avalanche Effect", "✅  Integrity Check"])

    with tab1:
        text = st.text_area("Input message", height=110, value="Hello, World!", key="hash_input")
        if text:
            c1, c2, c3 = st.columns(3)
            with c1:
                result("MD5 (128 bits)", HashFunctions.md5(text))
                st.caption("⚠️ Broken — do not use for security")
            with c2:
                result("SHA-256 (256 bits)", HashFunctions.sha256(text))
                st.caption("✓ Current standard")
            with c3:
                result("SHA-512 (512 bits)", hashlib.sha512(text.encode()).hexdigest())
                st.caption("✓ Faster on 64-bit CPUs")

    with tab2:
        text2 = st.text_area("Input for avalanche test", height=80, value="CryptoLab 2026", key="aval_input")
        if text2:
            h1, h2, diff, pct = HashFunctions.avalanche(text2)
            import hashlib
            sha512_h1 = hashlib.sha512(text2.encode()).hexdigest()
            modified = text2[:-1] + chr(ord(text2[-1]) ^ 1) if text2 else "x"
            sha512_h2 = hashlib.sha512(modified.encode()).hexdigest()
            b1_512 = bin(int(sha512_h1, 16))[2:].zfill(512)
            b2_512 = bin(int(sha512_h2, 16))[2:].zfill(512)
            diff_512 = sum(x != y for x, y in zip(b1_512, b2_512))

            section("SHA-256 Avalanche")
            m1, m2, m3 = st.columns(3)
            m1.metric("Original", h1[:20] + "…")
            m2.metric("1-bit flip", h2[:20] + "…")
            m3.metric("Bits changed", f"{diff} / 256", f"{pct}%  {'✓ ≈50%' if 40 < pct < 60 else ''}")
            section("SHA-512 Avalanche")
            n1, n2, n3 = st.columns(3)
            n1.metric("Original", sha512_h1[:20] + "…")
            n2.metric("1-bit flip", sha512_h2[:20] + "…")
            n3.metric("Bits changed", f"{diff_512} / 512", f"{round(diff_512/512*100,1)}%")
            answer_note("Why ~50%?", "A cryptographic hash behaves like a random function. One input bit change propagates through all rounds unpredictably, flipping on average half the output bits (ideal: 50%). MD5 shows the same effect but its collision resistance is broken.")

    with tab3:
        import hashlib
        ref_hash = st.text_input("Reference SHA-256 (from trusted source)", placeholder="Paste the official hash here…")
        data_input = st.text_area("Content to verify", height=100, placeholder="Paste file content or message…")
        if st.button("✅  Verify Integrity", use_container_width=True) and data_input:
            computed = hashlib.sha256(data_input.encode()).hexdigest()
            result("Computed SHA-256", computed)
            if ref_hash:
                if computed.lower() == ref_hash.lower().strip():
                    st.success("✓ INTACT — hashes match")
                else:
                    st.error("✗ CORRUPTED or TAMPERED — hashes differ")


# ─── DSA ─────────────────────────────────────────────────────────────────────
elif page == "DSA":
    theory("Digital Signature Algorithm", "<b>Params:</b> q (160–256 bit prime), p (1024-bit prime with q|(p−1)), g of order q<br><b>Sign(M):</b> k random ∈ [1,q−1]; r=(gᵏ mod p) mod q; s=k⁻¹(H(M)+xr) mod q → signature (r,s)<br><b>Verify(M,r,s):</b> w=s⁻¹ mod q; u₁=H(M)·w mod q; u₂=r·w mod q; v=(gᵘ¹·yᵘ² mod p) mod q; accept iff v=r<br><b>Security note:</b> if k is reused or predictable, x (private key) can be recovered!")
    howto([
        "Click <b>Generate Parameters</b> to create p, q, g, x, y.",
        "Type a message and click <b>Sign</b>.",
        "Click <b>Verify</b> with the same message — should say VALID.",
        "Use <b>Tamper Test</b> to sign one message and verify a different one — should REJECT.",
    ])
    if st.button("🔑  Generate DSA Parameters (q=160, p=1024 bits)", use_container_width=True):
        with st.spinner("Generating primes…"):
            st.session_state["dsa"] = DSA.generate_params(q_bits=160, p_bits=1024)
            st.session_state.pop("dsa_sig", None)

    if "dsa" in st.session_state:
        params = st.session_state["dsa"]
        with st.expander("🔍  Parameters"):
            st.code(f"q = {params['q']} ({params['q'].bit_length()} bits)\ng = {params['g']}\ny (public) = {params['y']}")

        msg = st.text_input("Message", value="Sign this message!", key="dsa_msg")
        c1, c2 = st.columns(2)
        if c1.button("✍️  Sign", use_container_width=True):
            if msg:
                r, s = DSA.sign(msg, params["p"], params["q"], params["g"], params["x"])
                st.session_state["dsa_sig"] = (r, s, msg)
                result("Signature (r, s)", f"r = {r}\ns = {s}")
            else:
                st.warning("Enter a message first.")
        if c2.button("✓  Verify", use_container_width=True):
            stored = st.session_state.get("dsa_sig")
            if stored:
                r, s, _ = stored
                ok = DSA.verify(msg, r, s, params["p"], params["q"], params["g"], params["y"])
                st.success("✓ Signature VALID") if ok else st.error("✗ Signature INVALID")
            else:
                st.warning("Sign a message first.")

        if st.session_state.get("dsa_sig"):
            section("Tamper Test")
            bad_msg = st.text_input("Tampered message", value=msg + " [MODIFIED]")
            if st.button("🧪  Verify Tampered Message", use_container_width=True):
                r, s, _ = st.session_state["dsa_sig"]
                ok = DSA.verify(bad_msg, r, s, params["p"], params["q"], params["g"], params["y"])
                st.success("Valid (unexpected!)") if ok else st.error("✗ REJECTED — tampering detected ✓")
            answer_note("Security note", "DSA provides <b>authenticity</b> (only x-holder can sign), <b>integrity</b> (any change invalidates signature), and <b>non-repudiation</b> (signer cannot deny). Critical weakness: if nonce k is reused across two signatures, x can be solved algebraically.")


# ─── SHAMIR ──────────────────────────────────────────────────────────────────
elif page == "Shamir (k,n)":
    theory("Shamir Secret Sharing", "A secret S is encoded as a polynomial f(x) of degree k−1 over a prime field, with f(0)=S. n shares (i, f(i)) are distributed. Any k shares reconstruct S via <b>Lagrange interpolation</b>. Any k−1 shares reveal <b>nothing</b> (information-theoretic security).")
    howto([
        "Enter a secret integer.",
        "Set threshold <b>k</b> (minimum shares needed to reconstruct) and <b>n</b> (total shares).",
        "Click <b>Split Secret</b> — n shares are generated.",
        "Select ≥ k shares and click <b>Reconstruct</b>. Try with fewer than k — it will fail.",
    ])
    secret = st.number_input("Secret S (integer)", min_value=0, value=12345, step=1)
    c1, c2 = st.columns(2)
    k = c1.slider("Threshold k (min shares to reconstruct)", 2, 10, 3)
    n = c2.slider("Total shares n", k, 20, 5)
    st.info(f"Any **{k}** of {n} shares can recover the secret. Any **{k-1}** or fewer reveal nothing.")
    if st.button("✂️  Split Secret", use_container_width=True):
        shares = ShamirSecretSharing.split(int(secret), k, n)
        st.session_state["shamir_shares"] = shares
        st.session_state["shamir_k"] = k
        st.session_state["shamir_secret"] = int(secret)
    if "shamir_shares" in st.session_state:
        shares = st.session_state["shamir_shares"]
        k_need = st.session_state["shamir_k"]
        sec = st.session_state["shamir_secret"]
        section("Generated shares — distribute these to n parties")
        st.dataframe(
            pd.DataFrame([{"Share #": i+1, "x": x, "y (share value)": y} for i, (x,y) in enumerate(shares)]),
            hide_index=True, use_container_width=True,
        )
        section("Reconstruct — select which shares to use")
        selected = st.multiselect(
            f"Select shares (need ≥ {k_need})",
            options=list(range(len(shares))),
            format_func=lambda i: f"Share {i+1}  (x={shares[i][0]})",
            default=list(range(k_need)),
        )
        if st.button("🔧  Reconstruct Secret", use_container_width=True):
            chosen = [shares[i] for i in selected]
            if len(chosen) < k_need:
                st.error(f"Need at least {k_need} shares, got {len(chosen)}.")
            else:
                res = ShamirSecretSharing.reconstruct(chosen)
                if res == sec:
                    st.success(f"✓ Reconstructed secret: **{res}** — matches original ✓")
                    st.balloons()
                else:
                    st.error(f"Got {res}, expected {sec}")
        # Demonstrate threshold: try with k-1
        if k_need >= 2:
            section("Threshold demo — try with k−1 shares")
            if st.button(f"🧪  Reconstruct with only {k_need-1} shares (should fail)", use_container_width=True):
                chosen_bad = [shares[i] for i in range(k_need - 1)]
                res_bad = ShamirSecretSharing.reconstruct(chosen_bad)
                st.warning(f"Result with {k_need-1} shares: {res_bad} (≠ {sec}) — wrong, as expected")
                answer_note("Why it fails", f"With only {k_need-1} shares, the polynomial is under-determined. Lagrange interpolation at x=0 gives an incorrect value. This is the information-theoretic security of Shamir's scheme.")


# ─── PAILLIER ────────────────────────────────────────────────────────────────
elif page == "Paillier":
    theory("Paillier Homomorphic Encryption", "<b>Enc(m₁) × Enc(m₂) mod n² = Enc(m₁ + m₂ mod n)</b><br>This allows a server to compute the sum of votes without ever decrypting individual votes — the foundation of <b>electronic voting</b> (TP6 Ex6.4).<br>Security: semantic security based on the Decisional Composite Residuosity problem.")
    howto([
        "Click <b>Generate Keys</b>.",
        "Enter up to 4 vote values (integers) simulating votes to tally.",
        "Click <b>Encrypt All & Tally</b> — sum is computed on ciphertexts, then decrypted once.",
        "Verify: decrypted total = sum of individual votes.",
    ])
    if st.button("🔑  Generate Keys", use_container_width=True):
        with st.spinner("Generating Paillier keys…"):
            st.session_state["paillier"] = Paillier.generate_keys(128)

    if "paillier" in st.session_state:
        pk = st.session_state["paillier"]
        with st.expander("🔍  Key parameters"):
            st.code(f"n  = {pk['n']}\ng  = {pk['g']}\nλ  = {pk['lam']}\nμ  = {pk['mu']}")

        tab1, tab2 = st.tabs(["➕  Homomorphic Addition", "🗳️  E-Voting Demo"])

        with tab1:
            c1, c2 = st.columns(2)
            m1 = c1.number_input("Value A", min_value=0, value=15, step=1)
            m2 = c2.number_input("Value B", min_value=0, value=27, step=1)
            if st.button("➕  Encrypt Both & Add Homomorphically", use_container_width=True):
                ct1 = Paillier.encrypt(int(m1), pk["n"], pk["g"])
                ct2 = Paillier.encrypt(int(m2), pk["n"], pk["g"])
                c_sum = Paillier.add_encrypted(ct1, ct2, pk["n"])
                res = Paillier.decrypt(c_sum, pk["n"], pk["lam"], pk["mu"])
                section("Computation trace")
                st.code(f"Enc({m1})      = {hex(ct1)[:40]}…\nEnc({m2})      = {hex(ct2)[:40]}…\nEnc(A)×Enc(B) = {hex(c_sum)[:40]}…\nDecrypt(sum)  = {res}")
                if res == int(m1) + int(m2):
                    st.success(f"✓ {m1} + {m2} = {res}  (computed entirely on ciphertexts!)")
                    st.balloons()
                else:
                    st.error(f"Got {res}, expected {int(m1)+int(m2)}")

        with tab2:
            st.markdown("Simulate **3 voters** each submitting an encrypted vote (0 = No, 1 = Yes).")
            votes_input = []
            cols = st.columns(3)
            for i, col in enumerate(cols):
                v = col.selectbox(f"Voter {i+1} vote", [0, 1], key=f"vote_{i}")
                votes_input.append(v)
            if st.button("🗳️  Tally Votes Homomorphically", use_container_width=True):
                enc_votes = [Paillier.encrypt(v, pk["n"], pk["g"]) for v in votes_input]
                # Homomorphic tally
                tally_enc = enc_votes[0]
                for ev in enc_votes[1:]:
                    tally_enc = Paillier.add_encrypted(tally_enc, ev, pk["n"])
                total = Paillier.decrypt(tally_enc, pk["n"], pk["lam"], pk["mu"])
                expected = sum(votes_input)
                section("Voting result")
                st.code(f"Votes cast (plaintext — for demo):  {votes_input}\nHomomorphic tally (decrypted once): {total}\nExpected:                           {expected}")
                if total == expected:
                    st.success(f"✓ Correct tally: {total} YES out of {len(votes_input)} votes — individual votes never revealed!")
                answer_note("Why this matters for TP6 Ex6.4", "In a real e-voting system, each voter encrypts their vote with the election authority's public key. The authority (or a distributed set of talliers) multiplies all ciphertexts homomorphically, then decrypts only the final sum. No individual vote is ever exposed.")


# ─── SCHNORR ─────────────────────────────────────────────────────────────────
elif page == "Schnorr ZKP":
    theory("Schnorr Zero-Knowledge Proof", "<b>Goal:</b> Alice proves she knows secret s (where h=gˢ mod p) to Bob, without revealing s.<br><b>Protocol:</b> (1) Alice commits: r←Zq, x=gʳ mod p → sends x. (2) Bob challenges: c←Zq → sends c. (3) Alice responds: y=r+sc mod q → sends y. (4) Bob verifies: gʸ ≡ x·hᶜ mod p.<br><b>Soundness:</b> a cheating prover who doesn't know s succeeds with probability 1/q ≈ 0.")
    howto([
        "Click <b>Setup</b> to generate parameters and Alice's secret.",
        "Follow steps 1–4 in order — each button simulates one protocol message.",
        "Step 4 reveals whether the verifier (Bob) accepts the proof.",
    ])
    if "schnorr" not in st.session_state:
        st.session_state["schnorr"] = {}
    state = st.session_state["schnorr"]
    current_step = state.get("step", 0)
    step_indicator(["Setup", "Alice commits", "Bob challenges", "Alice responds", "Bob verifies"], current_step)

    if st.button("⚙️  Setup — Generate Params & Alice's Secret", use_container_width=True):
        with st.spinner("Generating…"):
            params = Schnorr.generate_params(64)
            s, h = Schnorr.generate_keys(params["p"], params["q"], params["g"])
            state.clear()
            state.update(params=params, s=s, h=h, step=1)
            st.session_state["schnorr"] = state; st.rerun()

    if state.get("step", 0) >= 1:
        st.info(f"**Alice's secret s** = `{state['s']}`  _(private — never sent)_\n\n**Public key h** = gˢ mod p = `{state['h']}`")
        if st.button("Step 1 · Alice commits  →  x = gʳ mod p", use_container_width=True):
            r, x = Schnorr.prover_commit(state["params"]["p"], state["params"]["q"], state["params"]["g"])
            state.update(r=r, x=x, step=2); st.session_state["schnorr"] = state; st.rerun()

    if state.get("step", 0) >= 2:
        st.success(f"Alice → Bob:  **x** = `{state['x']}`")
        if st.button("Step 2 · Bob sends random challenge  →  c", use_container_width=True):
            c = Schnorr.generate_challenge(state["params"]["q"])
            state.update(c=c, step=3); st.session_state["schnorr"] = state; st.rerun()

    if state.get("step", 0) >= 3:
        st.success(f"Bob → Alice:  **c** = `{state['c']}`")
        if st.button("Step 3 · Alice responds  →  y = r + s·c mod q", use_container_width=True):
            y = Schnorr.prover_respond(state["r"], state["s"], state["c"], state["params"]["q"])
            state.update(y=y, step=4); st.session_state["schnorr"] = state; st.rerun()

    if state.get("step", 0) >= 4:
        st.success(f"Alice → Bob:  **y** = `{state['y']}`")
        if st.button("Step 4 · Bob verifies  →  gʸ ≡ x·hᶜ mod p ?", use_container_width=True):
            p_params = state["params"]
            ok = Schnorr.verify(p_params["g"], state["h"], state["x"], state["c"], state["y"], p_params["p"])
            if ok:
                st.success("✓ PROOF ACCEPTED — Bob is convinced Alice knows s, without learning s.")
            else:
                st.error("✗ Proof rejected")
            answer_note("Zero-knowledge property", "Bob only sees (x, c, y). He learns nothing about s because for any response y′, one can simulate a valid transcript (x′=gʸ′·h⁻ᶜ, c, y′) without knowing s. The protocol is honest-verifier zero-knowledge.")
            state["step"] = 0; st.session_state["schnorr"] = state


# ─── FEIGE-FIAT-SHAMIR ───────────────────────────────────────────────────────
elif page == "Feige-Fiat-Shamir":
    theory("Feige-Fiat-Shamir Identification", "<b>Setup:</b> n=p·q (RSA modulus), public v_i = s_i² mod n (or its inverse), private s_i.<br><b>Protocol:</b> (1) Prover picks r, sends x=r² mod n. (2) Verifier sends binary challenge b=[b₁…bk]. (3) Prover sends y=r·∏sᵢᵇⁱ mod n. (4) Verifier checks y²≡x·∏vᵢᵇⁱ mod n.<br>Security: based on hardness of computing square roots mod n (equivalent to factoring).")
    howto([
        "Click <b>Generate Parameters</b>.",
        "Follow steps 1–4 in order.",
        "Step 4 verifies whether identification succeeds.",
    ])
    K = 3
    if "ffs" not in st.session_state:
        st.session_state["ffs"] = {}
    state = st.session_state["ffs"]
    step_indicator(["Setup", "Prover commits", "Verifier challenges", "Prover responds", "Verifier checks"], state.get("step", 0))

    if st.button("⚙️  Generate FFS Parameters", use_container_width=True):
        with st.spinner("Generating RSA-like modulus…"):
            n = FeigeFiatShamir.generate_params(64)
            v, s = FeigeFiatShamir.generate_keys(n, K)
            state.clear()
            state.update(n=n, v=v, s=s, step=1); st.session_state["ffs"] = state; st.rerun()

    if state.get("step", 0) >= 1:
        st.info(f"**n** = {state['n']}")
        st.code("\n".join(f"s{i+1} = {state['s'][i]}   (private)   v{i+1} = {state['v'][i]}   (public = s{i+1}² mod n)" for i in range(K)))
        if st.button("Step 1 · Prover commits  →  x = r² mod n", use_container_width=True):
            r, x = FeigeFiatShamir.prover_commit(state["n"])
            state.update(r=r, x=x, step=2); st.session_state["ffs"] = state; st.rerun()

    if state.get("step", 0) >= 2:
        st.success(f"Prover → Verifier:  **x** = r² mod n = `{state['x']}`")
        if st.button("Step 2 · Verifier sends challenge bits  [b₁, b₂, b₃]", use_container_width=True):
            challenge = FeigeFiatShamir.generate_challenge(K)
            state.update(challenge=challenge, step=3); st.session_state["ffs"] = state; st.rerun()

    if state.get("step", 0) >= 3:
        st.success(f"Verifier → Prover:  challenge = `{state['challenge']}`")
        if st.button("Step 3 · Prover responds  →  y = r · ∏sᵢᵇⁱ mod n", use_container_width=True):
            y = FeigeFiatShamir.prover_respond(state["r"], state["s"], state["challenge"], state["n"])
            state.update(y=y, step=4); st.session_state["ffs"] = state; st.rerun()

    if state.get("step", 0) >= 4:
        st.success(f"Prover → Verifier:  **y** = `{state['y']}`")
        if st.button("Step 4 · Verifier checks  →  y² ≡ x · ∏vᵢᵇⁱ mod n ?", use_container_width=True):
            ok = FeigeFiatShamir.verify(state["x"], state["y"], state["v"], state["challenge"], state["n"])
            if ok:
                st.success("✓ Identification ACCEPTED")
            else:
                st.error("✗ Identification REJECTED")
            answer_note("Why it works", "y² = (r·∏sᵢ)² = r²·∏sᵢ² = x·∏vᵢ mod n (for bᵢ=1 positions). The verifier's check holds iff the prover correctly combined r with the right secret values sᵢ. A cheating prover who doesn't know sᵢ cannot compute the correct y with high probability.")
            state["step"] = 0; st.session_state["ffs"] = state


# ─── Helper for SHA-512 (not in HashFunctions) ───────────────────────────────
def import_sha512(text):
    import hashlib
    return hashlib.sha512(text.encode()).hexdigest()
