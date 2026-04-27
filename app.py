import streamlit as st
import pandas as pd
import textwrap

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
# DESIGN SYSTEM (premium dark theme + custom typography)
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

      /* ── App background: animated mesh gradient ───────────────────────── */
      .stApp {
        background:
          radial-gradient(900px 500px at 8% -10%, rgba(139,92,246,0.22), transparent 55%),
          radial-gradient(800px 500px at 110% 5%, rgba(6,182,212,0.16), transparent 55%),
          radial-gradient(700px 500px at 50% 110%, rgba(244,114,182,0.10), transparent 55%),
          var(--bg);
        background-attachment: fixed;
      }

      #MainMenu, footer { visibility: hidden; height: 0; }
      /* Keep header transparent but visible so sidebar toggle works */
      header[data-testid="stHeader"] {
        background: transparent !important;
        height: 2.5rem !important;
      }
      header[data-testid="stHeader"] button[kind="header"],
      header[data-testid="stHeader"] [data-testid="stBaseButton-headerNoPadding"] {
        color: #ECEFF7 !important;
      }
      .block-container { padding-top: 0.6rem !important; padding-bottom: 4rem !important; max-width: 1240px !important; }

      /* ── HERO ─────────────────────────────────────────────────────────── */
      .hero {
        position: relative;
        padding: 30px 36px 28px 36px;
        border-radius: 22px;
        background:
          linear-gradient(135deg, rgba(139,92,246,0.18), rgba(6,182,212,0.12) 60%, rgba(244,114,182,0.10));
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
      .hero p.tagline {
        margin: 4px 0 14px 0;
        color: var(--text-dim); font-size: 15px; max-width: 720px;
      }
      .hero .badge-row { display: flex; gap: 8px; flex-wrap: wrap; }
      .badge {
        font-size: 11px; font-weight: 500;
        padding: 5px 11px; border-radius: 999px;
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.08);
        color: #C8CFE2;
        backdrop-filter: blur(10px);
      }
      .badge.accent { background: rgba(139,92,246,0.14); border-color: rgba(139,92,246,0.35); color: #D8CDFF; }
      .badge.cyan   { background: rgba(6,182,212,0.12);  border-color: rgba(6,182,212,0.32);  color: #B6EAF6; }

      /* ── How-to card ─────────────────────────────────────────────────── */
      .howto {
        position: relative;
        padding: 16px 18px 16px 46px;
        border-radius: 14px;
        background: linear-gradient(180deg, rgba(6,182,212,0.07), rgba(6,182,212,0.02));
        border: 1px solid rgba(6,182,212,0.22);
        margin: 6px 0 22px 0;
        font-size: 14px; color: #D6DEEC;
      }
      .howto::before {
        content: "📘";
        position: absolute; left: 14px; top: 14px;
        font-size: 18px;
      }
      .howto .title {
        font-family: 'Space Grotesk', sans-serif;
        font-weight: 600; color: #FFFFFF; font-size: 13.5px;
        text-transform: uppercase; letter-spacing: 0.12em;
        margin-bottom: 6px;
      }
      .howto ol { margin: 0 0 0 18px; padding: 0; }
      .howto li { margin: 3px 0; line-height: 1.55; }
      .howto b { color: #FFFFFF; }

      /* ── Section heading ─────────────────────────────────────────────── */
      .section {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 12px; font-weight: 600; letter-spacing: 0.14em;
        text-transform: uppercase; color: var(--text-faint);
        margin: 22px 0 8px 0;
        display: flex; align-items: center; gap: 10px;
      }
      .section::after {
        content: ""; flex: 1; height: 1px;
        background: linear-gradient(90deg, var(--border-strong), transparent);
      }

      /* ── Result label ────────────────────────────────────────────────── */
      .result-label {
        font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.14em;
        color: var(--text-faint); margin: 14px 0 4px 0; font-weight: 600;
      }

      /* ── Sidebar styling ─────────────────────────────────────────────── */
      section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #050610 0%, #0A0C18 100%);
        border-right: 1px solid var(--border);
      }
      section[data-testid="stSidebar"] > div { padding-top: 8px; }
      .brand {
        padding: 10px 4px 18px 4px;
        border-bottom: 1px solid var(--border);
        margin-bottom: 14px;
      }
      .brand .logo {
        display: flex; align-items: center; gap: 12px;
      }
      .brand .logo .mark {
        width: 38px; height: 38px; border-radius: 11px;
        display: grid; place-items: center;
        font-size: 19px;
        background: linear-gradient(135deg, #8B5CF6, #06B6D4);
        box-shadow: 0 8px 24px -8px rgba(139,92,246,0.6);
      }
      .brand h2 {
        margin: 0; font-family: 'Space Grotesk', sans-serif;
        font-size: 19px; font-weight: 700; letter-spacing: -0.01em;
      }
      .brand .sub {
        margin: 2px 0 0 0; font-size: 11.5px; color: var(--text-faint);
        letter-spacing: 0.04em;
      }
      .cat-label {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 15px; font-weight: 700;
        letter-spacing: -0.005em;
        color: #FFFFFF;
        padding: 22px 8px 10px 8px;
        margin-top: 6px;
        display: flex; align-items: center; gap: 10px;
        border-top: 1px solid var(--border);
        position: relative;
      }
      .cat-label::after {
        content: ""; position: absolute; left: 8px; bottom: 4px;
        width: 22px; height: 2px; border-radius: 2px;
        background: linear-gradient(90deg, #8B5CF6, #06B6D4);
      }
      .cat-label .ic {
        font-size: 18px;
        width: 30px; height: 30px;
        display: grid; place-items: center;
        background: linear-gradient(135deg, rgba(139,92,246,0.20), rgba(6,182,212,0.14));
        border: 1px solid rgba(139,92,246,0.30);
        border-radius: 9px;
      }

      /* Sidebar buttons */
      section[data-testid="stSidebar"] .stButton > button {
        width: 100%;
        border-radius: 10px;
        border: 1px solid transparent;
        background: transparent;
        color: var(--text-dim);
        font-weight: 500;
        font-size: 13.5px;
        padding: 8px 12px;
        text-align: left;
        justify-content: flex-start !important;
        transition: all .15s ease;
      }
      section[data-testid="stSidebar"] .stButton > button:hover {
        background: rgba(139,92,246,0.10);
        color: #FFFFFF;
        border-color: rgba(139,92,246,0.25);
      }
      section[data-testid="stSidebar"] .stButton > button p {
        font-weight: 500 !important;
      }
      section[data-testid="stSidebar"] .nav-active .stButton > button {
        background: linear-gradient(90deg, rgba(139,92,246,0.22), rgba(139,92,246,0.04));
        color: #FFFFFF;
        border-color: rgba(139,92,246,0.38);
        box-shadow: 0 0 0 1px rgba(139,92,246,0.18) inset;
      }

      /* Main content buttons */
      .main .stButton > button, div[data-testid="stHorizontalBlock"] .stButton > button {
        border-radius: 11px;
        border: 1px solid var(--border-strong);
        background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.01));
        color: #E6EAF5;
        font-weight: 500;
        padding: 9px 16px;
        transition: all .18s ease;
      }
      .main .stButton > button:hover, div[data-testid="stHorizontalBlock"] .stButton > button:hover {
        border-color: rgba(139,92,246,0.55);
        background: linear-gradient(180deg, rgba(139,92,246,0.18), rgba(139,92,246,0.04));
        color: #FFFFFF;
        transform: translateY(-1px);
        box-shadow: 0 8px 22px -10px rgba(139,92,246,0.6);
      }
      .stButton > button:focus { box-shadow: none !important; outline: none !important; }
      .stButton > button:active { transform: translateY(0); }

      /* Inputs */
      .stTextInput > div > div, .stTextArea > div > div, .stNumberInput > div > div,
      .stSelectbox > div > div, .stMultiSelect > div > div {
        background: rgba(20, 24, 42, 0.6) !important;
        border: 1px solid var(--border) !important;
        border-radius: 11px !important;
      }
      .stTextInput input, .stTextArea textarea, .stNumberInput input {
        color: #ECEFF7 !important;
      }
      .stTextArea textarea {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 13.5px !important;
      }
      .stTextInput > label, .stTextArea > label, .stNumberInput > label,
      .stSelectbox > label, .stSlider > label, .stMultiSelect > label {
        font-size: 12px !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--text-faint) !important;
      }

      /* Code blocks */
      .stCodeBlock, pre {
        border-radius: 12px !important;
        border: 1px solid var(--border) !important;
        background: rgba(8, 10, 22, 0.7) !important;
      }
      .stCodeBlock code { font-size: 13.5px !important; }

      /* Tabs */
      .stTabs [data-baseweb="tab-list"] {
        gap: 6px;
        background: transparent;
        border-bottom: 1px solid var(--border);
        margin-bottom: 14px;
      }
      .stTabs [data-baseweb="tab"] {
        background: transparent;
        border-radius: 10px 10px 0 0;
        padding: 10px 18px;
        color: var(--text-dim);
        font-weight: 500;
      }
      .stTabs [aria-selected="true"] {
        background: rgba(139,92,246,0.10) !important;
        color: #FFFFFF !important;
        border-bottom: 2px solid #8B5CF6 !important;
      }

      /* Alerts */
      div[data-testid="stAlert"] {
        border-radius: 12px !important;
        border: 1px solid var(--border-strong) !important;
        backdrop-filter: blur(10px);
      }

      /* Metrics */
      div[data-testid="stMetric"] {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 16px 18px;
        backdrop-filter: blur(10px);
      }
      div[data-testid="stMetricLabel"] {
        color: var(--text-faint) !important;
        font-size: 11.5px !important;
        text-transform: uppercase;
        letter-spacing: 0.1em;
      }
      div[data-testid="stMetricValue"] {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 18px !important;
      }

      /* Expanders */
      .streamlit-expanderHeader, [data-testid="stExpander"] summary {
        background: var(--panel) !important;
        border-radius: 11px !important;
        border: 1px solid var(--border) !important;
        font-weight: 500 !important;
      }

      /* Sliders */
      .stSlider [data-baseweb="slider"] > div > div {
        background: linear-gradient(90deg, #8B5CF6, #06B6D4) !important;
      }

      /* Dataframes */
      .stDataFrame { border-radius: 12px; overflow: hidden; border: 1px solid var(--border); }

      /* Step indicator (for ZKP protocols) */
      .step-row { display: flex; gap: 8px; margin: 10px 0 18px 0; flex-wrap: wrap; }
      .step-chip {
        display: flex; align-items: center; gap: 8px;
        padding: 7px 13px; border-radius: 999px;
        background: rgba(255,255,255,0.03);
        border: 1px solid var(--border);
        font-size: 12.5px; color: var(--text-dim);
      }
      .step-chip .num {
        width: 20px; height: 20px; border-radius: 50%;
        background: rgba(255,255,255,0.06); color: var(--text-dim);
        display: grid; place-items: center; font-size: 11px; font-weight: 700;
      }
      .step-chip.done { color: #FFFFFF; border-color: rgba(52,211,153,0.4); background: rgba(52,211,153,0.10); }
      .step-chip.done .num { background: #34D399; color: #062117; }
      .step-chip.current { color: #FFFFFF; border-color: rgba(139,92,246,0.5); background: rgba(139,92,246,0.15);
        box-shadow: 0 0 0 3px rgba(139,92,246,0.10); }
      .step-chip.current .num { background: #8B5CF6; color: #FFFFFF; }

      /* Party card (Alice / Bob) */
      .party {
        padding: 16px 18px;
        border-radius: 14px;
        background: var(--panel);
        border: 1px solid var(--border);
        backdrop-filter: blur(10px);
      }
      .party h4 {
        margin: 0 0 8px 0; font-size: 14px;
        font-family: 'Space Grotesk', sans-serif;
        display: flex; align-items: center; gap: 8px;
      }
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
            ("Caesar",              "🏛️", "Shift cipher · the original"),
            ("Affine",               "📐", "Linear transformation"),
            ("Simple Substitution",  "🔤", "Permutation key"),
            ("Vigenere",             "🗝️", "Polyalphabetic"),
            ("One-Time Pad",         "📨", "Information-theoretic"),
            ("Playfair",             "🎴", "5×5 digram cipher"),
            ("Hill",                 "🧮", "Matrix-based cipher"),
        ],
    },
    "Modern Symmetric": {
        "icon": "🛡️",
        "items": [
            ("AES",  "🔒", "Advanced Encryption Standard"),
            ("RC4",  "🌊", "Stream cipher"),
        ],
    },
    "Asymmetric": {
        "icon": "🔑",
        "items": [
            ("RSA",            "🔐", "Rivest–Shamir–Adleman"),
            ("ElGamal",        "🧠", "Discrete logarithm"),
            ("Diffie-Hellman", "🤝", "Key exchange"),
        ],
    },
    "Hash Functions": {
        "icon": "🧬",
        "items": [
            ("MD5 / SHA-1 / SHA-256", "#️⃣", "One-way digests"),
        ],
    },
    "Digital Signatures": {
        "icon": "✍️",
        "items": [
            ("DSA", "✒️", "Digital Signature Algorithm"),
        ],
    },
    "Secret Sharing": {
        "icon": "🧩",
        "items": [
            ("Shamir (k,n)", "🧩", "Threshold sharing"),
        ],
    },
    "Homomorphic Encryption": {
        "icon": "➕",
        "items": [
            ("Paillier", "➕", "Additive homomorphism"),
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
              <p class="sub">Cryptography studio · v2</p>
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

    st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)



page = st.session_state["page"]
category = CATEGORY_OF.get(page, "")
cat_icon = PAGES.get(category, {}).get("icon", "🔐")
subtitle = SUBTITLE_OF.get(page, "")

# ─────────────────────────────────────────────────────────────────────────────
# HERO HEADER
# ─────────────────────────────────────────────────────────────────────────────
_html(f"""
    <div class="hero">
      <div class="eyebrow"><span class="dot"></span>{cat_icon}  {category}</div>
      <h1>{page}</h1>
      <p class="tagline">{subtitle}. Interactive playground to learn how it works — try it, break it, understand it.</p>
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

def section(title):
    _html(f'<div class="section">{title}</div>')

def result(label, value, lang=None):
    _html(f'<div class="result-label">{label}</div>')
    st.code(value, language=lang)

def step_indicator(steps, current):
    """current: 0 = none done, len(steps) = all done"""
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
    st.markdown("Each letter shifts by a fixed number of positions:  `C = (P + k) mod 26`")
    howto([
        "Type any text in the box below.",
        "Pick a shift value between 1 and 25.",
        "Click <b>Encrypt</b> or <b>Decrypt</b>. Try <b>Brute Force</b> to see all 25 candidates at once.",
    ])
    text = st.text_area("Text", height=120, placeholder="Type plaintext or ciphertext here…")
    key = st.slider("Shift (k)", 1, 25, 3)
    c1, c2, c3 = st.columns(3)
    if c1.button("🔒  Encrypt", use_container_width=True):
        result("Result", Caesar.encrypt(text, key))
    if c2.button("🔓  Decrypt", use_container_width=True):
        result("Result", Caesar.decrypt(text, key))
    if c3.button("🔍  Brute Force", use_container_width=True):
        section("All 25 candidate decryptions")
        rows = [{"k": k, "Decryption": v} for k, v in Caesar.brute_force(text)]
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)


# ─── AFFINE ──────────────────────────────────────────────────────────────────
elif page == "Affine":
    st.markdown("`C = (a · P + b) mod 26` — `a` must be coprime with 26.")
    howto([
        "Choose a value of <b>a</b> from the dropdown (only valid options shown).",
        "Pick a value of <b>b</b> between 0 and 25.",
        "Click <b>Encrypt</b> or <b>Decrypt</b> to transform the text.",
    ])
    text = st.text_area("Text", height=120, placeholder="Type text to encrypt or decrypt…")
    valid_a = [a for a in range(1, 26) if gcd(a, 26) == 1]
    c1, c2 = st.columns(2)
    a = c1.selectbox("a (coprime with 26)", valid_a, index=valid_a.index(7))
    b = c2.slider("b", 0, 25, 3)
    cc1, cc2 = st.columns(2)
    if cc1.button("🔒  Encrypt", use_container_width=True):
        result("Result", Affine.encrypt(text, a, b))
    if cc2.button("🔓  Decrypt", use_container_width=True):
        result("Result", Affine.decrypt(text, a, b))


# ─── SIMPLE SUBSTITUTION ─────────────────────────────────────────────────────
elif page == "Simple Substitution":
    st.markdown("Replaces each letter with another based on a fixed permutation key.")
    howto([
        "Use the auto-generated key, or click <b>Random Key</b> for a fresh permutation.",
        "Type your text and click <b>Encrypt</b> or <b>Decrypt</b>.",
        "Scroll down to view a frequency analysis — the classic way to break substitution ciphers.",
    ])
    text = st.text_area("Text", height=120)
    if "sub_key" not in st.session_state:
        st.session_state["sub_key"] = SimpleSubstitution.make_key()
    c1, c2 = st.columns([3, 1])
    key = c1.text_input("Substitution key (26 letters)", value=st.session_state["sub_key"])
    if c2.button("🎲  Random Key", use_container_width=True):
        st.session_state["sub_key"] = SimpleSubstitution.make_key()
        st.rerun()
    cc1, cc2 = st.columns(2)
    if cc1.button("🔒  Encrypt", use_container_width=True):
        result("Result", SimpleSubstitution.encrypt(text, key))
    if cc2.button("🔓  Decrypt", use_container_width=True):
        result("Result", SimpleSubstitution.decrypt(text, key))
    if text:
        section("Frequency Analysis")
        freq = SimpleSubstitution.frequency_analysis(text)
        if freq:
            df = pd.DataFrame(list(freq.items()), columns=["Letter", "Frequency (%)"])
            st.bar_chart(df.set_index("Letter"))


# ─── VIGENERE ────────────────────────────────────────────────────────────────
elif page == "Vigenere":
    st.markdown("Polyalphabetic cipher using a repeating keyword.")
    howto([
        "Enter a keyword — the longer, the harder to break.",
        "Type your text and click <b>Encrypt</b> or <b>Decrypt</b>.",
        "Use <b>Kasiski Analysis</b> to estimate the key length from a ciphertext.",
    ])
    text = st.text_area("Text", height=120)
    key = st.text_input("Keyword", value="SECRET")
    c1, c2 = st.columns(2)
    if c1.button("🔒  Encrypt", use_container_width=True):
        result("Result", Vigenere.encrypt(text, key))
    if c2.button("🔓  Decrypt", use_container_width=True):
        result("Result", Vigenere.decrypt(text, key))
    if st.button("🔍  Kasiski Analysis", use_container_width=True):
        if text:
            results = Vigenere.kasiski(text)
            if results:
                section("Likely key lengths (by factor frequency)")
                df = pd.DataFrame(results, columns=["Length", "Occurrences"])
                st.dataframe(df, hide_index=True, use_container_width=True)
            else:
                st.info("Not enough repeated sequences found in the input.")


# ─── OTP ─────────────────────────────────────────────────────────────────────
elif page == "One-Time Pad":
    st.markdown("Theoretically unbreakable — the key must be as long as the message and used only once.")
    howto([
        "Type your message.",
        "Click <b>Generate Key</b> to create a one-time pad of matching length.",
        "Use <b>Encrypt</b> or <b>Decrypt</b>. The same key must be used by both ends.",
    ])
    text = st.text_area("Text", height=120)
    letters_only = "".join(c for c in text if c.isalpha())
    if st.button("🔑  Generate Key", use_container_width=True):
        st.session_state["otp_key"] = OTP.generate_key(max(len(letters_only), 1))
    key = st.session_state.get("otp_key", [])
    if key:
        st.caption(f"Key (integers): {key[:30]}{'…' if len(key) > 30 else ''}")
    c1, c2 = st.columns(2)
    if c1.button("🔒  Encrypt", use_container_width=True) and key:
        result("Result", OTP.encrypt(text, key))
    if c2.button("🔓  Decrypt", use_container_width=True) and key:
        result("Result", OTP.decrypt(text, key))


# ─── PLAYFAIR ────────────────────────────────────────────────────────────────
elif page == "Playfair":
    st.markdown("Encrypts pairs of letters using a 5×5 key matrix. The letter J is treated as I.")
    howto([
        "Choose a keyword — it seeds the 5×5 matrix.",
        "Type letters only (digrams will be auto-paired with X if needed).",
        "Click <b>Encrypt</b> or <b>Decrypt</b>.",
    ])
    text = st.text_area("Text (letters only)", height=120)
    key = st.text_input("Keyword", value="MONARCHY")
    c1, c2 = st.columns(2)
    if c1.button("🔒  Encrypt", use_container_width=True):
        try: result("Result", Playfair.encrypt(text, key))
        except Exception as e: st.error(str(e))
    if c2.button("🔓  Decrypt", use_container_width=True):
        try: result("Result", Playfair.decrypt(text, key))
        except Exception as e: st.error(str(e))


# ─── HILL ────────────────────────────────────────────────────────────────────
elif page == "Hill":
    st.markdown("Matrix-based cipher. The key must be a 2×2 matrix invertible mod 26.")
    howto([
        "Fill in the four entries of the 2×2 key matrix.",
        "Make sure the determinant is invertible mod 26 (warning shown if not).",
        "Click <b>Encrypt</b> or <b>Decrypt</b> on your text.",
    ])
    text = st.text_area("Text", height=120)
    section("2×2 Key Matrix")
    c1, c2 = st.columns(2)
    a = c1.number_input("a", value=3, step=1)
    b = c2.number_input("b", value=3, step=1)
    c = c1.number_input("c", value=2, step=1)
    d = c2.number_input("d", value=5, step=1)
    key_matrix = [[int(a), int(b)], [int(c), int(d)]]
    det = (int(a)*int(d) - int(b)*int(c)) % 26
    if gcd(det, 26) != 1:
        st.warning(f"Determinant = {det}, not invertible mod 26. Choose different values.")
    else:
        cc1, cc2 = st.columns(2)
        if cc1.button("🔒  Encrypt", use_container_width=True):
            result("Result", Hill.encrypt(text, key_matrix))
        if cc2.button("🔓  Decrypt", use_container_width=True):
            result("Result", Hill.decrypt(text, key_matrix))


# ─── AES ─────────────────────────────────────────────────────────────────────
elif page == "AES":
    st.markdown("Block cipher with 128 / 192 / 256-bit keys. This implementation uses ECB mode.")
    howto([
        "Pick a key size, then click <b>Generate Key</b> for a random hex key.",
        "Type plaintext and click <b>Encrypt</b> — output is hex.",
        "To decrypt, paste the ciphertext hex and click <b>Decrypt</b>.",
    ])
    key_size = st.selectbox("Key size", [128, 192, 256])
    if "aes_key" not in st.session_state:
        st.session_state["aes_key"] = AES.generate_key(128)
    c1, c2 = st.columns([3, 1])
    aes_key = c1.text_input("Key (hex)", value=st.session_state["aes_key"])
    if c2.button("🎲  Generate", use_container_width=True):
        st.session_state["aes_key"] = AES.generate_key(key_size)
        st.rerun()
    text = st.text_area("Plaintext", height=110)
    cipher_input = st.text_input("Ciphertext (hex) for decryption", "")
    cc1, cc2 = st.columns(2)
    if cc1.button("🔒  Encrypt", use_container_width=True):
        try: result("Ciphertext (hex)", AES.encrypt_ecb(text, aes_key))
        except Exception as e: st.error(f"Error: {e}")
    if cc2.button("🔓  Decrypt", use_container_width=True):
        try: result("Plaintext", AES.decrypt_ecb(cipher_input or text, aes_key))
        except Exception as e: st.error(f"Error: {e}")


# ─── RC4 ─────────────────────────────────────────────────────────────────────
elif page == "RC4":
    st.markdown("Stream cipher using a key-scheduling algorithm. Simple but insecure for modern use.")
    howto([
        "Choose a passphrase as the key.",
        "Type plaintext to <b>Encrypt</b> — the output is hex.",
        "To decrypt, paste the ciphertext hex and click <b>Decrypt</b>.",
    ])
    text = st.text_area("Plaintext", height=110)
    cipher_hex = st.text_input("Ciphertext (hex) for decryption", "")
    key = st.text_input("Key", value="secretkey")
    c1, c2 = st.columns(2)
    if c1.button("🔒  Encrypt", use_container_width=True):
        result("Ciphertext (hex)", RC4.encrypt(text, key))
    if c2.button("🔓  Decrypt", use_container_width=True):
        try: result("Plaintext", RC4.decrypt(cipher_hex or text, key))
        except Exception as e: st.error(str(e))


# ─── RSA ─────────────────────────────────────────────────────────────────────
elif page == "RSA":
    st.markdown("Public-key cryptosystem based on the difficulty of factoring large integers.")
    howto([
        "Click <b>Generate Key Pair</b> (this may take a few seconds).",
        "In <b>Encrypt / Decrypt</b>, encrypt an integer with the public key and decrypt with the private key.",
        "In <b>Sign / Verify</b>, sign a message with the private key and verify with the public key.",
    ])
    if st.button("🔑  Generate 512-bit Key Pair", use_container_width=True):
        with st.spinner("Generating primes…"):
            st.session_state["rsa_keys"] = RSA.generate_keys(512)
    if "rsa_keys" in st.session_state:
        keys = st.session_state["rsa_keys"]
        with st.expander("🔍  View key material"):
            st.code(f"n = {hex(keys['n'])}\ne = {keys['e']}\nd = {hex(keys['d'])}")
        tab1, tab2 = st.tabs(["🔐  Encrypt / Decrypt", "✍️  Sign / Verify"])
        with tab1:
            msg = st.number_input("Message (integer, must be < n)", min_value=1, value=42, step=1)
            c1, c2 = st.columns(2)
            if c1.button("Encrypt with public key", use_container_width=True):
                ct = RSA.encrypt(int(msg), keys["e"], keys["n"])
                st.session_state["rsa_ct"] = ct
                result("Ciphertext", hex(ct))
            if c2.button("Decrypt with private key", use_container_width=True):
                ct = st.session_state.get("rsa_ct")
                if ct: result("Decrypted", str(RSA.decrypt(ct, keys["d"], keys["n"])))
        with tab2:
            msg = st.text_input("Message to sign", value="Hello RSA!")
            c1, c2 = st.columns(2)
            if c1.button("Sign", use_container_width=True):
                sig = RSA.sign(msg, keys["d"], keys["n"])
                st.session_state["rsa_sig"] = sig
                result("Signature", hex(sig))
            if c2.button("Verify", use_container_width=True):
                sig = st.session_state.get("rsa_sig")
                if sig:
                    ok = RSA.verify(msg, sig, keys["e"], keys["n"])
                    st.success("✓ Signature valid") if ok else st.error("✗ Invalid signature")


# ─── ELGAMAL ─────────────────────────────────────────────────────────────────
elif page == "ElGamal":
    st.markdown("Asymmetric cipher based on the discrete logarithm problem.")
    howto([
        "Click <b>Generate Keys</b>.",
        "Enter an integer message smaller than <b>p</b>.",
        "Encrypt produces a pair (c1, c2) — Decrypt recovers the original message.",
    ])
    if st.button("🔑  Generate Keys", use_container_width=True):
        with st.spinner("Generating…"):
            st.session_state["eg_keys"] = ElGamal.generate_keys(128)
    if "eg_keys" in st.session_state:
        k = st.session_state["eg_keys"]
        with st.expander("🔍  Key parameters"):
            st.code(f"p = {k['p']}\ng = {k['g']}\npublic y = {k['y']}")
        msg = st.number_input("Message (integer, 1 < m < p)", min_value=2, value=42, step=1)
        c1, c2 = st.columns(2)
        if c1.button("🔒  Encrypt", use_container_width=True):
            c1v, c2v = ElGamal.encrypt(int(msg), k["p"], k["g"], k["y"])
            st.session_state["eg_ct"] = (c1v, c2v)
            result("Ciphertext (c1, c2)", f"c1 = {c1v}\nc2 = {c2v}")
        if c2.button("🔓  Decrypt", use_container_width=True):
            ct = st.session_state.get("eg_ct")
            if ct:
                m = ElGamal.decrypt(ct[0], ct[1], k["x"], k["p"])
                result("Decrypted", str(m))


# ─── DIFFIE-HELLMAN ──────────────────────────────────────────────────────────
elif page == "Diffie-Hellman":
    st.markdown("Lets two parties establish a shared secret over an insecure channel.")
    howto([
        "Click <b>Run Exchange</b> to generate parameters and simulate Alice & Bob.",
        "Both parties independently compute the same shared secret.",
        "Compare their results — they should match exactly.",
    ])
    if st.button("▶️  Run Exchange", use_container_width=True):
        with st.spinner("Generating prime…"):
            p, g = DiffieHellman.generate_params(128)
            a_priv = DiffieHellman.generate_private(p)
            b_priv = DiffieHellman.generate_private(p)
            a_pub = DiffieHellman.compute_public(g, a_priv, p)
            b_pub = DiffieHellman.compute_public(g, b_priv, p)
            shared_a = DiffieHellman.compute_shared(b_pub, a_priv, p)
            shared_b = DiffieHellman.compute_shared(a_pub, b_priv, p)
            st.session_state["dh"] = dict(
                p=p, g=g, a_priv=a_priv, b_priv=b_priv,
                a_pub=a_pub, b_pub=b_pub, shared=shared_a,
                match=(shared_a == shared_b),
            )
    if "dh" in st.session_state:
        dh = st.session_state["dh"]
        with st.expander("🌐  Public parameters"):
            st.code(f"p = {dh['p']}\ng = {dh['g']}")
        c1, c2 = st.columns(2)
        with c1:
            _html(f"""
                <div class="party">
                  <div class="role">Party A</div>
                  <h4>👩 Alice</h4>
                  <div class="result-label">Private</div>
                  <code>{dh['a_priv']}</code>
                  <div class="result-label">Public</div>
                  <code>{dh['a_pub']}</code>
                </div>
                """)
        with c2:
            _html(f"""
                <div class="party">
                  <div class="role">Party B</div>
                  <h4>👨 Bob</h4>
                  <div class="result-label">Private</div>
                  <code>{dh['b_priv']}</code>
                  <div class="result-label">Public</div>
                  <code>{dh['b_pub']}</code>
                </div>
                """)
        st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)
        if dh["match"]:
            st.success(f"✓ Shared secret established: {dh['shared']}")
        else:
            st.error("Mismatch — something went wrong.")


# ─── HASHING ─────────────────────────────────────────────────────────────────
elif page == "MD5 / SHA-1 / SHA-256":
    st.markdown("One-way functions — easy to compute, infeasible to reverse.")
    howto([
        "Type any input below.",
        "All three hash digests are computed instantly.",
        "Scroll down for the <b>avalanche effect</b> — flipping one bit changes ~50% of output bits.",
    ])
    text = st.text_area("Input", height=110, value="Hello, World!")
    if text:
        c1, c2, c3 = st.columns(3)
        with c1: result("MD5", HashFunctions.md5(text))
        with c2: result("SHA-1", HashFunctions.sha1(text))
        with c3: result("SHA-256", HashFunctions.sha256(text))
        section("Avalanche Effect")
        h1, h2, diff, pct = HashFunctions.avalanche(text)
        m1, m2, m3 = st.columns(3)
        m1.metric("Original SHA-256", h1[:16] + "…")
        m2.metric("Modified SHA-256", h2[:16] + "…")
        m3.metric("Bits changed", f"{diff} / 256", f"{pct}%")


# ─── DSA ─────────────────────────────────────────────────────────────────────
elif page == "DSA":
    st.markdown("Generates and verifies digital signatures based on the discrete logarithm problem.")
    howto([
        "Click <b>Generate Parameters</b>.",
        "Type a message and click <b>Sign</b>.",
        "Click <b>Verify</b>, or use the <b>Tamper Test</b> below to see what happens with a modified message.",
    ])
    if st.button("🔑  Generate DSA Parameters", use_container_width=True):
        with st.spinner("Generating primes…"):
            st.session_state["dsa"] = DSA.generate_params(64)
    if "dsa" in st.session_state:
        params = st.session_state["dsa"]
        with st.expander("🔍  Parameters"):
            st.code(f"q = {params['q']}\ng = {params['g']}")
        msg = st.text_input("Message", value="Sign this message!")
        c1, c2 = st.columns(2)
        if c1.button("✍️  Sign", use_container_width=True):
            r, s = DSA.sign(msg, params["p"], params["q"], params["g"], params["x"])
            st.session_state["dsa_sig"] = (r, s)
            result("Signature", f"r = {r}\ns = {s}")
        if c2.button("✓  Verify", use_container_width=True):
            sig = st.session_state.get("dsa_sig")
            if sig:
                ok = DSA.verify(msg, sig[0], sig[1], params["p"], params["q"], params["g"], params["y"])
                st.success("✓ Signature valid") if ok else st.error("✗ Invalid")
        if st.session_state.get("dsa_sig"):
            section("Tamper Test")
            bad_msg = st.text_input("Tampered message", value=msg + "X")
            if st.button("🧪  Verify Tampered", use_container_width=True):
                sig = st.session_state["dsa_sig"]
                ok = DSA.verify(bad_msg, sig[0], sig[1], params["p"], params["q"], params["g"], params["y"])
                st.success("Valid (unexpected!)") if ok else st.error("✗ Rejected — tampering detected")


# ─── SHAMIR ──────────────────────────────────────────────────────────────────
elif page == "Shamir (k,n)":
    st.markdown("Split a secret into n shares — any k of them can reconstruct it.")
    howto([
        "Pick a secret integer.",
        "Choose threshold <b>k</b> (minimum shares needed) and total shares <b>n</b>.",
        "Click <b>Split Secret</b>, then select shares and <b>Reconstruct</b> to recover the original.",
    ])
    secret = st.number_input("Secret (integer)", min_value=0, value=12345)
    c1, c2 = st.columns(2)
    k = c1.slider("Threshold k", 2, 10, 3)
    n = c2.slider("Total shares n", k, 20, 5)
    if st.button("✂️  Split Secret", use_container_width=True):
        shares = ShamirSecretSharing.split(int(secret), k, n)
        st.session_state["shamir_shares"] = shares
        st.session_state["shamir_k"] = k
    if "shamir_shares" in st.session_state:
        shares = st.session_state["shamir_shares"]
        k_needed = st.session_state["shamir_k"]
        section("Generated shares")
        st.dataframe(
            pd.DataFrame([{"Share #": i+1, "x": x, "y": y} for i, (x, y) in enumerate(shares)]),
            hide_index=True, use_container_width=True,
        )
        section("Reconstruct")
        selected = st.multiselect(
            f"Select at least {k_needed} shares",
            options=list(range(len(shares))),
            format_func=lambda i: f"Share {i+1}",
            default=list(range(k_needed)),
        )
        if st.button("🔧  Reconstruct", use_container_width=True):
            chosen = [shares[i] for i in selected]
            if len(chosen) < k_needed:
                st.warning(f"Need at least {k_needed} shares.")
            else:
                res = ShamirSecretSharing.reconstruct(chosen)
                if res == int(secret):
                    st.success(f"✓ Reconstructed secret: {res}")
                else:
                    st.error(f"Got {res}, expected {secret}")


# ─── PAILLIER ────────────────────────────────────────────────────────────────
elif page == "Paillier":
    st.markdown("Additive homomorphic encryption:  **Enc(a) × Enc(b) = Enc(a + b)**")
    howto([
        "Click <b>Generate Keys</b>.",
        "Enter two values A and B.",
        "Click <b>Encrypt & Add</b> — the sum is computed in encrypted form, then decrypted.",
    ])
    if st.button("🔑  Generate Keys", use_container_width=True):
        with st.spinner("Generating…"):
            st.session_state["paillier"] = Paillier.generate_keys(128)
    if "paillier" in st.session_state:
        pk = st.session_state["paillier"]
        c1, c2 = st.columns(2)
        m1 = c1.number_input("Value A", min_value=0, value=15, step=1)
        m2 = c2.number_input("Value B", min_value=0, value=27, step=1)
        if st.button("➕  Encrypt Both & Add Homomorphically", use_container_width=True):
            ct1 = Paillier.encrypt(int(m1), pk["n"], pk["g"])
            ct2 = Paillier.encrypt(int(m2), pk["n"], pk["g"])
            c_sum = Paillier.add_encrypted(ct1, ct2, pk["n"])
            res = Paillier.decrypt(c_sum, pk["n"], pk["lam"], pk["mu"])
            result("Computation", f"Enc({m1}) × Enc({m2}) = Enc({res})")
            if res == int(m1) + int(m2):
                st.success(f"✓ Decrypted result: {res}  (expected {int(m1) + int(m2)})")
                st.balloons()
            else:
                st.error(f"Got {res}, expected {int(m1) + int(m2)}")


# ─── SCHNORR ─────────────────────────────────────────────────────────────────
elif page == "Schnorr ZKP":
    st.markdown(
        "Interactive proof — **Alice proves she knows the secret s** "
        "(where h = gˢ mod p) **without revealing s**."
    )
    howto([
        "Click <b>Setup</b> to generate parameters and Alice's secret.",
        "Walk through the four steps in order — each button advances the protocol.",
        "Step 4 reveals whether the verifier accepts the proof.",
    ])
    if "schnorr" not in st.session_state:
        st.session_state["schnorr"] = {}
    state = st.session_state["schnorr"]
    step_indicator(["Commit", "Challenge", "Respond", "Verify"], state.get("step", 0) - 1 if state.get("step", 0) > 0 else 0)

    if st.button("⚙️  Setup: Generate Params & Keys", use_container_width=True):
        with st.spinner("Generating…"):
            params = Schnorr.generate_params(64)
            s, h = Schnorr.generate_keys(params["p"], params["q"], params["g"])
            state.update(params=params, s=s, h=h, step=1)
            st.session_state["schnorr"] = state

    if state.get("step", 0) >= 1:
        st.info(f"h = gˢ mod p = {state['h']}  (public)\n\ns = {state['s']}  (private — only Alice knows)")
        if st.button("Step 1 · Alice commits  (x = gʳ mod p)", use_container_width=True):
            r, x = Schnorr.prover_commit(state["params"]["p"], state["params"]["q"], state["params"]["g"])
            state.update(r=r, x=x, step=2); st.session_state["schnorr"] = state; st.rerun()
    if state.get("step", 0) >= 2:
        st.success(f"Commitment x = {state['x']}")
        if st.button("Step 2 · Verifier sends challenge c", use_container_width=True):
            c = Schnorr.generate_challenge(state["params"]["q"])
            state.update(c=c, step=3); st.session_state["schnorr"] = state; st.rerun()
    if state.get("step", 0) >= 3:
        st.success(f"Challenge c = {state['c']}")
        if st.button("Step 3 · Alice responds  (y = r + s·c mod q)", use_container_width=True):
            y = Schnorr.prover_respond(state["r"], state["s"], state["c"], state["params"]["q"])
            state.update(y=y, step=4); st.session_state["schnorr"] = state; st.rerun()
    if state.get("step", 0) >= 4:
        st.success(f"Response y = {state['y']}")
        if st.button("Step 4 · Verifier checks  gʸ = x · hᶜ mod p", use_container_width=True):
            p = state["params"]
            ok = Schnorr.verify(p["g"], state["y"], state["h"], state["c"], state["x"], p["p"])
            if ok: st.success("✓ PROOF VALID — Alice knows s without revealing it.")
            else:  st.error("✗ Proof invalid")
            state["step"] = 0; st.session_state["schnorr"] = state


# ─── FEIGE-FIAT-SHAMIR ───────────────────────────────────────────────────────
elif page == "Feige-Fiat-Shamir":
    st.markdown("Zero-knowledge identification based on **quadratic residues**.")
    howto([
        "Click <b>Generate Parameters</b> to set up n and the public/private keys.",
        "Walk through the four protocol steps in order.",
        "Step 4 verifies whether the prover successfully identified themselves.",
    ])
    K = 3
    if "ffs" not in st.session_state:
        st.session_state["ffs"] = {}
    state = st.session_state["ffs"]
    step_indicator(["Commit", "Challenge", "Respond", "Verify"], state.get("step", 0) - 1 if state.get("step", 0) > 0 else 0)

    if st.button("⚙️  Generate FFS Parameters", use_container_width=True):
        with st.spinner("Generating…"):
            n = FeigeFiatShamir.generate_params(64)
            v, s = FeigeFiatShamir.generate_keys(n, K)
            state.update(n=n, v=v, s=s, step=1); st.session_state["ffs"] = state

    if state.get("step", 0) >= 1:
        st.info(f"n = {state['n']}")
        st.code("\n".join(f"v{i+1} = {state['v'][i]}" for i in range(K)))
        if st.button("Step 1 · Prover commits  (x = r²)", use_container_width=True):
            r, x = FeigeFiatShamir.prover_commit(state["n"])
            state.update(r=r, x=x, step=2); st.session_state["ffs"] = state; st.rerun()
    if state.get("step", 0) >= 2:
        st.success(f"x = r² mod n = {state['x']}")
        if st.button("Step 2 · Verifier sends challenge bits", use_container_width=True):
            challenge = FeigeFiatShamir.generate_challenge(K)
            state.update(challenge=challenge, step=3); st.session_state["ffs"] = state; st.rerun()
    if state.get("step", 0) >= 3:
        st.success(f"Challenge bits: {state['challenge']}")
        if st.button("Step 3 · Prover sends response y", use_container_width=True):
            y = FeigeFiatShamir.prover_respond(state["r"], state["s"], state["challenge"], state["n"])
            state.update(y=y, step=4); st.session_state["ffs"] = state; st.rerun()
    if state.get("step", 0) >= 4:
        st.success(f"y = {state['y']}")
        if st.button("Step 4 · Verifier checks  y² = x · ∏vᵢᵇⁱ", use_container_width=True):
            ok = FeigeFiatShamir.verify(state["x"], state["y"], state["v"], state["challenge"], state["n"])
            if ok: st.success("✓ Identification ACCEPTED")
            else:  st.error("✗ Identification REJECTED")
            state["step"] = 0; st.session_state["ffs"] = state
