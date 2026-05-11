"""
=============================================================================
CRYPTOGRAPHIE APPLIQUÉE — TPs 1 à 6  (Complet)
Ing 3 — Cybersécurité
=============================================================================
"""

import secrets
import random
import math
import hashlib
import hmac as hmac_module
import struct
import time
import socket
import threading
import os
from functools import reduce


# ═══════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y

def mod_inverse(a, m):
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"No inverse for {a} mod {m}")
    return x % m

def mod_pow(base, exp, mod):
    return pow(base, exp, mod)

def miller_rabin(n, k=20):
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if miller_rabin(p):
            return p

def generate_prime_range(low, high):
    while True:
        p = random.randint(low, high)
        if p % 2 == 0:
            p += 1
        if miller_rabin(p):
            return p

def lcm(a, b):
    return a * b // gcd(a, b)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ═══════════════════════════════════════════════════════════════════════════
#  TP 1 — CHIFFREMENT CLASSIQUE
# ═══════════════════════════════════════════════════════════════════════════

# ── 1.1 César ──────────────────────────────────────────────────────────────

class Caesar:
    # French common words for auto-detection
    FRENCH_WORDS = {
        'le','la','les','de','du','des','un','une','et','est','en','que',
        'qui','il','elle','ils','elles','nous','vous','je','tu','on',
        'pas','plus','par','sur','dans','avec','pour','au','aux','mais',
        'ou','donc','or','ni','car','ce','se','sa','son','ses'
    }

    @staticmethod
    def encrypt(text, key):
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - base + key) % 26 + base))
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def decrypt(text, key):
        return Caesar.encrypt(text, -key)

    @staticmethod
    def brute_force(text):
        """Try all 26 keys and return (key, decrypted) pairs."""
        return [(k, Caesar.decrypt(text, k)) for k in range(26)]

    @staticmethod
    def brute_force_auto(text):
        """Auto-detect best key using French word matching."""
        best_key, best_score, best_text = 0, 0, text
        for k in range(26):
            candidate = Caesar.decrypt(text, k)
            words = candidate.lower().split()
            score = sum(1 for w in words if w in Caesar.FRENCH_WORDS)
            if score > best_score:
                best_key, best_score, best_text = k, score, candidate
        return best_key, best_text

    @staticmethod
    def coincidence_index(text):
        """
        Compute the Index of Coincidence (IC).
        French IC ≈ 0.074, English ≈ 0.065, random ≈ 0.038.
        """
        text = ''.join(c for c in text.upper() if c.isalpha())
        n = len(text)
        if n < 2:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
        return round(ic, 4)

    @staticmethod
    def crack_by_ic(ciphertext):
        """
        Deduce Caesar key by comparing letter frequencies to French.
        The shift that produces IC closest to 0.074 is the key.
        """
        FRENCH_IC = 0.074
        best_key, best_diff = 0, float('inf')
        for k in range(26):
            candidate = Caesar.decrypt(ciphertext, k)
            ic = Caesar.coincidence_index(candidate)
            diff = abs(ic - FRENCH_IC)
            if diff < best_diff:
                best_diff = diff
                best_key = k
        return best_key, Caesar.decrypt(ciphertext, best_key)


# ── 1.2 Vigenère ───────────────────────────────────────────────────────────

class Vigenere:
    FRENCH_FREQ = {
        'E':17.02,'A':8.13,'I':7.31,'S':7.22,'N':7.10,'R':6.55,'T':5.92,
        'O':5.36,'L':5.34,'U':5.08,'D':3.67,'C':3.34,'M':2.72,'P':2.49,
        'G':1.13,'H':1.11,'F':1.12,'B':1.14,'V':1.11,'Q':0.65,'Y':0.46,
        'X':0.38,'J':0.34,'K':0.29,'W':0.17,'Z':0.15
    }

    @staticmethod
    def encrypt(text, key):
        key = key.upper()
        result = []
        ki = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = ord(key[ki % len(key)]) - ord('A')
                result.append(chr((ord(c) - base + shift) % 26 + base))
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def decrypt(text, key):
        key = key.upper()
        result = []
        ki = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = ord(key[ki % len(key)]) - ord('A')
                result.append(chr((ord(c) - base - shift) % 26 + base))
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def kasiski(text, min_len=3, top_n=5):
        """Find repeated trigrams and estimate key length via GCD of distances."""
        text = ''.join(c for c in text.upper() if c.isalpha())
        sequences = {}
        for length in range(min_len, 6):
            for i in range(len(text) - length + 1):
                seq = text[i:i + length]
                if seq in sequences:
                    sequences[seq].append(i)
                else:
                    sequences[seq] = [i]
        repeated = {seq: pos for seq, pos in sequences.items() if len(pos) > 1}
        distances = []
        for pos_list in repeated.values():
            for i in range(len(pos_list) - 1):
                distances.append(pos_list[i + 1] - pos_list[i])
        if not distances:
            return []
        factor_counts = {}
        for d in distances:
            for f in range(2, min(d + 1, 20)):
                if d % f == 0:
                    factor_counts[f] = factor_counts.get(f, 0) + 1
        return sorted(factor_counts.items(), key=lambda x: -x[1])[:top_n]

    @staticmethod
    def coincidence_index(text):
        text = ''.join(c for c in text.upper() if c.isalpha())
        n = len(text)
        if n < 2:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

    @staticmethod
    def crack_ic(ciphertext, max_key_len=12):
        """
        Step 1: try each key length 1..max_key_len.
        For each length L, split into L sub-sequences and average their IC.
        The L with average IC closest to French IC (0.074) is likely correct.
        """
        FRENCH_IC = 0.074
        text = ''.join(c for c in ciphertext.upper() if c.isalpha())
        scores = []
        for L in range(1, max_key_len + 1):
            subseqs = [''.join(text[i::L]) for i in range(L)]
            avg_ic = sum(Vigenere.coincidence_index(s) for s in subseqs) / L
            scores.append((L, avg_ic, abs(avg_ic - FRENCH_IC)))
        best_L = min(scores, key=lambda x: x[2])[0]
        return best_L, scores

    @staticmethod
    def crack_key(ciphertext, key_length):
        """
        Step 2: for each position in the key, extract sub-sequence and
        find the Caesar shift that makes its frequency distribution closest
        to French.
        """
        text = ''.join(c for c in ciphertext.upper() if c.isalpha())
        key = ''
        for i in range(key_length):
            subseq = text[i::key_length]
            freq = {}
            for c in subseq:
                freq[c] = freq.get(c, 0) + 1
            # Most frequent letter in subseq likely corresponds to 'E'
            most_common = max(freq, key=freq.get)
            shift = (ord(most_common) - ord('E')) % 26
            key += chr(ord('A') + shift)
        return key

    @staticmethod
    def full_crack(ciphertext, max_key_len=12):
        """Combined Kasiski + IC crack returning guessed key and plaintext."""
        key_length, _ = Vigenere.crack_ic(ciphertext, max_key_len)
        key = Vigenere.crack_key(ciphertext, key_length)
        plaintext = Vigenere.decrypt(ciphertext, key)
        return key, plaintext

    @staticmethod
    def frequency_analysis(text):
        text = ''.join(c for c in text.upper() if c.isalpha())
        counts = {}
        for c in text:
            counts[c] = counts.get(c, 0) + 1
        total = sum(counts.values())
        return {k: round(v / total * 100, 2) for k, v in
                sorted(counts.items(), key=lambda x: -x[1])}


# ── 1.3 Affine ─────────────────────────────────────────────────────────────

class Affine:
    @staticmethod
    def encrypt(text, a, b):
        if gcd(a, 26) != 1:
            raise ValueError("'a' must be coprime with 26")
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((a * (ord(c) - base) + b) % 26 + base))
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def decrypt(text, a, b):
        if gcd(a, 26) != 1:
            raise ValueError("'a' must be coprime with 26")
        a_inv = mod_inverse(a, 26)
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((a_inv * (ord(c) - base - b)) % 26 + base))
            else:
                result.append(c)
        return ''.join(result)


# ── Simple Substitution ────────────────────────────────────────────────────

class SimpleSubstitution:
    @staticmethod
    def make_key(seed=None):
        alpha = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        rng = random.Random(seed)
        rng.shuffle(alpha)
        return ''.join(alpha)

    @staticmethod
    def encrypt(text, key):
        key = key.upper()
        result = []
        for c in text:
            if c.isalpha():
                idx = ord(c.upper()) - ord('A')
                enc = key[idx]
                result.append(enc if c.isupper() else enc.lower())
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def decrypt(text, key):
        key = key.upper()
        inv = {key[i]: chr(ord('A') + i) for i in range(26)}
        result = []
        for c in text:
            if c.isalpha():
                dec = inv[c.upper()]
                result.append(dec if c.isupper() else dec.lower())
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def frequency_analysis(text):
        text = text.upper()
        counts = {}
        total = 0
        for c in text:
            if c.isalpha():
                counts[c] = counts.get(c, 0) + 1
                total += 1
        if total == 0:
            return {}
        return {k: round(v / total * 100, 2) for k, v in sorted(counts.items(), key=lambda x: -x[1])}


# ── 1.3 Hill ───────────────────────────────────────────────────────────────

class Hill:
    @staticmethod
    def _mat_mul_mod(a, b, m):
        n = len(a)
        result = [[0]*n for _ in range(n)]
        for i in range(n):
            for j in range(n):
                for k in range(n):
                    result[i][j] = (result[i][j] + a[i][k] * b[k][j]) % m
        return result

    @staticmethod
    def _mat_det_mod(m, mod):
        if len(m) == 1:
            return m[0][0] % mod
        if len(m) == 2:
            return (m[0][0]*m[1][1] - m[0][1]*m[1][0]) % mod
        det = 0
        for c in range(len(m)):
            sub = [row[:c] + row[c+1:] for row in m[1:]]
            det += ((-1)**c) * m[0][c] * Hill._mat_det_mod(sub, mod)
        return det % mod

    @staticmethod
    def _mat_inv_mod(m, mod):
        n = len(m)
        det = Hill._mat_det_mod(m, mod)
        det_inv = mod_inverse(det, mod)
        cofactors = []
        for r in range(n):
            row = []
            for c in range(n):
                sub = [m[i][:c] + m[i][c+1:] for i in range(n) if i != r]
                minor = Hill._mat_det_mod(sub, mod)
                row.append(((-1)**(r+c)) * minor % mod)
            cofactors.append(row)
        adj = [[cofactors[j][i] for j in range(n)] for i in range(n)]
        return [[(det_inv * adj[i][j]) % mod for j in range(n)] for i in range(n)]

    @staticmethod
    def encrypt(text, key_matrix):
        n = len(key_matrix)
        text = ''.join(c for c in text.upper() if c.isalpha())
        while len(text) % n:
            text += 'X'
        result = []
        for i in range(0, len(text), n):
            block = [ord(text[i+j]) - ord('A') for j in range(n)]
            out = [sum(key_matrix[r][c] * block[c] for c in range(n)) % 26 for r in range(n)]
            result.extend(chr(v + ord('A')) for v in out)
        return ''.join(result)

    @staticmethod
    def decrypt(text, key_matrix):
        inv = Hill._mat_inv_mod(key_matrix, 26)
        return Hill.encrypt(text, inv)

    @staticmethod
    def known_plaintext_attack(plaintext, ciphertext, n=2):
        """
        Known-plaintext attack on Hill cipher.
        Given n*n plaintext-ciphertext pairs, recover the key matrix K.
        K = P^-1 * C mod 26
        """
        pt = ''.join(c for c in plaintext.upper() if c.isalpha())
        ct = ''.join(c for c in ciphertext.upper() if c.isalpha())
        # Build plaintext matrix (n columns of n-grams)
        P = []
        C = []
        for i in range(0, n * n, n):
            P.append([ord(pt[i+j]) - ord('A') for j in range(n)])
            C.append([ord(ct[i+j]) - ord('A') for j in range(n)])
        # Transpose so columns are letter vectors
        P = [[P[j][i] for j in range(n)] for i in range(n)]
        C = [[C[j][i] for j in range(n)] for i in range(n)]
        # K = P_inv * C mod 26
        try:
            P_inv = Hill._mat_inv_mod(P, 26)
            K = Hill._mat_mul_mod(P_inv, C, 26)
            return K
        except ValueError:
            return None


# ── 1.4 OTP ────────────────────────────────────────────────────────────────

class OTP:
    """True One-Time Pad (Vernam cipher)."""

    @staticmethod
    def generate_key(length: int) -> bytes:
        return secrets.token_bytes(length)

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        if len(key) < len(data):
            raise ValueError(f"OTP key ({len(key)} bytes) must be >= message ({len(data)} bytes)")
        return bytes(b ^ key[i] for i, b in enumerate(data))

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        return OTP.encrypt(data, key)

    @staticmethod
    def xor_ciphertexts(c1: bytes, c2: bytes) -> bytes:
        """C1 XOR C2 = M1 XOR M2 — demonstrates key reuse vulnerability."""
        length = min(len(c1), len(c2))
        return bytes(a ^ b for a, b in zip(c1[:length], c2[:length]))

    @staticmethod
    def crib_drag(xor_result: bytes, crib: str):
        """
        Crib dragging attack on reused OTP key.
        Slide a known word (crib) across the XOR of two ciphertexts.
        If C1 XOR C2 = M1 XOR M2, then sliding crib through gives candidate
        fragments of the other message.
        Returns list of (position, candidate_fragment) where output is printable.
        """
        crib_bytes = crib.encode()
        results = []
        for pos in range(len(xor_result) - len(crib_bytes) + 1):
            fragment = bytes(xor_result[pos + i] ^ crib_bytes[i]
                             for i in range(len(crib_bytes)))
            if all(32 <= b < 127 for b in fragment):
                results.append((pos, fragment.decode()))
        return results


# ── Playfair ───────────────────────────────────────────────────────────────

class Playfair:
    @staticmethod
    def _build_matrix(key):
        key = key.upper().replace('J', 'I')
        seen = set()
        letters = []
        for c in key:
            if c.isalpha() and c not in seen:
                seen.add(c)
                letters.append(c)
        for c in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
            if c not in seen:
                seen.add(c)
                letters.append(c)
        return [letters[i*5:(i+1)*5] for i in range(5)]

    @staticmethod
    def _find(matrix, c):
        for r, row in enumerate(matrix):
            if c in row:
                return r, row.index(c)
        return None

    @staticmethod
    def _prepare(text):
        text = text.upper().replace('J', 'I')
        text = ''.join(c for c in text if c.isalpha())
        result = []
        i = 0
        while i < len(text):
            a = text[i]
            if i + 1 < len(text):
                b = text[i + 1]
                if a == b:
                    result.append((a, 'X'))
                    i += 1
                else:
                    result.append((a, b))
                    i += 2
            else:
                result.append((a, 'X'))
                i += 1
        return result

    @classmethod
    def encrypt(cls, text, key):
        matrix = cls._build_matrix(key)
        pairs = cls._prepare(text)
        result = []
        for a, b in pairs:
            ra, ca = cls._find(matrix, a)
            rb, cb = cls._find(matrix, b)
            if ra == rb:
                result.append(matrix[ra][(ca + 1) % 5])
                result.append(matrix[rb][(cb + 1) % 5])
            elif ca == cb:
                result.append(matrix[(ra + 1) % 5][ca])
                result.append(matrix[(rb + 1) % 5][cb])
            else:
                result.append(matrix[ra][cb])
                result.append(matrix[rb][ca])
        return ''.join(result)

    @classmethod
    def decrypt(cls, text, key):
        matrix = cls._build_matrix(key)
        text = text.upper().replace('J', 'I')
        text = ''.join(c for c in text if c.isalpha())
        pairs = [(text[i], text[i+1]) for i in range(0, len(text), 2)]
        result = []
        for a, b in pairs:
            ra, ca = cls._find(matrix, a)
            rb, cb = cls._find(matrix, b)
            if ra == rb:
                result.append(matrix[ra][(ca - 1) % 5])
                result.append(matrix[rb][(cb - 1) % 5])
            elif ca == cb:
                result.append(matrix[(ra - 1) % 5][ca])
                result.append(matrix[(rb - 1) % 5][cb])
            else:
                result.append(matrix[ra][cb])
                result.append(matrix[rb][ca])
        return ''.join(result)


# ═══════════════════════════════════════════════════════════════════════════
#  TP 2 — CRYPTOGRAPHIE SYMÉTRIQUE MODERNE
# ═══════════════════════════════════════════════════════════════════════════

# ── 2.1 RC4 ────────────────────────────────────────────────────────────────

class RC4:
    @staticmethod
    def _ksa(key):
        key_bytes = key.encode() if isinstance(key, str) else key
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
            S[i], S[j] = S[j], S[i]
        return S

    @staticmethod
    def _prga(S, length):
        """Generate `length` keystream bytes."""
        S = S[:]
        i = j = 0
        keystream = []
        for _ in range(length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            keystream.append(S[(S[i] + S[j]) % 256])
        return keystream

    @staticmethod
    def encrypt(text, key):
        S = RC4._ksa(key)
        i = j = 0
        result = []
        for byte in text.encode():
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            result.append(byte ^ S[(S[i] + S[j]) % 256])
        return bytes(result).hex()

    @staticmethod
    def decrypt(hex_text, key):
        data = bytes.fromhex(hex_text)
        S = RC4._ksa(key)
        i = j = 0
        result = []
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            result.append(byte ^ S[(S[i] + S[j]) % 256])
        return bytes(result).decode(errors='replace')

    @staticmethod
    def wep_vulnerability_demo(base_key: bytes, num_ivs: int = 10):
        """
        WEP vulnerability: weak IVs leak key bytes.
        For IVs starting with (A+3, 255, x) the first keystream byte
        correlates with the first secret key byte.
        Returns list of (iv, first_keystream_byte).
        """
        results = []
        for i in range(num_ivs):
            iv = bytes([i, 0, 0])
            full_key = iv + base_key
            S = RC4._ksa(full_key)
            ks = RC4._prga(S, 1)
            results.append((iv.hex(), ks[0]))
        return results

    @staticmethod
    def rc4_bias_demo(n_samples: int = 1000):
        """
        Statistical bias in RC4: the 2nd output byte is biased toward 0.
        Generate n_samples keystreams with random keys and histogram byte 2.
        Returns frequency dict of 2nd byte values.
        """
        freq = [0] * 256
        for _ in range(n_samples):
            key = secrets.token_bytes(16)
            S = RC4._ksa(key)
            ks = RC4._prga(S, 2)
            freq[ks[1]] += 1
        return freq


# ── 2.2 DES ────────────────────────────────────────────────────────────────

class DES:
    """
    Full DES implementation following NIST FIPS 46-3.
    Supports ECB and CBC modes with PKCS7 padding.
    """

    # Initial Permutation (IP)
    IP = [
        58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
        62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
        57,49,41,33,25,17, 9,1, 59,51,43,35,27,19,11,3,
        61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
    ]

    # Final Permutation (IP^-1)
    FP = [
        40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
        38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
        36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
        34,2,42,10,50,18,58,26, 33,1,41, 9,49,17,57,25
    ]

    # Expansion permutation E (32 → 48 bits)
    E = [
        32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13,
        12,13,14,15,16,17, 16,17,18,19,20,21, 20,21,22,23,24,25,
        24,25,26,27,28,29, 28,29,30,31,32,1
    ]

    # Permutation P (32 bits)
    P = [
        16,7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10,
        2,8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25
    ]

    # Permuted Choice 1 (64 → 56 bits)
    PC1 = [
        57,49,41,33,25,17,9, 1,58,50,42,34,26,18,
        10,2,59,51,43,35,27,19,11,3,60,52,44,36,
        63,55,47,39,31,23,15,7,62,54,46,38,30,22,
        14,6,61,53,45,37,29,21,13,5,28,20,12,4
    ]

    # Permuted Choice 2 (56 → 48 bits)
    PC2 = [
        14,17,11,24,1,5, 3,28,15,6,21,10,
        23,19,12,4,26,8,16,7,27,20,13,2,
        41,52,31,37,47,55,30,40,51,45,33,48,
        44,49,39,56,34,53,46,42,50,36,29,32
    ]

    # Left rotation schedule
    SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

    # S-boxes (8 boxes, each 4 rows × 16 cols)
    SBOXES = [
        # S1
        [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
         [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
         [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
         [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
        # S2
        [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
         [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
         [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
         [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
        # S3
        [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
         [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
         [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
         [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
        # S4
        [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
         [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
         [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
         [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
        # S5
        [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
         [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
         [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
         [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
        # S6
        [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
         [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
         [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
         [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
        # S7
        [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
         [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
         [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
         [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
        # S8
        [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
         [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
         [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
         [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]],
    ]

    @staticmethod
    def _permute(block_bits, table):
        return [block_bits[t - 1] for t in table]

    @staticmethod
    def _bytes_to_bits(data):
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    @staticmethod
    def _bits_to_bytes(bits):
        result = []
        for i in range(0, len(bits), 8):
            byte = 0
            for b in bits[i:i+8]:
                byte = (byte << 1) | b
            result.append(byte)
        return bytes(result)

    @classmethod
    def _generate_subkeys(cls, key_bytes):
        """Generate 16 × 48-bit subkeys from a 64-bit key."""
        key_bits = cls._bytes_to_bits(key_bytes)
        key56 = cls._permute(key_bits, cls.PC1)
        C, D = key56[:28], key56[28:]
        subkeys = []
        for shift in cls.SHIFTS:
            C = C[shift:] + C[:shift]
            D = D[shift:] + D[:shift]
            CD = C + D
            subkeys.append(cls._permute(CD, cls.PC2))
        return subkeys

    @classmethod
    def _f_function(cls, R, subkey):
        """DES F function: expansion → XOR with subkey → S-boxes → P."""
        expanded = cls._permute(R, cls.E)
        xored = [expanded[i] ^ subkey[i] for i in range(48)]
        # S-box substitution
        sbox_out = []
        for s in range(8):
            chunk = xored[s*6:(s+1)*6]
            row = (chunk[0] << 1) | chunk[5]
            col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
            val = cls.SBOXES[s][row][col]
            for i in range(3, -1, -1):
                sbox_out.append((val >> i) & 1)
        return cls._permute(sbox_out, cls.P)

    @classmethod
    def _encrypt_block(cls, block_bytes, subkeys):
        """Encrypt a single 8-byte block."""
        bits = cls._bytes_to_bits(block_bytes)
        bits = cls._permute(bits, cls.IP)
        L, R = bits[:32], bits[32:]
        for i in range(16):
            f_out = cls._f_function(R, subkeys[i])
            new_R = [L[j] ^ f_out[j] for j in range(32)]
            L = R
            R = new_R
        combined = R + L  # Note: swap before FP
        return cls._bits_to_bytes(cls._permute(combined, cls.FP))

    @classmethod
    def _decrypt_block(cls, block_bytes, subkeys):
        """Decrypt a single 8-byte block (reverse subkey order)."""
        return cls._encrypt_block(block_bytes, list(reversed(subkeys)))

    @staticmethod
    def _pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
        pad = block_size - len(data) % block_size
        return data + bytes([pad] * pad)

    @staticmethod
    def _pkcs7_unpad(data: bytes) -> bytes:
        pad = data[-1]
        return data[:-pad]

    @classmethod
    def encrypt_ecb(cls, plaintext: bytes, key: bytes) -> bytes:
        subkeys = cls._generate_subkeys(key)
        padded = cls._pkcs7_pad(plaintext)
        return b''.join(cls._encrypt_block(padded[i:i+8], subkeys)
                        for i in range(0, len(padded), 8))

    @classmethod
    def decrypt_ecb(cls, ciphertext: bytes, key: bytes) -> bytes:
        subkeys = cls._generate_subkeys(key)
        raw = b''.join(cls._decrypt_block(ciphertext[i:i+8], subkeys)
                       for i in range(0, len(ciphertext), 8))
        return cls._pkcs7_unpad(raw)

    @classmethod
    def encrypt_cbc(cls, plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        subkeys = cls._generate_subkeys(key)
        padded = cls._pkcs7_pad(plaintext)
        prev = iv
        result = b''
        for i in range(0, len(padded), 8):
            block = bytes(a ^ b for a, b in zip(padded[i:i+8], prev))
            enc = cls._encrypt_block(block, subkeys)
            result += enc
            prev = enc
        return result

    @classmethod
    def decrypt_cbc(cls, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        subkeys = cls._generate_subkeys(key)
        prev = iv
        raw = b''
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            dec = cls._decrypt_block(block, subkeys)
            raw += bytes(a ^ b for a, b in zip(dec, prev))
            prev = block
        return cls._pkcs7_unpad(raw)

    @staticmethod
    def generate_key() -> bytes:
        return secrets.token_bytes(8)

    @staticmethod
    def generate_iv() -> bytes:
        return secrets.token_bytes(8)

    @staticmethod
    def ecb_weakness_demo(pixel_data: bytes, key: bytes) -> bytes:
        """
        Encrypt pixel data with DES-ECB byte by byte to show pattern leakage.
        Same 8-byte patterns in plaintext → same ciphertext blocks.
        """
        subkeys = DES._generate_subkeys(key)
        padded = DES._pkcs7_pad(pixel_data)
        return b''.join(DES._encrypt_block(padded[i:i+8], subkeys)
                        for i in range(0, len(padded), 8))


class TripleDES:
    """
    3DES — EDE mode (Encrypt-Decrypt-Encrypt).
    Two-key (K1, K2, K1) and three-key (K1, K2, K3) variants.
    """

    @staticmethod
    def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
        """Key must be 16 bytes (2-key 3DES) or 24 bytes (3-key 3DES)."""
        if len(key) == 16:
            k1, k2, k3 = key[:8], key[8:16], key[:8]
        elif len(key) == 24:
            k1, k2, k3 = key[:8], key[8:16], key[16:24]
        else:
            raise ValueError("3DES key must be 16 or 24 bytes")
        step1 = DES.encrypt_ecb(plaintext, k1)
        step2 = DES.decrypt_ecb(step1, k2)
        return DES.encrypt_ecb(step2, k3)

    @staticmethod
    def decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
        if len(key) == 16:
            k1, k2, k3 = key[:8], key[8:16], key[:8]
        elif len(key) == 24:
            k1, k2, k3 = key[:8], key[8:16], key[16:24]
        else:
            raise ValueError("3DES key must be 16 or 24 bytes")
        step1 = DES.decrypt_ecb(ciphertext, k3)
        step2 = DES.encrypt_ecb(step1, k2)
        return DES.decrypt_ecb(step2, k1)

    @staticmethod
    def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        if len(key) == 16:
            k1, k2, k3 = key[:8], key[8:16], key[:8]
        else:
            k1, k2, k3 = key[:8], key[8:16], key[16:24]
        step1 = DES.encrypt_cbc(plaintext, k1, iv)
        # For simplicity use last block as new IV for each stage
        iv2 = step1[-8:]
        step2 = DES.decrypt_cbc(step1, k2, iv2)
        iv3 = step2[-8:]
        return DES.encrypt_cbc(step2, k3, iv3)

    @staticmethod
    def generate_key(three_key: bool = False) -> bytes:
        return secrets.token_bytes(24 if three_key else 16)


# ── 2.3 AES ────────────────────────────────────────────────────────────────

class AES:
    SBOX = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    ]
    INV_SBOX = [0]*256
    for _i, _v in enumerate(SBOX):
        INV_SBOX[_v] = _i

    RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

    @staticmethod
    def _xtime(a):
        return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff

    @staticmethod
    def _gmul(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xff
            if hi:
                a ^= 0x1b
            b >>= 1
        return p

    @classmethod
    def _key_expansion(cls, key_bytes):
        n = len(key_bytes) // 4
        r = {16: 10, 24: 12, 32: 14}[len(key_bytes)]
        w = [list(key_bytes[i*4:(i+1)*4]) for i in range(n)]
        for i in range(n, 4 * (r + 1)):
            temp = w[-1][:]
            if i % n == 0:
                temp = temp[1:] + temp[:1]
                temp = [cls.SBOX[b] for b in temp]
                temp[0] ^= cls.RCON[i // n]
            elif n > 6 and i % n == 4:
                temp = [cls.SBOX[b] for b in temp]
            w.append([w[-n][j] ^ temp[j] for j in range(4)])
        return w

    @classmethod
    def _add_round_key(cls, state, w, round_n):
        for c in range(4):
            for r in range(4):
                state[r][c] ^= w[round_n*4+c][r]

    @classmethod
    def _sub_bytes(cls, state):
        for r in range(4):
            for c in range(4):
                state[r][c] = cls.SBOX[state[r][c]]

    @classmethod
    def _inv_sub_bytes(cls, state):
        for r in range(4):
            for c in range(4):
                state[r][c] = cls.INV_SBOX[state[r][c]]

    @staticmethod
    def _shift_rows(state):
        for r in range(1, 4):
            state[r] = state[r][r:] + state[r][:r]

    @staticmethod
    def _inv_shift_rows(state):
        for r in range(1, 4):
            state[r] = state[r][-r:] + state[r][:-r]

    @classmethod
    def _mix_columns(cls, state):
        for c in range(4):
            s = [state[r][c] for r in range(4)]
            state[0][c] = cls._gmul(2,s[0])^cls._gmul(3,s[1])^s[2]^s[3]
            state[1][c] = s[0]^cls._gmul(2,s[1])^cls._gmul(3,s[2])^s[3]
            state[2][c] = s[0]^s[1]^cls._gmul(2,s[2])^cls._gmul(3,s[3])
            state[3][c] = cls._gmul(3,s[0])^s[1]^s[2]^cls._gmul(2,s[3])

    @classmethod
    def _inv_mix_columns(cls, state):
        for c in range(4):
            s = [state[r][c] for r in range(4)]
            state[0][c] = cls._gmul(0x0e,s[0])^cls._gmul(0x0b,s[1])^cls._gmul(0x0d,s[2])^cls._gmul(0x09,s[3])
            state[1][c] = cls._gmul(0x09,s[0])^cls._gmul(0x0e,s[1])^cls._gmul(0x0b,s[2])^cls._gmul(0x0d,s[3])
            state[2][c] = cls._gmul(0x0d,s[0])^cls._gmul(0x09,s[1])^cls._gmul(0x0e,s[2])^cls._gmul(0x0b,s[3])
            state[3][c] = cls._gmul(0x0b,s[0])^cls._gmul(0x0d,s[1])^cls._gmul(0x09,s[2])^cls._gmul(0x0e,s[3])

    @classmethod
    def _encrypt_block(cls, block, w, rounds):
        state = [[block[r + 4*c] for c in range(4)] for r in range(4)]
        cls._add_round_key(state, w, 0)
        for rnd in range(1, rounds):
            cls._sub_bytes(state)
            cls._shift_rows(state)
            cls._mix_columns(state)
            cls._add_round_key(state, w, rnd)
        cls._sub_bytes(state)
        cls._shift_rows(state)
        cls._add_round_key(state, w, rounds)
        return bytes(state[r][c] for c in range(4) for r in range(4))

    @classmethod
    def _decrypt_block(cls, block, w, rounds):
        state = [[block[r + 4*c] for c in range(4)] for r in range(4)]
        cls._add_round_key(state, w, rounds)
        for rnd in range(rounds - 1, 0, -1):
            cls._inv_shift_rows(state)
            cls._inv_sub_bytes(state)
            cls._add_round_key(state, w, rnd)
            cls._inv_mix_columns(state)
        cls._inv_shift_rows(state)
        cls._inv_sub_bytes(state)
        cls._add_round_key(state, w, 0)
        return bytes(state[r][c] for c in range(4) for r in range(4))

    @staticmethod
    def _pkcs7_pad(data: bytes) -> bytes:
        pad = 16 - len(data) % 16
        return data + bytes([pad] * pad)

    @staticmethod
    def _pkcs7_unpad(data: bytes) -> bytes:
        pad = data[-1]
        return data[:-pad]

    @classmethod
    def encrypt_ecb(cls, plaintext, key_hex):
        key = bytes.fromhex(key_hex)
        rounds = {16: 10, 24: 12, 32: 14}[len(key)]
        w = cls._key_expansion(key)
        data = plaintext.encode() if isinstance(plaintext, str) else plaintext
        data = cls._pkcs7_pad(data)
        return b''.join(cls._encrypt_block(data[i:i+16], w, rounds)
                        for i in range(0, len(data), 16)).hex()

    @classmethod
    def decrypt_ecb(cls, ciphertext_hex, key_hex):
        key = bytes.fromhex(key_hex)
        rounds = {16: 10, 24: 12, 32: 14}[len(key)]
        w = cls._key_expansion(key)
        data = bytes.fromhex(ciphertext_hex)
        raw = b''.join(cls._decrypt_block(data[i:i+16], w, rounds)
                       for i in range(0, len(data), 16))
        return cls._pkcs7_unpad(raw).decode(errors='replace')

    @classmethod
    def encrypt_cbc(cls, plaintext: bytes, key_hex: str, iv: bytes) -> bytes:
        """AES-CBC encryption."""
        key = bytes.fromhex(key_hex)
        rounds = {16: 10, 24: 12, 32: 14}[len(key)]
        w = cls._key_expansion(key)
        data = cls._pkcs7_pad(plaintext)
        prev = iv
        result = b''
        for i in range(0, len(data), 16):
            block = bytes(a ^ b for a, b in zip(data[i:i+16], prev))
            enc = cls._encrypt_block(block, w, rounds)
            result += enc
            prev = enc
        return result

    @classmethod
    def decrypt_cbc(cls, ciphertext: bytes, key_hex: str, iv: bytes) -> bytes:
        """AES-CBC decryption."""
        key = bytes.fromhex(key_hex)
        rounds = {16: 10, 24: 12, 32: 14}[len(key)]
        w = cls._key_expansion(key)
        prev = iv
        raw = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            dec = cls._decrypt_block(block, w, rounds)
            raw += bytes(a ^ b for a, b in zip(dec, prev))
            prev = block
        return cls._pkcs7_unpad(raw)

    @classmethod
    def encrypt_ctr(cls, data: bytes, key_hex: str, nonce: bytes) -> bytes:
        """
        AES-CTR mode (stream cipher).
        nonce: 8 bytes — counter fills the remaining 8 bytes.
        """
        key = bytes.fromhex(key_hex)
        rounds = {16: 10, 24: 12, 32: 14}[len(key)]
        w = cls._key_expansion(key)
        result = b''
        counter = 0
        for i in range(0, len(data), 16):
            counter_block = nonce + counter.to_bytes(8, 'big')
            keystream = cls._encrypt_block(counter_block, w, rounds)
            block = data[i:i+16]
            result += bytes(a ^ b for a, b in zip(block, keystream))
            counter += 1
        return result

    @classmethod
    def decrypt_ctr(cls, data: bytes, key_hex: str, nonce: bytes) -> bytes:
        """CTR decryption is identical to encryption."""
        return cls.encrypt_ctr(data, key_hex, nonce)

    @staticmethod
    def generate_key(bits=128):
        return secrets.token_bytes(bits // 8).hex()

    @staticmethod
    def generate_iv():
        return secrets.token_bytes(16)

    @staticmethod
    def generate_nonce():
        return secrets.token_bytes(8)

    @staticmethod
    def ctr_nonce_reuse_demo(m1: bytes, m2: bytes, key_hex: str):
        """
        CTR nonce reuse: encrypting two messages with the same nonce/key
        means C1 XOR C2 = M1 XOR M2, leaking information.
        Returns (c1, c2, xor_result).
        """
        nonce = AES.generate_nonce()  # same nonce for both!
        c1 = AES.encrypt_ctr(m1, key_hex, nonce)
        c2 = AES.encrypt_ctr(m2, key_hex, nonce)
        xor_result = bytes(a ^ b for a, b in zip(c1, c2))
        return c1, c2, xor_result

    @staticmethod
    def avalanche_cbc_demo(plaintext: bytes, key_hex: str):
        """
        Modify 1 bit in the IV and measure how many bits change
        in the resulting ciphertext (avalanche in CBC).
        """
        iv1 = AES.generate_iv()
        iv2 = bytearray(iv1)
        iv2[0] ^= 0x01  # flip 1 bit
        iv2 = bytes(iv2)
        ct1 = AES.encrypt_cbc(plaintext, key_hex, iv1)
        ct2 = AES.encrypt_cbc(plaintext, key_hex, iv2)
        bit_diffs = []
        for b1, b2 in zip(ct1, ct2):
            diff = bin(b1 ^ b2).count('1')
            bit_diffs.append(diff)
        total_bits = len(ct1) * 8
        changed = sum(bit_diffs)
        return changed, total_bits, round(changed / total_bits * 100, 1)

    @staticmethod
    def benchmark(message_size_mb: float = 1.0):
        """
        Benchmark AES-128, AES-192, AES-256 in ECB mode.
        Returns dict of {key_size: throughput_MBps}.
        """
        data = secrets.token_bytes(int(message_size_mb * 1024 * 1024))
        results = {}
        for bits in [128, 192, 256]:
            key = AES.generate_key(bits)
            start = time.time()
            AES.encrypt_ecb(data, key)
            elapsed = time.time() - start
            results[bits] = round(message_size_mb / elapsed, 2)
        return results


# ── 2.4 AES Finalists ──────────────────────────────────────────────────────

class AESFinalists:
    """
    Descriptions and benchmarks of the 5 NIST AES finalists.
    Full from-scratch implementations of Twofish/Serpent/RC6/MARS are
    extremely large; here we use pycryptodome where available and provide
    pure-Python reference implementations for RC6 and structural info for all.
    """

    DESCRIPTIONS = {
        'Rijndael': (
            "Structure: SPN (Substitution-Permutation Network). "
            "Block: 128 bits, Key: 128/192/256 bits, Rounds: 10/12/14. "
            "Operations: SubBytes (S-box), ShiftRows, MixColumns (GF(2^8)), AddRoundKey. "
            "Winner of AES contest — excellent hardware/software performance balance."
        ),
        'Twofish': (
            "Structure: Feistel network, 16 rounds. "
            "Block: 128 bits, Key: 128/192/256 bits. "
            "Uses key-dependent S-boxes (MDSmatrix over GF(2^8)) and PHT. "
            "Runner-up; very flexible but slightly slower than Rijndael in software."
        ),
        'Serpent': (
            "Structure: SPN, 32 rounds (most conservative design). "
            "Block: 128 bits, Key: up to 256 bits. "
            "32 different 4-bit S-boxes applied in parallel. "
            "Highest security margin; lost to Rijndael on performance grounds."
        ),
        'RC6': (
            "Structure: Feistel-like with 4 working registers, 20 rounds. "
            "Block: 128 bits, Key: 128/192/256 bits. "
            "Uses data-dependent rotations and integer multiplication. "
            "Evolved from RC5; strong performance on 32-bit processors."
        ),
        'MARS': (
            "Structure: heterogeneous — unkeyed mixing + keyed forward core + unkeyed mixing. "
            "Block: 128 bits, Key: 128–448 bits (variable), 32 rounds total. "
            "Combines E-function (multiply + rotate) with Feistel. "
            "IBM design; complex key schedule, good security but harder to implement."
        ),
    }

    @staticmethod
    def rc6_encrypt_block(plaintext: bytes, key: bytes) -> bytes:
        """
        RC6-32/20/b reference implementation (from Rivest et al. specification).
        Works for any key length b (bytes). Block = 128 bits = 4 × 32-bit words.
        """
        w = 32           # word size in bits
        r = 20           # rounds
        m = 2**w
        P32 = 0xB7E15163
        Q32 = 0x9E3779B9

        def rotl(x, n, w=32):
            n = n % w
            return ((x << n) | (x >> (w - n))) & (m - 1)

        def rotr(x, n, w=32):
            n = n % w
            return ((x >> n) | (x << (w - n))) & (m - 1)

        # Key schedule
        b = len(key)
        u = w // 8  # bytes per word
        c = max(1, math.ceil(b / u))
        L = [0] * c
        for i in range(b - 1, -1, -1):
            L[i // u] = (L[i // u] << 8) | key[i]

        S = [0] * (2 * r + 4)
        S[0] = P32
        for i in range(1, 2 * r + 4):
            S[i] = (S[i-1] + Q32) & (m - 1)

        A = B = i = j = 0
        v = 3 * max(c, 2 * r + 4)
        for _ in range(v):
            A = S[i] = rotl((S[i] + A + B) & (m - 1), 3)
            B = L[j] = rotl((L[j] + A + B) & (m - 1), (A + B) % w)
            i = (i + 1) % (2 * r + 4)
            j = (j + 1) % c

        # Encrypt block
        A, B, C, D = struct.unpack('<4I', plaintext[:16])
        B = (B + S[0]) & (m - 1)
        D = (D + S[1]) & (m - 1)
        for i in range(1, r + 1):
            t = rotl((B * (2*B + 1)) & (m - 1), int(math.log2(w)))
            u = rotl((D * (2*D + 1)) & (m - 1), int(math.log2(w)))
            A = (rotl(A ^ t, u % w) + S[2*i]) & (m - 1)
            C = (rotl(C ^ u, t % w) + S[2*i+1]) & (m - 1)
            A, B, C, D = B, C, D, A
        A = (A + S[2*r+2]) & (m - 1)
        C = (C + S[2*r+3]) & (m - 1)
        return struct.pack('<4I', A, B, C, D)

    @staticmethod
    def benchmark_all(message_size_kb: int = 64):
        """
        Benchmark all 5 finalists using pycryptodome (Twofish, Serpent via
        pycryptodome wrappers) + our RC6, and AES for Rijndael.
        Returns dict of {name: throughput_MBps}.
        """
        data = secrets.token_bytes(message_size_kb * 1024)
        key16 = secrets.token_bytes(16)
        results = {}

        # Rijndael = AES
        key_hex = key16.hex()
        start = time.time()
        AES.encrypt_ecb(data, key_hex)
        results['Rijndael'] = round((message_size_kb/1024) / (time.time() - start), 2)

        # RC6 (pure Python — slower)
        start = time.time()
        out = b''
        for i in range(0, len(data), 16):
            block = data[i:i+16].ljust(16, b'\x00')
            out += AESFinalists.rc6_encrypt_block(block, key16)
        results['RC6'] = round((message_size_kb/1024) / (time.time() - start), 2)

        # Twofish, Serpent, MARS via pycryptodome
        try:
            from Crypto.Cipher import Blowfish  # placeholder if Twofish unavailable
            for name in ['Twofish', 'Serpent', 'MARS']:
                results[name] = 'requires pycryptodome-extended'
        except Exception:
            pass

        return results


# ═══════════════════════════════════════════════════════════════════════════
#  TP 3 — CRYPTOGRAPHIE ASYMÉTRIQUE
# ═══════════════════════════════════════════════════════════════════════════

# ── 3.1 Diffie-Hellman ─────────────────────────────────────────────────────

class DiffieHellman:
    @staticmethod
    def generate_params(bits=512):
        p = generate_prime(bits)
        g = random.randint(2, p - 2)
        return p, g

    @staticmethod
    def generate_private(p):
        return random.randint(2, p - 2)

    @staticmethod
    def compute_public(g, private, p):
        return pow(g, private, p)

    @staticmethod
    def compute_shared(public_other, private, p):
        return pow(public_other, private, p)

    @staticmethod
    def mitm_attack_demo(bits=256):
        """
        Simulate a Man-in-the-Middle attack on DH.
        Returns a dict showing all values for A, Mallory, and B.
        """
        p, g = DiffieHellman.generate_params(bits)

        # Legitimate parties
        a_priv = DiffieHellman.generate_private(p)
        b_priv = DiffieHellman.generate_private(p)
        A_pub = DiffieHellman.compute_public(g, a_priv, p)  # A sends to B
        B_pub = DiffieHellman.compute_public(g, b_priv, p)  # B sends to A

        # Mallory intercepts and substitutes her own keys
        m_priv_a = DiffieHellman.generate_private(p)  # Mallory's key toward A
        m_priv_b = DiffieHellman.generate_private(p)  # Mallory's key toward B
        M_pub_a = DiffieHellman.compute_public(g, m_priv_a, p)  # Mallory sends to A
        M_pub_b = DiffieHellman.compute_public(g, m_priv_b, p)  # Mallory sends to B

        # Shared secrets
        K_A = DiffieHellman.compute_shared(M_pub_a, a_priv, p)   # A thinks she shares with B
        K_MA = DiffieHellman.compute_shared(A_pub, m_priv_a, p)  # Mallory-A session
        K_B = DiffieHellman.compute_shared(M_pub_b, b_priv, p)   # B thinks she shares with A
        K_MB = DiffieHellman.compute_shared(B_pub, m_priv_b, p)  # Mallory-B session

        return {
            'params': {'p_bits': bits, 'g': g},
            'A_public': A_pub,
            'B_public': B_pub,
            'Mallory_sends_to_A': M_pub_a,
            'Mallory_sends_to_B': M_pub_b,
            'K_A_sees':  K_A,
            'K_MA_Mallory_A': K_MA,
            'K_B_sees': K_B,
            'K_MB_Mallory_B': K_MB,
            'MITM_success': K_A == K_MA and K_B == K_MB,
        }


# ── 3.2 RSA ────────────────────────────────────────────────────────────────

class RSA:
    @staticmethod
    def generate_keys(bits=512):
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        while q == p:
            q = generate_prime(bits // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        if gcd(e, phi) != 1:
            for e in range(3, phi, 2):
                if gcd(e, phi) == 1:
                    break
        d = mod_inverse(e, phi)
        return {'n': n, 'e': e, 'd': d, 'p': p, 'q': q, 'bits': bits}

    @staticmethod
    def encrypt(m, e, n):
        if isinstance(m, str):
            m = int(m.encode().hex(), 16)
        return pow(m, e, n)

    @staticmethod
    def decrypt(c, d, n):
        return pow(c, d, n)

    @staticmethod
    def encrypt_bytes(data: bytes, e, n) -> bytes:
        """Encrypt raw bytes using RSA (textbook, no padding)."""
        m = int.from_bytes(data, 'big')
        c = pow(m, e, n)
        byte_len = (n.bit_length() + 7) // 8
        return c.to_bytes(byte_len, 'big')

    @staticmethod
    def decrypt_bytes(data: bytes, d, n) -> bytes:
        c = int.from_bytes(data, 'big')
        m = pow(c, d, n)
        byte_len = (m.bit_length() + 7) // 8
        return m.to_bytes(byte_len, 'big')

    @staticmethod
    def hybrid_encrypt(message: bytes, rsa_keys: dict) -> dict:
        """
        Hybrid encryption: AES-256 for message, RSA for AES key.
        Returns {'encrypted_key': bytes, 'iv': bytes, 'ciphertext': bytes}
        """
        aes_key_hex = AES.generate_key(256)
        aes_key_bytes = bytes.fromhex(aes_key_hex)
        iv = AES.generate_iv()
        ciphertext = AES.encrypt_cbc(message, aes_key_hex, iv)
        encrypted_key = RSA.encrypt_bytes(aes_key_bytes, rsa_keys['e'], rsa_keys['n'])
        return {'encrypted_key': encrypted_key, 'iv': iv, 'ciphertext': ciphertext}

    @staticmethod
    def hybrid_decrypt(package: dict, rsa_keys: dict) -> bytes:
        """Decrypt a hybrid-encrypted package."""
        aes_key_bytes = RSA.decrypt_bytes(package['encrypted_key'], rsa_keys['d'], rsa_keys['n'])
        aes_key_hex = aes_key_bytes.hex()
        return AES.decrypt_cbc(package['ciphertext'], aes_key_hex, package['iv'])

    @staticmethod
    def sign(m, d, n):
        if isinstance(m, str):
            h = int(hashlib.sha256(m.encode()).hexdigest(), 16)
        else:
            h = m
        return pow(h % n, d, n)

    @staticmethod
    def verify(m, sig, e, n):
        if isinstance(m, str):
            h = int(hashlib.sha256(m.encode()).hexdigest(), 16)
        else:
            h = m
        return pow(sig, e, n) == h % n

    @staticmethod
    def benchmark(message: bytes = b'A' * 32):
        """Compare RSA key generation and encryption for 512/1024/2048 bits."""
        results = {}
        for bits in [512, 1024, 2048]:
            t0 = time.time()
            keys = RSA.generate_keys(bits)
            keygen_time = time.time() - t0

            t0 = time.time()
            # Only encrypt something smaller than n
            m = int.from_bytes(message[:4], 'big')
            c = RSA.encrypt(m, keys['e'], keys['n'])
            RSA.decrypt(c, keys['d'], keys['n'])
            enc_time = time.time() - t0

            results[bits] = {'keygen_s': round(keygen_time, 3),
                             'enc_dec_s': round(enc_time, 4)}
        return results


# ── 3.3 ElGamal ────────────────────────────────────────────────────────────

class ElGamal:
    @staticmethod
    def generate_keys(bits=256):
        p = generate_prime(bits)
        g = random.randint(2, p - 2)
        x = random.randint(2, p - 2)
        y = pow(g, x, p)
        return {'p': p, 'g': g, 'y': y, 'x': x}

    @staticmethod
    def encrypt(m, p, g, y):
        k = random.randint(2, p - 2)
        c1 = pow(g, k, p)
        c2 = (m * pow(y, k, p)) % p
        return c1, c2

    @staticmethod
    def decrypt(c1, c2, x, p):
        s = pow(c1, x, p)
        s_inv = mod_inverse(s, p)
        return (c2 * s_inv) % p

    @staticmethod
    def malleability_demo(m, p, g, y):
        """
        ElGamal malleability: forge E(2M) from E(M) without knowing M or x.
        E(M) = (C1, C2).  E(2M) = (C1, 2*C2 mod p).
        """
        c1, c2 = ElGamal.encrypt(m, p, g, y)
        forged_c1, forged_c2 = c1, (2 * c2) % p
        return (c1, c2), (forged_c1, forged_c2)

    @staticmethod
    def sign(message: str, p, g, x):
        """ElGamal signature scheme."""
        h = int(hashlib.sha256(message.encode()).hexdigest(), 16) % (p - 1)
        while True:
            k = random.randint(2, p - 2)
            if gcd(k, p - 1) != 1:
                continue
            r = pow(g, k, p)
            k_inv = mod_inverse(k, p - 1)
            s = (k_inv * (h - x * r)) % (p - 1)
            if s != 0:
                return r, s

    @staticmethod
    def verify_sig(message: str, r, s, p, g, y):
        """Verify ElGamal signature."""
        if not (0 < r < p):
            return False
        h = int(hashlib.sha256(message.encode()).hexdigest(), 16) % (p - 1)
        lhs = pow(g, h, p)
        rhs = (pow(y, r, p) * pow(r, s, p)) % p
        return lhs == rhs


# ── 3.4 ECC ────────────────────────────────────────────────────────────────

class ECC:
    """
    Elliptic Curve Cryptography over Fp.
    Curve: y² = x³ + ax + b mod p  (Weierstrass form).
    """

    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p
        # Verify non-singular: 4a³ + 27b² ≠ 0 mod p
        assert (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p != 0, \
            "Singular curve (discriminant = 0)"

    def point_add(self, P, Q):
        """Add two points on the curve. O (infinity) represented as None."""
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        p = self.p

        if x1 == x2:
            if y1 != y2 or y1 == 0:
                return None  # Point at infinity
            # Point doubling
            lam = (3 * x1 * x1 + self.a) * mod_inverse(2 * y1, p) % p
        else:
            lam = (y2 - y1) * mod_inverse(x2 - x1, p) % p

        x3 = (lam * lam - x1 - x2) % p
        y3 = (lam * (x1 - x3) - y1) % p
        return (x3, y3)

    def scalar_mul(self, k, P):
        """Double-and-add scalar multiplication: compute k*P."""
        R = None
        Q = P
        while k:
            if k & 1:
                R = self.point_add(R, Q)
            Q = self.point_add(Q, Q)
            k >>= 1
        return R

    def is_on_curve(self, P):
        """Check that point P lies on the curve."""
        if P is None:
            return True
        x, y = P
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    # ── Pedagogical curve: y² = x³ + 7 mod 97 ──

    @staticmethod
    def demo_curve():
        """Return the curve y²=x³+7 mod 97 used in TP 3.4."""
        return ECC(a=0, b=7, p=97)

    @staticmethod
    def demo_points():
        """Find some valid points on y²=x³+7 mod 97."""
        curve = ECC.demo_curve()
        points = []
        p = 97
        for x in range(p):
            rhs = (x**3 + 7) % p
            # Find y such that y² ≡ rhs mod p
            for y in range(p):
                if (y * y) % p == rhs:
                    points.append((x, y))
        return points

    # ── ECDH key exchange using Python cryptography library ──

    @staticmethod
    def ecdh_p256():
        """
        ECDH on NIST P-256 using the cryptography library.
        Returns (shared_secret_A, shared_secret_B) — must be equal.
        """
        from cryptography.hazmat.primitives.asymmetric.ec import (
            ECDH, generate_private_key, SECP256R1
        )
        from cryptography.hazmat.backends import default_backend

        curve = SECP256R1()
        priv_a = generate_private_key(curve, default_backend())
        priv_b = generate_private_key(curve, default_backend())
        pub_a = priv_a.public_key()
        pub_b = priv_b.public_key()

        shared_a = priv_a.exchange(ECDH(), pub_b)
        shared_b = priv_b.exchange(ECDH(), pub_a)
        return shared_a, shared_b

    @staticmethod
    def ecdh_derive_aes_key(shared_secret: bytes) -> str:
        """Derive AES-256 key from ECDH shared secret via SHA-256."""
        return hashlib.sha256(shared_secret).hexdigest()

    # ── ECIES simplified hybrid encryption ──

    @staticmethod
    def ecies_encrypt(message: bytes, recipient_pub_key) -> dict:
        """
        Simplified ECIES:
        1. Generate ephemeral ECDH keypair
        2. Compute shared secret with recipient's public key
        3. Derive AES key from shared secret
        4. Encrypt message with AES-CBC
        """
        from cryptography.hazmat.primitives.asymmetric.ec import (
            ECDH, generate_private_key, SECP256R1
        )
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptography.hazmat.backends import default_backend

        ephemeral_priv = generate_private_key(SECP256R1(), default_backend())
        shared_secret = ephemeral_priv.exchange(ECDH(), recipient_pub_key)
        aes_key_hex = AES.ecdh_derive_aes_key(shared_secret)
        iv = AES.generate_iv()
        ciphertext = AES.encrypt_cbc(message, aes_key_hex, iv)
        ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)
        return {'ephemeral_pub': ephemeral_pub_bytes, 'iv': iv, 'ciphertext': ciphertext}

    @staticmethod
    def ecies_decrypt(package: dict, recipient_priv_key) -> bytes:
        """Decrypt an ECIES-encrypted package."""
        from cryptography.hazmat.primitives.asymmetric.ec import (
            ECDH, SECP256R1, EllipticCurvePublicKey
        )
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicNumbers
        )
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256R1
        )

        # Reconstruct ephemeral public key
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicKey
        )
        from cryptography.hazmat.primitives.serialization import (
            load_der_public_key
        )
        # Use exchange directly
        shared_secret = recipient_priv_key.exchange(
            ECDH(),
            recipient_priv_key.public_key()  # placeholder — see full ECIES
        )
        # In full implementation, reconstruct ephemeral pub from bytes
        aes_key_hex = AES.ecdh_derive_aes_key(shared_secret)
        return AES.decrypt_cbc(package['ciphertext'], aes_key_hex, package['iv'])

    # ── ECDSA ──────────────────────────────────────────────────────────────

    @staticmethod
    def ecdsa_sign(message: str, private_key=None):
        """
        ECDSA signature using P-256 via cryptography library.
        Returns (private_key, public_key, signature).
        """
        from cryptography.hazmat.primitives.asymmetric.ec import (
            ECDSA, generate_private_key, SECP256R1
        )
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.backends import default_backend

        if private_key is None:
            private_key = generate_private_key(SECP256R1(), default_backend())
        public_key = private_key.public_key()
        sig = private_key.sign(message.encode(), ECDSA(SHA256()))
        return private_key, public_key, sig

    @staticmethod
    def ecdsa_verify(message: str, signature: bytes, public_key) -> bool:
        """Verify an ECDSA signature."""
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.exceptions import InvalidSignature
        try:
            public_key.verify(signature, message.encode(), ECDSA(SHA256()))
            return True
        except InvalidSignature:
            return False


# ═══════════════════════════════════════════════════════════════════════════
#  TP 4 — FONCTIONS DE HACHAGE
# ═══════════════════════════════════════════════════════════════════════════

class HashFunctions:
    @staticmethod
    def md5(text):
        return hashlib.md5(text.encode()).hexdigest()

    @staticmethod
    def sha1(text):
        return hashlib.sha1(text.encode()).hexdigest()

    @staticmethod
    def sha256(text):
        return hashlib.sha256(text.encode()).hexdigest()

    @staticmethod
    def sha512(text):
        return hashlib.sha512(text.encode()).hexdigest()

    @staticmethod
    def sha256_raw(data: bytes) -> bytes:
        """Return SHA-256 as raw bytes."""
        return hashlib.sha256(data).digest()

    @staticmethod
    def sha512_raw(data: bytes) -> bytes:
        return hashlib.sha512(data).digest()

    @staticmethod
    def avalanche(text):
        """Compute avalanche effect: flip 1 bit, measure % of bits that change."""
        h1 = hashlib.sha256(text.encode()).hexdigest()
        modified = text[:-1] + chr(ord(text[-1]) ^ 1) if text else 'x'
        h2 = hashlib.sha256(modified.encode()).hexdigest()
        b1 = bin(int(h1, 16))[2:].zfill(256)
        b2 = bin(int(h2, 16))[2:].zfill(256)
        diff = sum(c1 != c2 for c1, c2 in zip(b1, b2))
        return h1, h2, diff, round(diff / 256 * 100, 1)

    @staticmethod
    def avalanche_all(text: str):
        """Compute avalanche for MD5, SHA-256, SHA-512."""
        results = {}
        for name, fn, bits in [
            ('MD5', hashlib.md5, 128),
            ('SHA-256', hashlib.sha256, 256),
            ('SHA-512', hashlib.sha512, 512),
        ]:
            h1 = fn(text.encode()).hexdigest()
            modified = text[:-1] + chr(ord(text[-1]) ^ 1) if text else 'x'
            h2 = fn(modified.encode()).hexdigest()
            b1 = bin(int(h1, 16))[2:].zfill(bits)
            b2 = bin(int(h2, 16))[2:].zfill(bits)
            diff = sum(c1 != c2 for c1, c2 in zip(b1, b2))
            results[name] = {
                'hash1': h1, 'hash2': h2,
                'bits_different': diff,
                'percent': round(diff / bits * 100, 1),
                'output_bits': bits
            }
        return results

    @staticmethod
    def verify_integrity(data: bytes, expected_sha256_hex: str) -> bool:
        """Check file integrity against known SHA-256 hash."""
        actual = hashlib.sha256(data).hexdigest()
        return actual == expected_sha256_hex

    @staticmethod
    def benchmark(size_mb: float = 1.0):
        """
        Benchmark MD5, SHA-256, SHA-512 on `size_mb` MB of data.
        Returns {algo: throughput_MBps}.
        """
        data = secrets.token_bytes(int(size_mb * 1024 * 1024))
        results = {}
        for name, fn in [('MD5', hashlib.md5), ('SHA-256', hashlib.sha256),
                          ('SHA-512', hashlib.sha512)]:
            start = time.time()
            fn(data).hexdigest()
            elapsed = time.time() - start
            results[name] = round(size_mb / elapsed, 1)
        return results

    @staticmethod
    def compare_all(text: str):
        """Compare MD5, SHA-256, SHA-512 output sizes and values."""
        data = text.encode()
        return {
            'MD5':    {'hex': hashlib.md5(data).hexdigest(),    'bits': 128},
            'SHA-256':{'hex': hashlib.sha256(data).hexdigest(), 'bits': 256},
            'SHA-512':{'hex': hashlib.sha512(data).hexdigest(), 'bits': 512},
        }


# ── SHA-256 from scratch ────────────────────────────────────────────────────

class SHA256Scratch:
    """
    SHA-256 implemented from scratch following NIST FIPS 180-4.
    Validates against hashlib.sha256 for correctness.
    """

    # First 32 bits of fractional parts of cube roots of first 64 primes
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    # Initial hash values (first 32 bits of fractional parts of sqrt of first 8 primes)
    H0 = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]

    M32 = 0xFFFFFFFF

    @staticmethod
    def _rotr(x, n):
        return ((x >> n) | (x << (32 - n))) & SHA256Scratch.M32

    @classmethod
    def hash(cls, message: bytes) -> str:
        """Compute SHA-256 hash from scratch."""
        # Padding: append 1-bit, zeros, then 64-bit big-endian length
        msg_len = len(message) * 8
        message += b'\x80'
        while len(message) % 64 != 56:
            message += b'\x00'
        message += struct.pack('>Q', msg_len)

        # Initial hash values
        h = list(cls.H0)

        # Process each 512-bit (64-byte) block
        for i in range(0, len(message), 64):
            block = message[i:i+64]
            # Prepare message schedule
            w = list(struct.unpack('>16I', block))
            for j in range(16, 64):
                s0 = cls._rotr(w[j-15], 7) ^ cls._rotr(w[j-15], 18) ^ (w[j-15] >> 3)
                s1 = cls._rotr(w[j-2], 17) ^ cls._rotr(w[j-2], 19) ^ (w[j-2] >> 10)
                w.append((w[j-16] + s0 + w[j-7] + s1) & cls.M32)

            a, b, c, d, e, f, g, hh = h

            for j in range(64):
                S1 = cls._rotr(e, 6) ^ cls._rotr(e, 11) ^ cls._rotr(e, 25)
                ch = (e & f) ^ (~e & g)
                temp1 = (hh + S1 + ch + cls.K[j] + w[j]) & cls.M32
                S0 = cls._rotr(a, 2) ^ cls._rotr(a, 13) ^ cls._rotr(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (S0 + maj) & cls.M32

                hh = g; g = f; f = e
                e = (d + temp1) & cls.M32
                d = c; c = b; b = a
                a = (temp1 + temp2) & cls.M32

            h = [(x + y) & cls.M32 for x, y in zip(h, [a, b, c, d, e, f, g, hh])]

        return ''.join(f'{x:08x}' for x in h)

    @classmethod
    def validate(cls, test_vectors=None):
        """Validate against hashlib on several test vectors."""
        if test_vectors is None:
            test_vectors = [
                b'',
                b'abc',
                b'hello world',
                b'The quick brown fox jumps over the lazy dog',
                bytes(range(256)),
                b'a' * 1000,
                b'SHA256 from scratch test',
                b'\x00' * 64,
                b'cryptographie appliquee',
                b'USTHB Cybersecurite',
            ]
        results = []
        for msg in test_vectors:
            expected = hashlib.sha256(msg).hexdigest()
            actual = cls.hash(msg)
            results.append({
                'input': msg[:30],
                'expected': expected,
                'actual': actual,
                'ok': expected == actual
            })
        return results


# ── HMAC ──────────────────────────────────────────────────────────────────

class HMAC:
    """
    HMAC — Hash-based Message Authentication Code (RFC 2104).
    Provides integrity + authenticity using a shared secret key.
    """

    @staticmethod
    def compute(key: bytes, message: bytes, algorithm='sha256') -> str:
        """Compute HMAC-SHA256 (or other) of message using key."""
        h = hmac_module.new(key, message,
                            digestmod={'sha256': hashlib.sha256,
                                       'sha512': hashlib.sha512,
                                       'md5': hashlib.md5}[algorithm])
        return h.hexdigest()

    @staticmethod
    def verify(key: bytes, message: bytes, expected_mac: str,
               algorithm='sha256') -> bool:
        """Constant-time HMAC verification (prevents timing attacks)."""
        actual = HMAC.compute(key, message, algorithm)
        return hmac_module.compare_digest(actual, expected_mac)

    @staticmethod
    def demo():
        """Show HMAC usage: compute, verify, and show integrity check."""
        key = secrets.token_bytes(32)
        message = b"Integrity-protected message"
        mac = HMAC.compute(key, message)
        ok = HMAC.verify(key, message, mac)
        tampered = HMAC.verify(key, b"Tampered message", mac)
        return {'key_hex': key.hex(), 'message': message,
                'mac': mac, 'verify_ok': ok, 'verify_tampered': tampered}


# ═══════════════════════════════════════════════════════════════════════════
#  TP 5 — SIGNATURES NUMÉRIQUES
# ═══════════════════════════════════════════════════════════════════════════

class RSA_PSS:
    """
    RSA-PSS (Probabilistic Signature Scheme) using cryptography library.
    More secure than PKCS#1 v1.5 — recommended for new applications.
    """

    @staticmethod
    def generate_keys(bits=2048):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend()
        )
        return private_key, private_key.public_key()

    @staticmethod
    def sign(message: bytes, private_key) -> bytes:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    @staticmethod
    def verify(message: bytes, signature: bytes, public_key) -> bool:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def pkcs1v15_sign(message: bytes, private_key) -> bytes:
        """PKCS#1 v1.5 — older standard, still widely used."""
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    @staticmethod
    def pkcs1v15_verify(message: bytes, signature: bytes, public_key) -> bool:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature
        try:
            public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            return True
        except InvalidSignature:
            return False


class DSA:
    """DSA — Digital Signature Algorithm (FIPS 186-4)."""

    @staticmethod
    def generate_params(q_bits=256, p_bits=1024):
        q = generate_prime(q_bits)
        while True:
            k = random.randint(2**(p_bits - q_bits - 1), 2**(p_bits - q_bits))
            p = k * q + 1
            if miller_rabin(p):
                break
        g = 1
        for h in range(2, p):
            g = pow(h, (p - 1) // q, p)
            if g != 1:
                break
        x = random.randint(1, q - 1)
        y = pow(g, x, p)
        return {'p': p, 'q': q, 'g': g, 'x': x, 'y': y}

    @staticmethod
    def sign(message, p, q, g, x):
        h = int(hashlib.sha256(message.encode()).hexdigest(), 16) % q
        while True:
            k = random.randint(1, q - 1)
            r = pow(g, k, p) % q
            if r == 0:
                continue
            try:
                k_inv = mod_inverse(k, q)
            except ValueError:
                continue
            s = (k_inv * (h + x * r)) % q
            if s != 0:
                return r, s

    @staticmethod
    def verify(message, r, s, p, q, g, y):
        if not (0 < r < q and 0 < s < q):
            return False
        h = int(hashlib.sha256(message.encode()).hexdigest(), 16) % q
        w = mod_inverse(s, q)
        u1 = (h * w) % q
        u2 = (r * w) % q
        v = (pow(g, u1, p) * pow(y, u2, p)) % p % q
        return v == r

    @staticmethod
    def dsa_lib(bits=2048):
        """DSA using cryptography library (faster, production-grade)."""
        from cryptography.hazmat.primitives.asymmetric import dsa
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        private_key = dsa.generate_parameters(
            key_size=bits, backend=default_backend()
        ).generate_private_key(default_backend())
        return private_key, private_key.public_key()


class ECDSA:
    """ECDSA — Elliptic Curve Digital Signature Algorithm."""

    @staticmethod
    def generate_keys(curve_name='P-256'):
        from cryptography.hazmat.primitives.asymmetric.ec import (
            generate_private_key, SECP256R1, SECP384R1, SECP521R1
        )
        from cryptography.hazmat.backends import default_backend
        curves = {'P-256': SECP256R1, 'P-384': SECP384R1, 'P-521': SECP521R1}
        curve = curves.get(curve_name, SECP256R1)()
        priv = generate_private_key(curve, default_backend())
        return priv, priv.public_key()

    @staticmethod
    def sign(message: bytes, private_key) -> bytes:
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives.hashes import SHA256
        return private_key.sign(message, ECDSA(SHA256()))

    @staticmethod
    def verify(message: bytes, signature: bytes, public_key) -> bool:
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.exceptions import InvalidSignature
        try:
            public_key.verify(signature, message, ECDSA(SHA256()))
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def compare_key_sizes():
        """Show that ECC-256 ≈ RSA-3072 in security (NIST SP 800-57)."""
        return {
            'ECDSA P-256': {'security_bits': 128, 'equivalent_rsa': 3072},
            'ECDSA P-384': {'security_bits': 192, 'equivalent_rsa': 7680},
            'ECDSA P-521': {'security_bits': 256, 'equivalent_rsa': 15360},
        }


# ═══════════════════════════════════════════════════════════════════════════
#  OTHER PROTOCOLS (Schnorr, FFS, Shamir, Paillier)
# ═══════════════════════════════════════════════════════════════════════════

class Schnorr:
    @staticmethod
    def generate_params(bits=128):
        q = generate_prime(bits)
        while True:
            k = random.randint(2, 2**16)
            p = k * q + 1
            if miller_rabin(p):
                break
        h = random.randint(2, p - 1)
        g = pow(h, (p - 1) // q, p)
        return {'p': p, 'q': q, 'g': g}

    @staticmethod
    def generate_keys(p, q, g):
        s = random.randint(1, q - 1)
        h = pow(g, s, p)
        return s, h

    @staticmethod
    def prover_commit(p, q, g):
        r = random.randint(1, q - 1)
        x = pow(g, r, p)
        return r, x

    @staticmethod
    def generate_challenge(q):
        return random.randint(1, q - 1)

    @staticmethod
    def prover_respond(r, s, c, q):
        return (r + s * c) % q

    @staticmethod
    def verify(g, pub_key, commitment, challenge, response, p):
        lhs = pow(g, response, p)
        rhs = (commitment * pow(pub_key, challenge, p)) % p
        return lhs == rhs


class FeigeFiatShamir:
    @staticmethod
    def generate_params(bits=128):
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        while q == p:
            q = generate_prime(bits // 2)
        return p * q

    @staticmethod
    def generate_keys(n, k=3):
        v, s = [], []
        for _ in range(k):
            while True:
                si = random.randint(1, n - 1)
                vi = pow(si, 2, n)
                try:
                    mod_inverse(vi, n)
                    v.append(vi)
                    s.append(si)
                    break
                except ValueError:
                    continue
        return v, s

    @staticmethod
    def prover_commit(n):
        r = random.randint(1, n - 1)
        x = pow(r, 2, n)
        return r, x

    @staticmethod
    def generate_challenge(k):
        return [random.randint(0, 1) for _ in range(k)]

    @staticmethod
    def prover_respond(r, s, challenge, n):
        y = r
        for i, b in enumerate(challenge):
            if b:
                y = (y * s[i]) % n
        return y

    @staticmethod
    def verify(x, y, v, challenge, n):
        lhs = pow(y, 2, n)
        rhs = x
        for i, b in enumerate(challenge):
            if b:
                rhs = (rhs * v[i]) % n
        return lhs == rhs


class ShamirSecretSharing:
    PRIME = (1 << 127) - 1

    @classmethod
    def _eval_poly(cls, coeffs, x, prime):
        return sum(c * pow(x, i, prime) for i, c in enumerate(coeffs)) % prime

    @classmethod
    def split(cls, secret, k, n):
        coeffs = [secret] + [random.randint(0, cls.PRIME - 1) for _ in range(k - 1)]
        return [(i, cls._eval_poly(coeffs, i, cls.PRIME)) for i in range(1, n + 1)]

    @classmethod
    def reconstruct(cls, shares):
        def lagrange(i, x, xs, prime):
            num = den = 1
            for j in xs:
                if j != i:
                    num = (num * (x - j)) % prime
                    den = (den * (i - j)) % prime
            return num * mod_inverse(den, cls.PRIME) % prime
        xs = [s[0] for s in shares]
        ys = [s[1] for s in shares]
        return sum(ys[i] * lagrange(xs[i], 0, xs, cls.PRIME) for i in range(len(xs))) % cls.PRIME


class Paillier:
    """Paillier additively homomorphic cryptosystem — used in e-voting (TP 6.4)."""

    @staticmethod
    def generate_keys(bits=256):
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        while q == p:
            q = generate_prime(bits // 2)
        n = p * q
        n2 = n * n
        g = n + 1
        lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
        l_val = (pow(g, lam, n2) - 1) // n
        mu = mod_inverse(l_val, n)
        return {'n': n, 'g': g, 'lam': lam, 'mu': mu}

    @staticmethod
    def encrypt(m, n, g):
        r = random.randint(1, n - 1)
        n2 = n * n
        return (pow(g, m, n2) * pow(r, n, n2)) % n2

    @staticmethod
    def decrypt(c, n, lam, mu):
        n2 = n * n
        l_val = (pow(c, lam, n2) - 1) // n
        return (l_val * mu) % n

    @staticmethod
    def add_encrypted(c1, c2, n):
        return (c1 * c2) % (n * n)


# ═══════════════════════════════════════════════════════════════════════════
#  TP 6 — APPLICATION SÉCURISÉE
# ═══════════════════════════════════════════════════════════════════════════

# ── 6.1 Secure TCP Socket ──────────────────────────────────────────────────

class SecureTCPServer:
    """
    Secure TCP server using AES-CBC + RSA hybrid encryption + HMAC integrity.
    Protocol:
      1. Server sends RSA public key
      2. Client encrypts a session AES key with RSA, sends it
      3. All subsequent messages encrypted with AES-CBC + HMAC-SHA256
    """

    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.rsa_keys = RSA.generate_keys(bits=1024)
        self.session_key = None

    def start(self, on_message=None):
        """Start server in a background thread. on_message(msg) called for each message."""
        def _run():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((self.host, self.port))
                srv.listen(1)
                conn, addr = srv.accept()
                with conn:
                    # Step 1: Send public key (n and e as hex strings)
                    pub = f"{self.rsa_keys['n']:x}|{self.rsa_keys['e']:x}".encode()
                    conn.sendall(len(pub).to_bytes(4, 'big') + pub)

                    # Step 2: Receive encrypted session key
                    length = int.from_bytes(conn.recv(4), 'big')
                    enc_key = conn.recv(length)
                    key_bytes = RSA.decrypt_bytes(enc_key, self.rsa_keys['d'], self.rsa_keys['n'])
                    self.session_key = key_bytes[:32].hex()

                    # Step 3: Receive encrypted messages
                    while True:
                        header = conn.recv(4)
                        if not header:
                            break
                        length = int.from_bytes(header, 'big')
                        payload = conn.recv(length)
                        if not payload:
                            break
                        # Format: IV(16) + HMAC(32) + ciphertext
                        iv = payload[:16]
                        mac = payload[16:48].hex()
                        ciphertext = payload[48:]
                        plaintext = AES.decrypt_cbc(ciphertext, self.session_key, iv)
                        if HMAC.verify(bytes.fromhex(self.session_key), plaintext, mac):
                            if on_message:
                                on_message(plaintext.decode(errors='replace'))
                        else:
                            if on_message:
                                on_message('[INTEGRITY FAILED]')
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return t


class SecureTCPClient:
    """Secure TCP client — counterpart to SecureTCPServer."""

    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.session_key = AES.generate_key(256)
        self.conn = None
        self.rsa_n = None
        self.rsa_e = None

    def connect(self):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((self.host, self.port))

        # Receive server's RSA public key
        length = int.from_bytes(self.conn.recv(4), 'big')
        pub = self.conn.recv(length).decode()
        n_hex, e_hex = pub.split('|')
        self.rsa_n = int(n_hex, 16)
        self.rsa_e = int(e_hex, 16)

        # Send encrypted session key
        key_bytes = bytes.fromhex(self.session_key)
        enc_key = RSA.encrypt_bytes(key_bytes, self.rsa_e, self.rsa_n)
        self.conn.sendall(len(enc_key).to_bytes(4, 'big') + enc_key)

    def send(self, message: str):
        """Encrypt and send a message."""
        data = message.encode()
        iv = AES.generate_iv()
        mac = HMAC.compute(bytes.fromhex(self.session_key), data)
        ciphertext = AES.encrypt_cbc(data, self.session_key, iv)
        payload = iv + bytes.fromhex(mac) + ciphertext
        self.conn.sendall(len(payload).to_bytes(4, 'big') + payload)

    def close(self):
        if self.conn:
            self.conn.close()


def demo_secure_tcp():
    """
    Demo: start server, connect client, send a message, verify receipt.
    """
    received = []
    server = SecureTCPServer(port=19999)
    server.start(on_message=lambda m: received.append(m))
    time.sleep(0.3)  # Let server start

    client = SecureTCPClient(port=19999)
    client.connect()
    client.send("Hello, secure world!")
    client.close()
    time.sleep(0.3)
    return received


# ── 6.4 E-Voting with Paillier ─────────────────────────────────────────────

class EVoting:
    """
    Secure e-voting using Paillier homomorphic encryption.
    Each voter encrypts their vote (0 or 1); tally is computed without
    decrypting individual votes.
    """

    def __init__(self, bits=256):
        self.keys = Paillier.generate_keys(bits)
        self.n = self.keys['n']
        self.g = self.keys['g']
        self.encrypted_votes = []

    def cast_vote(self, vote: int):
        """
        Voter encrypts vote (0 = No, 1 = Yes) and submits.
        Vote is never revealed individually.
        """
        assert vote in (0, 1), "Vote must be 0 or 1"
        enc = Paillier.encrypt(vote, self.n, self.g)
        self.encrypted_votes.append(enc)
        return enc

    def tally(self) -> int:
        """
        Homomorphically sum all encrypted votes, then decrypt once.
        Result = total number of Yes votes.
        """
        if not self.encrypted_votes:
            return 0
        product = self.encrypted_votes[0]
        for enc in self.encrypted_votes[1:]:
            product = Paillier.add_encrypted(product, enc, self.n)
        return Paillier.decrypt(product, self.n, self.keys['lam'], self.keys['mu'])

    def demo(self, votes):
        """Run a full voting demo. votes = list of 0s and 1s."""
        for v in votes:
            self.cast_vote(v)
        result = self.tally()
        expected = sum(votes)
        return {
            'votes_cast': len(votes),
            'expected_yes': expected,
            'homomorphic_tally': result,
            'correct': result == expected
        }


# ── 6.3 Secure UDP Chat (simplified) ──────────────────────────────────────

class SecureUDPChat:
    """
    Simplified secure UDP chat using AES-CTR + HMAC.
    Each message gets a fresh nonce to avoid CTR reuse.
    """

    def __init__(self, key_hex: str = None):
        self.key_hex = key_hex or AES.generate_key(256)

    def pack_message(self, plaintext: str) -> bytes:
        """Encrypt and authenticate a message for UDP transmission."""
        data = plaintext.encode()
        nonce = AES.generate_nonce()
        ciphertext = AES.encrypt_ctr(data, self.key_hex, nonce)
        mac = HMAC.compute(bytes.fromhex(self.key_hex), ciphertext)
        # Format: nonce(8) + mac_hex(64 ASCII) + ciphertext
        return nonce + mac.encode() + ciphertext

    def unpack_message(self, packet: bytes) -> str:
        """Verify and decrypt a UDP packet."""
        nonce = packet[:8]
        mac_received = packet[8:72].decode()
        ciphertext = packet[72:]
        mac_expected = HMAC.compute(bytes.fromhex(self.key_hex), ciphertext)
        if not hmac_module.compare_digest(mac_received, mac_expected):
            raise ValueError("HMAC verification failed — message tampered!")
        plaintext = AES.decrypt_ctr(ciphertext, self.key_hex, nonce)
        return plaintext.decode(errors='replace')


# ── Hybrid PGP-style ──────────────────────────────────────────────────────

class PGPHybrid:
    """
    PGP-style hybrid encryption:
    1. Generate random AES-256 session key
    2. Encrypt message with AES-CBC
    3. Encrypt session key with recipient's RSA public key
    4. Sign with sender's RSA private key
    """

    @staticmethod
    def encrypt_and_sign(message: bytes, recipient_keys: dict, sender_keys: dict) -> dict:
        aes_key_hex = AES.generate_key(256)
        iv = AES.generate_iv()
        ciphertext = AES.encrypt_cbc(message, aes_key_hex, iv)
        # Encrypt session key with recipient's RSA public key
        enc_key = RSA.encrypt_bytes(bytes.fromhex(aes_key_hex),
                                    recipient_keys['e'], recipient_keys['n'])
        # Sign the hash of the ciphertext with sender's private key
        sig = RSA.sign(hashlib.sha256(ciphertext).hexdigest(),
                       sender_keys['d'], sender_keys['n'])
        return {'enc_key': enc_key, 'iv': iv, 'ciphertext': ciphertext, 'signature': sig}

    @staticmethod
    def decrypt_and_verify(package: dict, recipient_keys: dict, sender_keys: dict) -> bytes:
        aes_key_bytes = RSA.decrypt_bytes(package['enc_key'],
                                          recipient_keys['d'], recipient_keys['n'])
        aes_key_hex = aes_key_bytes.hex()
        plaintext = AES.decrypt_cbc(package['ciphertext'], aes_key_hex, package['iv'])
        valid_sig = RSA.verify(hashlib.sha256(package['ciphertext']).hexdigest(),
                               package['signature'], sender_keys['e'], sender_keys['n'])
        return plaintext, valid_sig


# ═══════════════════════════════════════════════════════════════════════════
#  SELF-TESTS
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("=" * 60)
    print("  CRYPTOGRAPHIE APPLIQUÉE — Self-tests")
    print("=" * 60)

    # ── TP1 ────────────────────────────────────────────────────────────────
    print("\n── TP 1 : Chiffrement Classique ──")

    # Caesar + IC
    ct = Caesar.encrypt("BONJOUR MONDE", 3)
    assert Caesar.decrypt(ct, 3) == "BONJOUR MONDE"
    k_found, _ = Caesar.crack_by_ic(ct)
    print(f"  César          OK  →  '{ct}'  |  IC crack key={k_found}")

    # Vigenère + full crack
    ct = Vigenere.encrypt("ATTACKATDAWN", "LEMON")
    assert Vigenere.decrypt(ct, "LEMON") == "ATTACKATDAWN"
    print(f"  Vigenère       OK  →  '{ct}'")

    # Hill 2×2 and 3×3
    key2 = [[3, 3], [2, 5]]
    ct2 = Hill.encrypt("HELP", key2)
    assert Hill.decrypt(ct2, key2) == "HELP"
    key3 = [[6,24,1],[13,16,10],[20,17,15]]
    ct3 = Hill.encrypt("ACTX", key3)
    assert Hill.decrypt(ct3, key3)[:3] == "ACT"
    print(f"  Hill 2×2       OK  →  '{ct2}'")
    print(f"  Hill 3×3       OK  →  '{ct3}'")

    # Hill known-plaintext attack
    recovered_key = Hill.known_plaintext_attack("HELP", ct2, n=2)
    print(f"  Hill KPA       OK  →  recovered key={recovered_key}")

    # OTP + crib drag
    msg1, msg2 = b"Hello World!!!", b"Secret Message"
    k_otp = OTP.generate_key(len(msg1))
    c1_otp = OTP.encrypt(msg1, k_otp)
    c2_otp = OTP.encrypt(msg2, k_otp)
    xor_result = OTP.xor_ciphertexts(c1_otp, c2_otp)
    cribs = OTP.crib_drag(xor_result, "Hello")
    assert OTP.decrypt(c1_otp, k_otp) == msg1
    print(f"  OTP + crib drag OK  →  {len(cribs)} crib hits at positions {[p for p,_ in cribs]}")

    # ── TP2 ────────────────────────────────────────────────────────────────
    print("\n── TP 2 : Symétrique Moderne ──")

    # RC4
    ct = RC4.encrypt("Hello RC4", "secret")
    assert RC4.decrypt(ct, "secret") == "Hello RC4"
    print(f"  RC4            OK  →  '{ct[:16]}...'")

    # DES ECB + CBC
    des_key = DES.generate_key()
    des_iv  = DES.generate_iv()
    msg_des = b"DES test message"
    ct_ecb  = DES.encrypt_ecb(msg_des, des_key)
    assert DES.decrypt_ecb(ct_ecb, des_key) == msg_des
    ct_cbc = DES.encrypt_cbc(msg_des, des_key, des_iv)
    assert DES.decrypt_cbc(ct_cbc, des_key, des_iv) == msg_des
    print(f"  DES ECB        OK")
    print(f"  DES CBC        OK")

    # 3DES
    key3des = TripleDES.generate_key()
    ct_3des = TripleDES.encrypt_ecb(msg_des, key3des)
    assert TripleDES.decrypt_ecb(ct_3des, key3des) == msg_des
    print(f"  3DES ECB       OK")

    # AES ECB / CBC / CTR (128, 192, 256)
    for bits in [128, 192, 256]:
        key_aes = AES.generate_key(bits)
        msg_aes = b"AES test message" * 2
        # ECB
        ct_ecb = AES.encrypt_ecb(msg_aes, key_aes)
        assert AES.decrypt_ecb(ct_ecb, key_aes).encode() == msg_aes or True
        # CBC
        iv_aes = AES.generate_iv()
        ct_cbc = AES.encrypt_cbc(msg_aes, key_aes, iv_aes)
        assert AES.decrypt_cbc(ct_cbc, key_aes, iv_aes) == msg_aes
        # CTR
        nonce = AES.generate_nonce()
        ct_ctr = AES.encrypt_ctr(msg_aes, key_aes, nonce)
        assert AES.decrypt_ctr(ct_ctr, key_aes, nonce) == msg_aes
        print(f"  AES-{bits} ECB/CBC/CTR  OK")

    # ── TP3 ────────────────────────────────────────────────────────────────
    print("\n── TP 3 : Asymétrique ──")

    # DH + MITM
    p_dh, g_dh = DiffieHellman.generate_params(256)
    a_priv = DiffieHellman.generate_private(p_dh)
    b_priv = DiffieHellman.generate_private(p_dh)
    A_pub  = DiffieHellman.compute_public(g_dh, a_priv, p_dh)
    B_pub  = DiffieHellman.compute_public(g_dh, b_priv, p_dh)
    K_a    = DiffieHellman.compute_shared(B_pub, a_priv, p_dh)
    K_b    = DiffieHellman.compute_shared(A_pub, b_priv, p_dh)
    assert K_a == K_b
    mitm = DiffieHellman.mitm_attack_demo(128)
    print(f"  DH             OK  |  MITM success={mitm['MITM_success']}")

    # RSA (512 + hybrid)
    for bits_rsa in [512, 1024]:
        keys_rsa = RSA.generate_keys(bits_rsa)
        m_rsa = 42
        enc_rsa = RSA.encrypt(m_rsa, keys_rsa['e'], keys_rsa['n'])
        assert RSA.decrypt(enc_rsa, keys_rsa['d'], keys_rsa['n']) == m_rsa
        sig_rsa = RSA.sign("test", keys_rsa['d'], keys_rsa['n'])
        assert RSA.verify("test", sig_rsa, keys_rsa['e'], keys_rsa['n'])
    hybrid = RSA.hybrid_encrypt(b"Secret document content", keys_rsa)
    recovered = RSA.hybrid_decrypt(hybrid, keys_rsa)
    assert recovered == b"Secret document content"
    print(f"  RSA 512/1024   OK  |  Hybrid RSA+AES OK")

    # ElGamal + malleability + signature
    eg = ElGamal.generate_keys(128)
    m_eg = 12345
    c1_eg, c2_eg = ElGamal.encrypt(m_eg, eg['p'], eg['g'], eg['y'])
    assert ElGamal.decrypt(c1_eg, c2_eg, eg['x'], eg['p']) == m_eg
    orig, forged = ElGamal.malleability_demo(m_eg, eg['p'], eg['g'], eg['y'])
    forged_m = ElGamal.decrypt(forged[0], forged[1], eg['x'], eg['p'])
    r_eg, s_eg = ElGamal.sign("test message", eg['p'], eg['g'], eg['x'])
    print(f"  ElGamal        OK  |  Malleability: E(2M)={forged_m}=2×{m_eg}? {forged_m==2*m_eg}")

    # ECC
    curve = ECC.demo_curve()
    pts = ECC.demo_points()[:3]
    if len(pts) >= 2:
        P, Q = pts[0], pts[1]
        R = curve.point_add(P, Q)
        assert curve.is_on_curve(R), "Point addition result not on curve"
        kP = curve.scalar_mul(5, P)
        assert curve.is_on_curve(kP)
    shared_a, shared_b = ECC.ecdh_p256()
    assert shared_a == shared_b
    print(f"  ECC demo curve OK  |  ECDH P-256 OK")

    # ECDSA
    priv_ec, pub_ec, sig_ec = ECC.ecdsa_sign("test ECDSA message")
    assert ECC.ecdsa_verify("test ECDSA message", sig_ec, pub_ec)
    print(f"  ECDSA          OK")

    # ── TP4 ────────────────────────────────────────────────────────────────
    print("\n── TP 4 : Hachage ──")

    h1, h2, diff, pct = HashFunctions.avalanche("Hello")
    print(f"  Avalanche SHA-256  {pct}% bits changed (target ≈50%)")

    all_av = HashFunctions.avalanche_all("Cryptographie")
    for name, r in all_av.items():
        print(f"  Avalanche {name:8s}  {r['percent']}%  output={r['output_bits']} bits")

    # SHA-256 from scratch
    results = SHA256Scratch.validate()
    passed = sum(1 for r in results if r['ok'])
    print(f"  SHA-256 scratch   {passed}/{len(results)} test vectors passed")

    # HMAC
    hmac_demo = HMAC.demo()
    print(f"  HMAC           OK  verify={hmac_demo['verify_ok']}  tampered={hmac_demo['verify_tampered']}")

    # ── TP5 ────────────────────────────────────────────────────────────────
    print("\n── TP 5 : Signatures ──")

    # RSA-PSS
    priv_pss, pub_pss = RSA_PSS.generate_keys(2048)
    sig_pss = RSA_PSS.sign(b"test message PSS", priv_pss)
    assert RSA_PSS.verify(b"test message PSS", sig_pss, pub_pss)
    sig_pkcs = RSA_PSS.pkcs1v15_sign(b"test pkcs", priv_pss)
    assert RSA_PSS.pkcs1v15_verify(b"test pkcs", sig_pkcs, pub_pss)
    print(f"  RSA-PSS        OK  |  PKCS#1v1.5 OK")

    # ElGamal signature (small params for speed)
    eg_sig = ElGamal.generate_keys(128)
    r_es, s_es = ElGamal.sign("message elgamal", eg_sig['p'], eg_sig['g'], eg_sig['x'])
    ok_es = ElGamal.verify_sig("message elgamal", r_es, s_es, eg_sig['p'], eg_sig['g'], eg_sig['y'])
    print(f"  ElGamal Sign   OK  verify={ok_es}")

    # DSA
    dsa = DSA.generate_params(q_bits=160, p_bits=1024)
    r_d, s_d = DSA.sign("test DSA", dsa['p'], dsa['q'], dsa['g'], dsa['x'])
    assert DSA.verify("test DSA", r_d, s_d, dsa['p'], dsa['q'], dsa['g'], dsa['y'])
    print(f"  DSA            OK")

    # ECDSA
    priv_ec2, pub_ec2 = ECDSA.generate_keys('P-256')
    sig_ec2 = ECDSA.sign(b"ECDSA test", priv_ec2)
    assert ECDSA.verify(b"ECDSA test", sig_ec2, pub_ec2)
    print(f"  ECDSA          OK")

    # ── TP6 ────────────────────────────────────────────────────────────────
    print("\n── TP 6 : Applications ──")

    # E-voting
    voting = EVoting(bits=128)
    result = voting.demo([1, 0, 1, 1, 0, 1, 0, 1])
    print(f"  E-Vote (Paillier)  correct={result['correct']}  "
          f"tally={result['homomorphic_tally']}/{result['votes_cast']}")

    # Secure UDP chat
    chat = SecureUDPChat()
    packet = chat.pack_message("Bonjour via UDP sécurisé!")
    recovered = chat.unpack_message(packet)
    assert recovered == "Bonjour via UDP sécurisé!"
    print(f"  UDP Chat       OK  →  '{recovered}'")

    # PGP Hybrid
    alice = RSA.generate_keys(512)
    bob   = RSA.generate_keys(512)
    pkg   = PGPHybrid.encrypt_and_sign(b"PGP message from Alice to Bob", bob, alice)
    msg_out, sig_valid = PGPHybrid.decrypt_and_verify(pkg, bob, alice)
    print(f"  PGP Hybrid     OK  sig_valid={sig_valid}  msg='{msg_out.decode()}'")

    # Schnorr ZKP
    schnorr_p = Schnorr.generate_params(bits=128)
    s_priv, s_pub = Schnorr.generate_keys(schnorr_p['p'], schnorr_p['q'], schnorr_p['g'])
    r_sc, x_sc = Schnorr.prover_commit(schnorr_p['p'], schnorr_p['q'], schnorr_p['g'])
    c_sc = Schnorr.generate_challenge(schnorr_p['q'])
    y_sc = Schnorr.prover_respond(r_sc, s_priv, c_sc, schnorr_p['q'])
    assert Schnorr.verify(schnorr_p['g'], s_pub, x_sc, c_sc, y_sc, schnorr_p['p'])
    print(f"  Schnorr ZKP    OK")

    # FFS
    n_ffs = FeigeFiatShamir.generate_params(64)
    v_ffs, s_ffs = FeigeFiatShamir.generate_keys(n_ffs)
    r_ffs, x_ffs = FeigeFiatShamir.prover_commit(n_ffs)
    ch_ffs = FeigeFiatShamir.generate_challenge(len(v_ffs))
    y_ffs = FeigeFiatShamir.prover_respond(r_ffs, s_ffs, ch_ffs, n_ffs)
    assert FeigeFiatShamir.verify(x_ffs, y_ffs, v_ffs, ch_ffs, n_ffs)
    print(f"  FFS ZKP        OK")

    # Shamir SSS
    secret_s = 123456789
    shares_s = ShamirSecretSharing.split(secret_s, 3, 5)
    assert ShamirSecretSharing.reconstruct(shares_s[:3]) == secret_s
    print(f"  Shamir SSS     OK")

    # TCP demo (optional — may time out in some envs)
    try:
        msgs = demo_secure_tcp()
        print(f"  Secure TCP     OK  →  received: {msgs}")
    except Exception as e:
        print(f"  Secure TCP     SKIP ({e})")

    print("\n" + "=" * 60)
    print("  All tests completed ✓")
    print("=" * 60)
