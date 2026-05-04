import secrets
import random
import math
import hashlib
import struct
from functools import reduce


# ─── HELPERS ────────────────────────────────────────────────────────────────

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


# ─── CLASSICAL CIPHERS ───────────────────────────────────────────────────────

class Caesar:
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
        # key 0 is the identity (included for completeness)
        return [(k, Caesar.decrypt(text, k)) for k in range(0, 26)]


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


class Vigenere:
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
            for f in range(2, d + 1):
                if d % f == 0:
                    factor_counts[f] = factor_counts.get(f, 0) + 1
        return sorted(factor_counts.items(), key=lambda x: -x[1])[:top_n]


class OTP:
    """
    True One-Time Pad (Vernam cipher) — XOR byte-by-byte.
    The key must be at least as long as the message (true OTP requirement).
    For perfect secrecy, generate a fresh key for every message.
    """

    @staticmethod
    def generate_key(length: int) -> bytes:
        """Generate a cryptographically random key of `length` bytes."""
        return secrets.token_bytes(length)

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        """
        XOR each byte of data with the corresponding key byte.
        Raises ValueError if key is shorter than data.
        """
        if len(key) < len(data):
            raise ValueError(
                f"OTP key ({len(key)} bytes) must be >= message ({len(data)} bytes)"
            )
        return bytes(b ^ key[i] for i, b in enumerate(data))

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        """XOR is its own inverse — same operation as encrypt."""
        return OTP.encrypt(data, key)

    # ── Vulnerability demo: key reuse (crib-dragging setup) ──────────────────

    @staticmethod
    def xor_ciphertexts(c1: bytes, c2: bytes) -> bytes:
        """
        C1 XOR C2 = M1 XOR M2.
        Demonstrates that reusing a key leaks the XOR of the plaintexts.
        """
        length = min(len(c1), len(c2))
        return bytes(a ^ b for a, b in zip(c1[:length], c2[:length]))


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
        if len(m) == 1:                              # base case — was missing, caused all-zero inverse
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


# ─── MODERN SYMMETRIC ────────────────────────────────────────────────────────

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
    def encrypt(text, key):
        """Encrypt a string; returns hex-encoded ciphertext."""
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
        """Decrypt hex-encoded ciphertext; returns plaintext string."""
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
    for i, v in enumerate(SBOX):
        INV_SBOX[v] = i

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

    @classmethod
    def encrypt_ecb(cls, plaintext, key_hex):
        key = bytes.fromhex(key_hex)
        rounds = {16: 10, 24: 12, 32: 14}[len(key)]
        w = cls._key_expansion(key)
        data = plaintext.encode()
        pad = 16 - len(data) % 16
        data += bytes([pad] * pad)
        return b''.join(cls._encrypt_block(data[i:i+16], w, rounds) for i in range(0, len(data), 16)).hex()

    @classmethod
    def decrypt_ecb(cls, ciphertext_hex, key_hex):
        key = bytes.fromhex(key_hex)
        rounds = {16: 10, 24: 12, 32: 14}[len(key)]
        w = cls._key_expansion(key)
        data = bytes.fromhex(ciphertext_hex)
        raw = b''.join(cls._decrypt_block(data[i:i+16], w, rounds) for i in range(0, len(data), 16))
        pad = raw[-1]
        return raw[:-pad].decode(errors='replace')

    @staticmethod
    def generate_key(bits=128):
        # Use secrets for cryptographically secure key generation
        return secrets.token_bytes(bits // 8).hex()


# ─── ASYMMETRIC ──────────────────────────────────────────────────────────────

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
        return {'n': n, 'e': e, 'd': d, 'p': p, 'q': q}

    @staticmethod
    def encrypt(m, e, n):
        if isinstance(m, str):
            m = int(m.encode().hex(), 16)
        return pow(m, e, n)

    @staticmethod
    def decrypt(c, d, n):
        return pow(c, d, n)

    @staticmethod
    def sign(m, d, n):
        """Sign a message: computes S = H(m)^d mod n."""
        if isinstance(m, str):
            h = int(hashlib.sha256(m.encode()).hexdigest(), 16)
        else:
            h = m
        # Reduce hash modulo n to fit the key size
        return pow(h % n, d, n)

    @staticmethod
    def verify(m, sig, e, n):
        """
        Verify a signature.
        Recomputes H(m) % n and compares with sig^e mod n.
        Note: for production use OAEP/PSS padding instead.
        """
        if isinstance(m, str):
            h = int(hashlib.sha256(m.encode()).hexdigest(), 16)
        else:
            h = m
        # Must use the same reduction as sign()
        return pow(sig, e, n) == h % n


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


class DiffieHellman:
    @staticmethod
    def generate_params(bits=256):
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


# ─── HASH FUNCTIONS ──────────────────────────────────────────────────────────

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
    def avalanche(text):
        h1 = hashlib.sha256(text.encode()).hexdigest()
        if text:
            modified = text[:-1] + chr(ord(text[-1]) ^ 1)
        else:
            modified = 'x'
        h2 = hashlib.sha256(modified.encode()).hexdigest()
        b1 = bin(int(h1, 16))[2:].zfill(256)
        b2 = bin(int(h2, 16))[2:].zfill(256)
        diff = sum(c1 != c2 for c1, c2 in zip(b1, b2))
        return h1, h2, diff, round(diff / 256 * 100, 1)


# ─── DIGITAL SIGNATURES (DSA) ────────────────────────────────────────────────

class DSA:
    @staticmethod
    def generate_params(q_bits=256, p_bits=1024):
        """
        Generate DSA parameters following standard sizing:
          q — prime divisor of (p-1), q_bits bits  (e.g. 256)
          p — large prime,            p_bits bits   (e.g. 1024)
          g — generator of order q in Z*_p
        """
        q = generate_prime(q_bits)
        # Keep generating k until p = k*q + 1 is prime and has the right bit-length
        while True:
            k = random.randint(
                2 ** (p_bits - q_bits - 1),
                2 ** (p_bits - q_bits)
            )
            p = k * q + 1
            if miller_rabin(p):
                break
        # Find a generator g of order q
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


# ─── SHAMIR SECRET SHARING ───────────────────────────────────────────────────

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


# ─── PAILLIER HOMOMORPHIC ENCRYPTION ─────────────────────────────────────────

class Paillier:
    """
    Paillier cryptosystem — additively homomorphic.
    Enc(m1) * Enc(m2) mod n² = Enc(m1 + m2 mod n)
    Used in TP 6.4 for secure e-voting.
    """

    @staticmethod
    def generate_keys(bits=256):
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        while q == p:
            q = generate_prime(bits // 2)
        n = p * q
        n2 = n * n
        g = n + 1                                   # standard simplification: g = n+1
        lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
        # Correct mu: mu = L(g^lambda mod n²)^-1 mod n
        # where L(x) = (x - 1) / n
        l_val = (pow(g, lam, n2) - 1) // n         # L(g^λ mod n²)
        mu = mod_inverse(l_val, n)
        return {'n': n, 'g': g, 'lam': lam, 'mu': mu}

    @staticmethod
    def encrypt(m, n, g):
        r = random.randint(1, n - 1)
        n2 = n * n
        return (pow(g, m, n2) * pow(r, n, n2)) % n2

    @staticmethod
    def decrypt(c, n, lam, mu):
        """
        Decrypt: m = L(c^lambda mod n²) * mu mod n
        where L(x) = (x - 1) / n
        """
        n2 = n * n
        l_val = (pow(c, lam, n2) - 1) // n         # L(c^λ mod n²)
        return (l_val * mu) % n

    @staticmethod
    def add_encrypted(c1, c2, n):
        """Homomorphic addition: Enc(m1+m2) = Enc(m1)*Enc(m2) mod n²"""
        return (c1 * c2) % (n * n)


# ─── SCHNORR ZERO-KNOWLEDGE PROOF ────────────────────────────────────────────

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
        s = random.randint(1, q - 1)           # private key
        h = pow(g, s, p)                        # public key
        return s, h

    @staticmethod
    def prover_commit(p, q, g):
        r = random.randint(1, q - 1)           # random nonce
        x = pow(g, r, p)                        # commitment
        return r, x

    @staticmethod
    def generate_challenge(q):
        return random.randint(1, q - 1)

    @staticmethod
    def prover_respond(r, s, c, q):
        """Compute response: y = r + s*c mod q"""
        return (r + s * c) % q

    @staticmethod
    def verify(g, pub_key, commitment, challenge, response, p):
        """
        Verify: g^response mod p == commitment * pub_key^challenge mod p
        Parameters renamed for clarity (was: g, y, h, c, x, p — confusing).
        """
        lhs = pow(g, response, p)
        rhs = (commitment * pow(pub_key, challenge, p)) % p
        return lhs == rhs


# ─── FEIGE-FIAT-SHAMIR ───────────────────────────────────────────────────────

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
        """
        Generate k pairs (v_i, s_i) where:
          s_i  = random secret
          v_i  = s_i² mod n   (public key component)
        Returns v (list of public values) and s (list of secrets).
        """
        v = []
        s = []
        for _ in range(k):
            while True:
                si = random.randint(1, n - 1)
                vi = pow(si, 2, n)              # v_i = s_i² mod n (public)
                # Make sure vi is invertible (needed for verification)
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
        x = pow(r, 2, n)                        # commitment x = r² mod n
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
        """
        Verify: y² mod n == x * product(v_i) for b_i=1  mod n
        Note: v[i] = s[i]² (not its inverse), so we multiply directly.
        Bug fix: original code used mod_inverse(v[i], n) which double-inverted.
        """
        lhs = pow(y, 2, n)
        rhs = x
        for i, b in enumerate(challenge):
            if b:
                rhs = (rhs * v[i]) % n          # FIXED: multiply by v[i], not its inverse
        return lhs == rhs


# ─── QUICK SELF-TEST ─────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=== Self-tests ===\n")

    # Caesar
    ct = Caesar.encrypt("Hello World", 3)
    assert Caesar.decrypt(ct, 3) == "Hello World"
    print(f"Caesar      OK  →  '{ct}'")

    # Vigenere
    ct = Vigenere.encrypt("ATTACKATDAWN", "LEMON")
    assert Vigenere.decrypt(ct, "LEMON") == "ATTACKATDAWN"
    print(f"Vigenere    OK  →  '{ct}'")

    # Hill 2x2
    key = [[3, 3], [2, 5]]
    ct = Hill.encrypt("HELP", key)
    assert Hill.decrypt(ct, key) == "HELP"
    print(f"Hill        OK  →  '{ct}'")

    # OTP (byte-level XOR)
    msg = b"Secret message!"
    key_otp = OTP.generate_key(len(msg))
    enc = OTP.encrypt(msg, key_otp)
    assert OTP.decrypt(enc, key_otp) == msg
    print(f"OTP         OK  →  {enc.hex()}")

    # RC4
    ct = RC4.encrypt("Hello RC4", "secret")
    assert RC4.decrypt(ct, "secret") == "Hello RC4"
    print(f"RC4         OK  →  '{ct}'")

    # AES ECB
    key_aes = AES.generate_key(128)
    ct = AES.encrypt_ecb("AES test message", key_aes)
    assert AES.decrypt_ecb(ct, key_aes) == "AES test message"
    print(f"AES-128 ECB OK")

    # RSA
    keys = RSA.generate_keys(512)
    m = 42
    enc = RSA.encrypt(m, keys['e'], keys['n'])
    assert RSA.decrypt(enc, keys['d'], keys['n']) == m
    sig = RSA.sign("test", keys['d'], keys['n'])
    assert RSA.verify("test", sig, keys['e'], keys['n'])
    print(f"RSA-512     OK")

    # ElGamal
    eg = ElGamal.generate_keys(128)
    m = 12345
    c1, c2 = ElGamal.encrypt(m, eg['p'], eg['g'], eg['y'])
    assert ElGamal.decrypt(c1, c2, eg['x'], eg['p']) == m
    print(f"ElGamal     OK")

    # Paillier
    pal = Paillier.generate_keys(128)
    m1, m2 = 17, 25
    e1 = Paillier.encrypt(m1, pal['n'], pal['g'])
    e2 = Paillier.encrypt(m2, pal['n'], pal['g'])
    e_sum = Paillier.add_encrypted(e1, e2, pal['n'])
    assert Paillier.decrypt(e_sum, pal['n'], pal['lam'], pal['mu']) == m1 + m2
    print(f"Paillier    OK  →  {m1} + {m2} = {m1+m2} (homomorphic)")

    # DSA
    dsa = DSA.generate_params(q_bits=160, p_bits=1024)
    r, s = DSA.sign("test message", dsa['p'], dsa['q'], dsa['g'], dsa['x'])
    assert DSA.verify("test message", r, s, dsa['p'], dsa['q'], dsa['g'], dsa['y'])
    print(f"DSA         OK")

    # FFS
    n_ffs = FeigeFiatShamir.generate_params(64)
    v, s = FeigeFiatShamir.generate_keys(n_ffs)
    r_ffs, x_ffs = FeigeFiatShamir.prover_commit(n_ffs)
    ch = FeigeFiatShamir.generate_challenge(len(v))
    y_ffs = FeigeFiatShamir.prover_respond(r_ffs, s, ch, n_ffs)
    assert FeigeFiatShamir.verify(x_ffs, y_ffs, v, ch, n_ffs)
    print(f"FFS         OK")

    # Shamir
    secret = 123456789
    shares = ShamirSecretSharing.split(secret, 3, 5)
    assert ShamirSecretSharing.reconstruct(shares[:3]) == secret
    print(f"Shamir SSS  OK")

    print("\nAll tests passed ✓")
