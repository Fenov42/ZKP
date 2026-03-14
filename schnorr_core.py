"""
schnorr_core.py  —  Shared Cryptographic Core
===============================================
Imported by BOTH prover.py and verifier.py.
Contains ONLY:
  • secp256k1 curve parameters
  • elliptic-curve arithmetic
  • hash / challenge function
  • Schnorr verify  (verifier needs it)
  • proof serialisation helpers

NO secret keys, NO encryption, NO network code.
"""

import hashlib
import hmac
import json

# ── secp256k1 parameters ────────────────────────────────────────────────────

P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A  = 0
B  = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# ── Elliptic-curve arithmetic ────────────────────────────────────────────────

def _modinv(a: int, m: int) -> int:
    lm, hm, low, high = 1, 0, a % m, m
    while low > 1:
        r = high // low
        lm, hm = hm - lm * r, lm
        low, high = high - low * r, low
    return lm % m


def ec_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1, y1 = P1;  x2, y2 = P2
    if x1 == x2:
        if y1 != y2: return None
        lam = (3 * x1 * x1 + A) * _modinv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _modinv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def ec_mul(k: int, point: tuple) -> tuple:
    result, addend = None, point
    while k:
        if k & 1: result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result


# ── Point validation ─────────────────────────────────────────────────────────

class InvalidPointError(Exception):
    pass


def validate_point(pt: tuple) -> tuple:
    """Reject infinity, out-of-range coords, and off-curve points."""
    if pt is None:
        raise InvalidPointError("Point at infinity")
    x, y = pt
    if not (0 < x < P and 0 < y < P):
        raise InvalidPointError("Coordinates outside field range")
    if (y * y) % P != (x * x * x + B) % P:
        raise InvalidPointError("Point does not lie on secp256k1")
    return pt


# ── Hash / challenge ─────────────────────────────────────────────────────────

def H(*parts: bytes) -> bytes:
    """SHA-256 over concatenated parts."""
    d = hashlib.sha256()
    for p in parts:
        d.update(p)
    return d.digest()


def compute_challenge(R: tuple, public_key: tuple, message: bytes) -> int:
    """
    Fiat–Shamir challenge:
        c = H(R || P || message)  mod N
    """
    Rb = point_to_bytes(R)
    Pb = point_to_bytes(public_key)
    return int.from_bytes(H(Rb, Pb, message), 'big') % N


# ── Serialisation helpers ────────────────────────────────────────────────────

def point_to_bytes(pt: tuple) -> bytes:
    """Uncompressed 65-byte SEC1 encoding."""
    x, y = pt
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def point_from_bytes(data: bytes) -> tuple:
    if len(data) != 65 or data[0] != 0x04:
        raise ValueError("Invalid point encoding (expected 65-byte uncompressed)")
    return (int.from_bytes(data[1:33], 'big'),
            int.from_bytes(data[33:],  'big'))


def point_to_hex(pt: tuple) -> str:
    return point_to_bytes(pt).hex()


def point_from_hex(s: str) -> tuple:
    return point_from_bytes(bytes.fromhex(s))


def proof_to_dict(R: tuple, s: int) -> dict:
    """Serialise (R, s) to a JSON-safe dict."""
    return {"R": point_to_hex(R), "s": hex(s)}


def proof_from_dict(d: dict):
    """Deserialise (R, s) from dict produced by proof_to_dict."""
    R = point_from_hex(d["R"])
    s = int(d["s"], 16)
    return R, s


# ── Schnorr verification (shared — both sides may call this) ─────────────────

def schnorr_verify(public_key: tuple,
                   message:    bytes,
                   R:          tuple,
                   s:          int) -> bool:
    """
    Accept iff  s·G  ==  R + c·P
    where  c = H(R || P || message).

    All inputs are validated before computation.
    """
    try:
        validate_point(public_key)
        validate_point(R)
        if not (1 <= s <= N - 1):
            return False
    except InvalidPointError:
        return False

    c  = compute_challenge(R, public_key, message)
    sG = ec_mul(s, G)
    cP = ec_mul(c, public_key)
    Rp = ec_add(R, cP)
    return sG == Rp
