# RFC 8017 Sections 8.1 & 9.1 — EMSA-PSS encoding/verification + RSA sign/verify

import hashlib
import math
import os

from utils import i2osp, os2ip
from mgf1 import mgf1


def emsa_pss_encode(
    message: bytes,
    em_bits: int,
    salt_length: int = 32,
    hash_func=hashlib.sha256,
    verbose: bool = True,
) -> bytes:
    """Encode message M into EM using the 7-step PSS construction."""
    h_len = hash_func().digest_size
    em_len = math.ceil(em_bits / 8)

    if em_len < h_len + salt_length + 2:
        raise ValueError("Encoding error: modulus too small for these parameters")

    # Step 1: mHash = h(M)
    m_hash = hash_func(message).digest()
    if verbose:
        print(f"  Step 1 — mHash = h(M) = {m_hash.hex()[:40]}...")

    # Step 2: random salt
    salt = os.urandom(salt_length)
    if verbose:
        print(f"  Step 2 — salt = {salt.hex()[:40]}...")

    # Step 3: H = h(padding1 || mHash || salt)
    m_prime = b"\x00" * 8 + m_hash + salt
    h_value = hash_func(m_prime).digest()
    if verbose:
        print(f"  Step 3 — H = h(M') = {h_value.hex()[:40]}...")

    # Step 4: DB = zeros || 0x01 || salt
    ps_len = em_len - salt_length - h_len - 2
    db = b"\x00" * ps_len + b"\x01" + salt
    if verbose:
        print(f"  Step 4 — DB = zeros({ps_len}B) || 0x01 || salt({salt_length}B)")

    # Step 5: dbMask = MGF1(H, len(DB))
    db_mask = mgf1(h_value, len(db), hash_func)
    if verbose:
        print(f"  Step 5 — dbMask = MGF1(H, {len(db)}) = {db_mask.hex()[:40]}...")

    # Step 6: maskedDB = DB XOR dbMask  (zero top bits so EM < n)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    top_bits = 8 * em_len - em_bits
    if top_bits > 0:
        masked_db = bytes([masked_db[0] & (0xFF >> top_bits)]) + masked_db[1:]
    if verbose:
        print(f"  Step 6 — maskedDB = {masked_db.hex()[:40]}...")

    # Step 7: EM = maskedDB || H || 0xbc
    em = masked_db + h_value + b"\xbc"
    if verbose:
        print(f"  Step 7 — EM = maskedDB({len(masked_db)}B) || H({h_len}B) || 0xbc")
        print(f"           EM = {em.hex()[:40]}...{em.hex()[-4:]}  ({len(em)}B)")

    return em


def emsa_pss_verify(
    message: bytes,
    em: bytes,
    em_bits: int,
    salt_length: int = 32,
    hash_func=hashlib.sha256,
    verbose: bool = True,
) -> bool:
    """Verify EM against message M by reversing the PSS encoding."""
    h_len = hash_func().digest_size
    em_len = math.ceil(em_bits / 8)

    if verbose:
        print(f"\n  ── Verification ──")

    if em_len < h_len + salt_length + 2:
        return False

    m_hash = hash_func(message).digest()
    if verbose:
        print(f"  1. mHash = {m_hash.hex()[:32]}...")

    # Check trailer byte
    if em[-1:] != b"\xbc":
        if verbose: print(f"  FAIL: expected 0xbc trailer")
        return False
    if verbose:
        print(f"  2. Trailer 0xbc ✓")

    # Split EM → maskedDB || H || bc
    db_len = em_len - h_len - 1
    masked_db = em[:db_len]
    h_value = em[db_len:db_len + h_len]
    if verbose:
        print(f"  3. maskedDB({db_len}B) + H({h_len}B) + bc")

    # Check top bits, recover DB
    top_bits = 8 * em_len - em_bits
    if top_bits > 0 and masked_db[0] & (0xFF << (8 - top_bits) & 0xFF):
        if verbose: print("  FAIL: top bits not zero")
        return False

    db = bytes(a ^ b for a, b in zip(masked_db, mgf1(h_value, db_len, hash_func)))
    if top_bits > 0:
        db = bytes([db[0] & (0xFF >> top_bits)]) + db[1:]
    if verbose:
        print(f"  4. DB recovered")

    # Check padding: zeros || 0x01 || salt
    ps_len = em_len - h_len - salt_length - 2
    if db[:ps_len] != b"\x00" * ps_len or db[ps_len:ps_len + 1] != b"\x01":
        if verbose: print("  FAIL: padding structure invalid")
        return False
    if verbose:
        print(f"  5. Padding verified ✓")

    # Extract salt, recompute H' and compare
    salt = db[ps_len + 1:]
    h_prime = hash_func(b"\x00" * 8 + m_hash + salt).digest()
    if verbose:
        print(f"  6. salt = {salt.hex()[:32]}...")
        print(f"  7. H' = {h_prime.hex()[:32]}...")

    result = h_value == h_prime
    if verbose:
        print(f"  8. H == H' → {'VALID ✓' if result else 'INVALID ✗'}")
    return result


def rsa_pss_sign(
    message: bytes,
    n: int,
    d: int,
    salt_length: int = 32,
    hash_func=hashlib.sha256,
    verbose: bool = True,
) -> bytes:
    """Sign: EM = emsa_pss_encode(M), then s = EM^d mod n."""
    mod_bits = n.bit_length()
    em = emsa_pss_encode(message, mod_bits - 1, salt_length, hash_func, verbose)
    sig_int = pow(os2ip(em), d, n)
    signature = i2osp(sig_int, math.ceil(mod_bits / 8))
    if verbose:
        print(f"\n  s = EM^d mod n → {signature.hex()[:40]}...")
    return signature


def rsa_pss_verify(
    message: bytes,
    signature: bytes,
    n: int,
    e: int,
    salt_length: int = 32,
    hash_func=hashlib.sha256,
    verbose: bool = True,
) -> bool:
    """Verify: recover EM = s^e mod n, then run emsa_pss_verify."""
    mod_bits = n.bit_length()
    em_bits = mod_bits - 1
    em_len = math.ceil(em_bits / 8)

    sig_int = os2ip(signature)
    if sig_int >= n:
        if verbose: print("  FAIL: signature out of range")
        return False

    em = i2osp(pow(sig_int, e, n), em_len)
    if verbose:
        print(f"  EM = s^e mod n = {em.hex()[:40]}...{em.hex()[-4:]}")

    return emsa_pss_verify(message, em, em_bits, salt_length, hash_func, verbose)
