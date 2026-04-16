"""
main.py — RSA-PSS Demo
=======================
Cryptography Course Project | Kadir Has University | April 2026

Based on:
  - Understanding Cryptography by Paar & Pelzl, Chapter 10
  - RFC 8017 (PKCS#1 v2.2), Sections 8.1, 9.1

Characters:
  Alice  → the signer (holds the private key)
  Bob    → the verifier (holds Alice's public key)
  Oscar  → the attacker (tries to forge or tamper)

Author: Dedar | M.S. Applied Cybersecurity — CyberMACS
"""

import os
import time

from utils import i2osp
from rsa_keys import generate_rsa_keys
from rsa_pss import rsa_pss_sign, rsa_pss_verify


def main():
    print("╔" + "═" * 62 + "╗")
    print("║  RSA-PSS: Probabilistic Signature Scheme                     ║")
    print("╚" + "═" * 62 + "╝")

    # ─────────────────────────────────────────────────────────────────────
    # KEY GENERATION — Alice generates her key pair
    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 64)
    print("  KEY GENERATION — Alice creates her RSA key pair")
    print("=" * 64)

    start = time.time()
    n, e, d = generate_rsa_keys(bits=1024)
    elapsed = time.time() - start

    print(f"  Modulus n:        {n.bit_length()} bits")
    print(f"  Public exponent:  e = {e}")
    print(f"  Private exponent: d = (secret, {d.bit_length()} bits)")
    print(f"  Key generation:   {elapsed:.2f}s")
    print(f"\n  Alice keeps d secret. She shares (n, e) with Bob.")

    # ─────────────────────────────────────────────────────────────────────
    # TEST 1 — Alice signs, Bob verifies
    # ─────────────────────────────────────────────────────────────────────
    message = b"Transfer $500 to Bob's account"

    print("\n" + "=" * 64)
    print(f"  TEST 1: Alice signs a message, Bob verifies")
    print(f'  Message: "{message.decode()}"')
    print("=" * 64)

    print("\n  ── Alice's Signing Process ──")
    signature = rsa_pss_sign(message, n, d)

    print("\n  ── Bob Receives (message, signature) ──")
    valid = rsa_pss_verify(message, signature, n, e)
    print(f"\n  >>> Bob's verdict: {'VALID ✓' if valid else 'INVALID ✗'}")

    # ─────────────────────────────────────────────────────────────────────
    # TEST 2 — Oscar tampers with the message
    # ─────────────────────────────────────────────────────────────────────
    tampered = b"Transfer $5000 to Bob's account"

    print("\n" + "=" * 64)
    print(f"  TEST 2: Oscar tampers with the message in transit")
    print(f'  Original:  "{message.decode()}"')
    print(f'  Tampered:  "{tampered.decode()}"')
    print(f'  (Oscar changed "$500" to "$5000" — one extra zero)')
    print("=" * 64)

    print("\n  ── Bob tries to verify the tampered message ──")
    valid_tampered = rsa_pss_verify(tampered, signature, n, e)
    print(f"\n  >>> Bob's verdict: {'VALID ✓' if valid_tampered else 'INVALID ✗'}")
    if not valid_tampered:
        print("  >>> Oscar's tampering was detected!")

    # ─────────────────────────────────────────────────────────────────────
    # TEST 3 — Probabilistic uniqueness
    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 64)
    print(f"  TEST 3: Alice signs the same message twice")
    print(f'  Message: "{message.decode()}"')
    print("=" * 64)

    print("\n  ── First signing ──")
    sig1 = rsa_pss_sign(message, n, d, verbose=False)
    print(f"  Signature 1 = {sig1.hex()[:40]}...")

    print("\n  ── Second signing (same message, different salt) ──")
    sig2 = rsa_pss_sign(message, n, d, verbose=False)
    print(f"  Signature 2 = {sig2.hex()[:40]}...")

    same = sig1 == sig2
    print(f"\n  Same signature both times? {same}")
    print(f"  (Expected: False — the random salt makes every signature unique)")

    v1 = rsa_pss_verify(message, sig1, n, e, verbose=False)
    v2 = rsa_pss_verify(message, sig2, n, e, verbose=False)
    print(f"\n  Bob verifies signature 1: {'VALID ✓' if v1 else 'INVALID ✗'}")
    print(f"  Bob verifies signature 2: {'VALID ✓' if v2 else 'INVALID ✗'}")

    # ─────────────────────────────────────────────────────────────────────
    # TEST 4 — Oscar's forgery attempt
    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 64)
    print("  TEST 4: Oscar tries to forge a signature (existential forgery)")
    print("=" * 64)

    print("\n  Oscar picks a random value s and computes x = s^e mod n...")
    fake_s_int = int.from_bytes(os.urandom(128), "big") % n
    fake_x_int = pow(fake_s_int, e, n)

    k = n.bit_length() // 8 + (1 if n.bit_length() % 8 else 0)
    fake_sig = i2osp(fake_s_int, k)
    fake_msg = i2osp(fake_x_int, k)

    print(f"  Forged 'message' x = {fake_msg.hex()[:40]}...")
    print(f"  Forged 'signature' s = {fake_sig.hex()[:40]}...")
    print(f"\n  Does s^e mod n == x?  {pow(fake_s_int, e, n) == fake_x_int}  (math checks out!)")

    print(f"\n  But can it pass RSA-PSS verification?")
    valid_forged = rsa_pss_verify(fake_msg, fake_sig, n, e, verbose=False)
    print(f"  >>> Bob's verdict: {'VALID ✓' if valid_forged else 'INVALID ✗'}")
    if not valid_forged:
        print("  >>> The padding check stopped Oscar's forgery!")
        print("  >>> Without RSA-PSS padding, this attack would have succeeded.")

    # ─────────────────────────────────────────────────────────────────────
    # SUMMARY
    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 64)
    print("  RESULTS SUMMARY")
    print("=" * 64)
    print(f"  {'Test':<42} {'Expected':<12} {'Result'}")
    print(f"  {'-'*42} {'-'*12} {'-'*8}")
    print(f"  {'Test 1: Original message verified':<42} {'VALID':<12} {'PASS ✓' if valid else 'FAIL ✗'}")
    print(f"  {'Test 2: Tampered message rejected':<42} {'INVALID':<12} {'PASS ✓' if not valid_tampered else 'FAIL ✗'}")
    print(f"  {'Test 3: Different sigs each time':<42} {'Different':<12} {'PASS ✓' if not same else 'FAIL ✗'}")
    print(f"  {'Test 3: Both signatures verified':<42} {'VALID':<12} {'PASS ✓' if (v1 and v2) else 'FAIL ✗'}")
    print(f"  {'Test 4: Oscar forgery blocked':<42} {'INVALID':<12} {'PASS ✓' if not valid_forged else 'FAIL ✗'}")
    print("=" * 64)

    all_pass = valid and (not valid_tampered) and (not same) and v1 and v2 and (not valid_forged)
    print(f"\n  All tests passed: {all_pass}")
    if all_pass:
        print("  RSA-PSS is working correctly.")
    print()


if __name__ == "__main__":
    main()
