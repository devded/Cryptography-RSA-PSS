# RSA-PSS: Probabilistic Signature Scheme

A from-scratch Python implementation of RSA-PSS, built for the Cryptography course at Kadir Has University (April 2026).

Based on Paar & Pelzl *Understanding Cryptography*, Chapter 10, and [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017).

---

## What is RSA-PSS?

RSA-PSS is a digital signature scheme. It lets Alice sign a message so that Bob can verify it came from her — and detect if anyone (Oscar) tampered with it in transit.

The "PSS" part (Probabilistic Signature Scheme) adds a random salt before signing, so the same message produces a different signature every time. This makes it much harder to forge compared to plain RSA.

---

## Project Structure

```
utils.py      — integer ↔ byte-string conversion (I2OSP, OS2IP)
rsa_keys.py   — RSA key generation (Miller-Rabin primality, Extended Euclidean)
mgf1.py       — Mask Generation Function (MGF1)
rsa_pss.py    — EMSA-PSS encoding/verification + RSA sign/verify
main.py       — demo with 4 test cases
```

---

## How to Run

```bash
python3 main.py
```

No dependencies — standard library only.

---

## What the Demo Shows

| Test | What happens |
|------|-------------|
| Test 1 | Alice signs a message, Bob verifies it — should pass |
| Test 2 | Oscar changes one character in the message — should be caught |
| Test 3 | Alice signs the same message twice — signatures should differ |
| Test 4 | Oscar tries to forge a signature without Alice's private key — should fail |

---

## How Signing Works (the short version)

**Alice signs:**
1. Hash the message → `mHash`
2. Generate a random salt
3. Hash `(padding || mHash || salt)` → `H`
4. Build a data block `DB` containing the salt
5. Use MGF1 to generate a mask from `H`
6. XOR `DB` with the mask → `maskedDB`
7. Assemble `EM = maskedDB || H || 0xbc`
8. Apply private key: `signature = EM^d mod n`

**Bob verifies:**
1. Recover `EM = signature^e mod n` using Alice's public key
2. Reverse the encoding steps and recompute `H'`
3. If `H == H'` → valid. Otherwise → tampered or forged.

---

## Author

Dedar Alam — M.S. Applied Cybersecurity, CyberMACS
