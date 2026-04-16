# RSA key generation — prime generation + key derivation

import os


def _miller_rabin(n: int, rounds: int = 20) -> bool:
    """Probabilistic primality test. Returns False if definitely composite."""
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(rounds):
        a = int.from_bytes(os.urandom(8), "big") % (n - 3) + 2
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


def _generate_prime(bits: int) -> int:
    """Generate a random prime of exactly `bits` bits."""
    while True:
        candidate = int.from_bytes(os.urandom(bits // 8), "big")
        candidate |= (1 << (bits - 1))  # ensure correct bit length
        candidate |= 1                   # ensure odd
        if _miller_rabin(candidate):
            return candidate


def _mod_inverse(e: int, phi: int) -> int:
    """Modular inverse via Extended Euclidean Algorithm."""
    def _ext_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = _ext_gcd(b % a, a)
        return gcd, y1 - (b // a) * x1, x1

    gcd, x, _ = _ext_gcd(e % phi, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return x % phi


def generate_rsa_keys(bits: int = 1024) -> tuple:
    """
    Generate RSA key pair (n, e, d).
      n, e — public  (shared with verifier)
      d    — private (kept secret by signer)
    """
    p = _generate_prime(bits // 2)
    q = _generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = _mod_inverse(e, phi)
    return n, e, d
