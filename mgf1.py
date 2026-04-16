# RFC 8017 Appendix B.2.1 — Mask Generation Function

import hashlib
import math

from utils import i2osp


def mgf1(seed: bytes, mask_len: int, hash_func=hashlib.sha256) -> bytes:
    """Stretch seed into mask_len pseudorandom bytes via h(seed || counter)."""
    h_len = hash_func().digest_size
    mask = b""
    for counter in range(math.ceil(mask_len / h_len)):
        mask += hash_func(seed + i2osp(counter, 4)).digest()
    return mask[:mask_len]
