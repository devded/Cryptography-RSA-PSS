# RFC 8017 Section 4 — integer/byte-string conversion primitives

def i2osp(integer: int, length: int) -> bytes:
    """Integer → fixed-length big-endian byte string."""
    return integer.to_bytes(length, byteorder="big")


def os2ip(octet_string: bytes) -> int:
    """Big-endian byte string → integer."""
    return int.from_bytes(octet_string, byteorder="big")
