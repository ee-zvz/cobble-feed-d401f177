"""Minimal ed25519 (sign + verify) with no dependencies.

Only the feed signing path and the loader's verification touch this file.
The private key never leaves the build machine; the loader carries the public
key as a constant.
"""

import hashlib

Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


def _h(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, Q - 2, Q)


D = -121665 * _inv(121666) % Q
I = pow(2, (Q - 1) // 4, Q)


def _recover_x(y: int, sign: int):
    if y >= Q:
        return None
    x2 = (y * y - 1) * _inv(D * y * y + 1)
    if x2 == 0:
        return 0 if sign == 0 else None
    x = pow(x2, (Q + 3) // 8, Q)
    if (x * x - x2) % Q != 0:
        x = x * I % Q
    if (x * x - x2) % Q != 0:
        return None
    if (x & 1) != sign:
        x = Q - x
    return x


_GY = 4 * _inv(5) % Q
_GX = _recover_x(_GY, 0)
G = (_GX, _GY, 1, _GX * _GY % Q)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % Q
    b = (p[1] + p[0]) * (q[1] + q[0]) % Q
    c = 2 * p[3] * q[3] * D % Q
    d = 2 * p[2] * q[2] % Q
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % Q, g * h % Q, f * g % Q, e * h % Q)


def _mul(s: int, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _compress(p) -> bytes:
    z = _inv(p[2])
    x = p[0] * z % Q
    y = p[1] * z % Q
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % Q)


def _expand(secret: bytes):
    digest = _h(secret)
    a = int.from_bytes(digest[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, digest[32:]


def public_key(secret: bytes) -> bytes:
    a, _ = _expand(secret)
    return _compress(_mul(a, G))


def sign(secret: bytes, message: bytes) -> bytes:
    a, prefix = _expand(secret)
    pub = _compress(_mul(a, G))
    r = int.from_bytes(_h(prefix + message), "little") % L
    rs = _compress(_mul(r, G))
    h = int.from_bytes(_h(rs + pub + message), "little") % L
    s = (r + h * a) % L
    return rs + s.to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    if a is None:
        return False
    rs = signature[:32]
    r = _decompress(rs)
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    h = int.from_bytes(_h(rs + public + message), "little") % L
    return _compress(_mul(s, G)) == _compress(_add(r, _mul(h, a)))
