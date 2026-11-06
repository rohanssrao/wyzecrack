"""ThroughTek's TransCode, the keyless obfuscation of the older IOTC framing.

SDK 3.x/4.2 devices (the Wyze Cam v2 on 4.9.9.x) frame their packets with
a 16-byte "04 02 1a xx" header instead of 0xCC51, obfuscated with
TransCode: word rotations, a byte permutation and XOR with this string
(go2rtc pkg/tutk/crypto.go, which this follows). direct.py builds the
packets themselves.
"""
import struct

CHARLIE = b"Charlie is the designer of P2P!!"
_P16 = (11, 9, 8, 15, 13, 10, 12, 14, 2, 1, 5, 0, 6, 4, 7, 3)
_P8 = (7, 4, 3, 2, 1, 6, 5, 0)


def _rotl(x, r):
    r %= 32
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def _swap(src, n):
    """The permutation for n in (2, 4, 8, 16) bytes (each one undoes
    itself); other lengths pass through."""
    if n == 2:
        return bytes((src[1], src[0]))
    if n == 4:
        return bytes((src[2], src[3], src[0], src[1]))
    if n == 8:
        return bytes(src[i] for i in _P8)
    if n == 16:
        return bytes(src[i] for i in _P16)
    return bytes(src[:n])


def _rot_words(b, base):
    return b"".join(struct.pack("<I", _rotl(struct.unpack_from("<I", b, i)[0],
                                            base(i)))
                    for i in range(0, 16, 4))


def trans_code(src):
    out, pos, n = bytearray(), 0, len(src)
    while n >= 16:
        t = _rot_words(src[pos:pos + 16], lambda i: -i - 1)
        t = _swap(bytes(t[i] ^ CHARLIE[i] for i in range(16)), 16)
        out += _rot_words(t, lambda i: -i - 3)
        pos, n = pos + 16, n - 16
    out += _swap(bytes(src[pos + i] ^ CHARLIE[i] for i in range(n)), n)
    return bytes(out)


def untrans_code(src):
    out, pos, n = bytearray(), 0, len(src)
    while n >= 16:
        t = _swap(_rot_words(src[pos:pos + 16], lambda i: i + 3), 16)
        out += _rot_words(bytes(t[i] ^ CHARLIE[i] for i in range(16)),
                          lambda i: i + 1)
        pos, n = pos + 16, n - 16
    t = _swap(src[pos:], n)
    out += bytes(t[i] ^ CHARLIE[i] for i in range(n))
    return bytes(out)


def trans_code_blob(src):
    """A whole packet: the 16-byte header, then the body. With bit 0 of
    header byte 3 set (data packets), only the body's first 48 bytes are
    obfuscated and the rest is sent as is."""
    if len(src) <= 16:
        return trans_code(src)
    if src[3] & 1:
        return trans_code(src[:16]) + trans_code(src[16:64]) + bytes(src[64:])
    return trans_code(src[:16]) + trans_code(src[16:])


def untrans_code_blob(src):
    if len(src) <= 16:
        return untrans_code(src)
    head = untrans_code(src[:16])
    if head[3] & 1:
        return head + untrans_code(src[16:64]) + bytes(src[64:])
    return head + untrans_code(src[16:])
