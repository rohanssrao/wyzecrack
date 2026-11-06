"""TUTK/IOTC wrapper format, as seen on the Wyze Cam v3 (fw 4.36.17.21).

Every P2P/relay datagram is a 0xCC51 wrapper: a 28-byte header (magic
`51 cc`, little-endian cmd at [4:6], plen at [6:8], ticket + session id at
[14:24]; the ticket differs per path, the session id at [16:24] does
not), the payload, and a 20-byte trailer keyed on the header. DTLS
records ride in the payload of two commands:

  0x1502  DTLS via the data relay (the session's main path)
  0x1402  DTLS via a STUN relay on :3478 -- one session can use both: the
          phone's ClientHello may arrive as 0x1402 through a STUN relay
          while the camera answers as 0x1502 on the data relay

Control traffic: 0x1102 channel-open, 0x1202 keepalive, 0x0402/0x0502
STUN-path exchanges. The camera sends each media datagram twice.
"""
import struct

DTLS_CMDS = (0x1502, 0x1402)
STUN_RELAY_PORT = 3478
CMD_CHANNEL_OPEN = 0x1102


def wrap_cmd(data):
    return struct.unpack("<H", data[4:6])[0] if len(data) >= 6 else 0


def is_dtls_wrap(data):
    return (len(data) > 48 and data[:2] == b"\x51\xcc"
            and wrap_cmd(data) in DTLS_CMDS)


def is_clienthello_flight(data):
    """True if a DTLS wrapper's payload starts with an epoch-0
    handshake record that is a ClientHello (or HelloVerifyRequest)."""
    if len(data) < 60 or data[:2] != b"\x51\xcc":
        return False
    if wrap_cmd(data) not in DTLS_CMDS:
        return False
    body = data[28:-20]
    if len(body) < 14 or body[0] != 22:
        return False
    if struct.unpack(">H", body[3:5])[0] != 0:  # epoch 0
        return False
    return body[13] in (1, 3)  # ClientHello / HelloVerifyRequest


def is_hs_flight(data):
    """True if a DTLS wrapper carries an epoch-0 DTLS handshake
    record (rt=22). Run-6 wire capture: every handshake flight (CH,
    HVR, cookie-CH, SH/SKE/SHD, CKE, NST) is rt=22/ep=0; established
    media and ACKs are rt=23/ep=1 in BOTH directions (3640 phone,
    ~30 camera packets). This is the handshake-vs-media discriminator
    the latch needs: a relatch must never fire on an established
    session -- diverting one into a not-yet-started engine drops all
    its media and kills the user's video."""
    if len(data) < 48 or data[:2] != b"\x51\xcc":
        return False
    if wrap_cmd(data) not in DTLS_CMDS:
        return False
    body = data[28:-20]
    if len(body) < 14 or body[0] != 22:
        return False
    return struct.unpack(">H", body[3:5])[0] == 0


def is_plain_clienthello(data):
    """A DTLS wrapper carrying an epoch-0 plain ClientHello with an
    empty cookie (DTLS hs header is 12B, then client_version(2),
    random(32), session_id_len(1) -> cookie_len at body[60]). The
    phone's first CH on a fresh flow is plain (305B); ghost-flow
    retransmits from abandoned sessions are cookie-CHs and CKEs, so
    requiring an empty cookie skips them."""
    if not is_clienthello_flight(data) or len(data) < 28 + 61:
        return False
    return data[28 + 60] == 0


# -- the older IOTC framing --------------------------------------------------
# SDK 3.x/4.2 devices (the Wyze Cam v2 on 4.9.9.x) frame their packets with
# a 16-byte "04 02 1a xx" header instead of 0xCC51, obfuscated with
# ThroughTek's keyless "TransCode": word rotations, a byte permutation and
# XOR with this string (go2rtc pkg/tutk/crypto.go, which this follows).
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
