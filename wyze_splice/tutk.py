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
