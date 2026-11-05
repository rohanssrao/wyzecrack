"""direct.py: the LAN client's framing, keys and challenge, and the plain
media format a direct session gets."""
import hashlib
import hmac
import struct

from wyze_splice import direct
from wyze_splice.media import parse_media

ENR, MAC = "gekMdn0XjZoWF/mD", "D03F27A1B2C3"
UID = "ABCDEFGHJKLMNPQR111A"            # made up


def xxtea_encrypt(data, key):
    """Reference XXTEA encryption (the inverse of direct.xxtea_decrypt)."""
    n = len(data) // 4
    v = list(struct.unpack(f"<{n}I", data))
    k = struct.unpack("<4I", key)
    delta, mask = 0x9E3779B9, 0xFFFFFFFF
    total, z = 0, v[n - 1]
    for _ in range(6 + 52 // n):
        total = (total + delta) & mask
        e = (total >> 2) & 3
        for p in range(n):
            y = v[(p + 1) % n]
            mx = ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) & mask) ^ \
                 (((total ^ y) + (k[(p & 3) ^ e] ^ z)) & mask)
            v[p] = (v[p] + mx) & mask
            z = v[p]
    return struct.pack(f"<{n}I", *v)


def test_xxtea_matches_go2rtc_vector():
    out = direct.xxtea_decrypt(b"WERhJxb87WF3zgPa", b"GAgDiwVPg2E4GMke")
    assert out.hex() == "c4a62ca1106417a5da02e162a5f06271"


def test_challenge_response_undoes_the_cameras_encryption():
    secret = bytes(range(16))
    assert direct.challenge_response(
        xxtea_encrypt(secret, ENR.encode()[:16]), ENR, 3) == secret
    assert direct.challenge_response(
        xxtea_encrypt(secret, b"F" * 16), ENR, 1) == secret


def test_auth_key():
    h = hashlib.sha256((ENR + MAC).encode()).digest()[:6]
    assert direct.auth_key(ENR, "d0:3f:27:a1:b2:c3") == direct.auth_key(ENR, MAC)
    assert len(direct.auth_key(ENR, MAC)) == 8
    assert b"+" not in direct.auth_key(ENR, MAC) and h


def _client():
    d = direct.Direct("127.0.0.1", UID, ENR, MAC, local_ip="127.0.0.1")
    d.ticket, d.sid = 0x1234, b"\x11" * 8
    return d


def test_data_wrapper_layout_and_trailer():
    d = _client()
    try:
        w = d._wrap(b"x" * 10, channel=1)
        assert len(w) == 28 + 10 + 20
        cmd, plen = struct.unpack_from("<HH", w, 4)
        assert (cmd, plen) == (0x1502, len(w) - 12)
        assert struct.unpack_from("<HH", w, 12) == (0x0110, 0x1234)
        assert w[16:24] == b"\x11" * 8 and w[28:38] == b"x" * 10
        key = UID.encode() + direct.auth_key(ENR, MAC)
        assert w[-20:] == hmac.new(key, w[:28], hashlib.sha1).digest()
    finally:
        d.close()


def test_discovery_trailer_covers_32_bytes():
    d = _client()
    try:
        p = d._disco(2)
        assert len(p) == 52 and struct.unpack_from("<HH", p, 12) == (2, 0x1234)
        key = UID.encode() + direct.auth_key(ENR, MAC)
        assert p[32:] == hmac.new(key, p[:32], hashlib.sha1).digest()
    finally:
        d.close()


def test_k_commands():
    assert direct.find_hl(bytes(40) + direct.hl(10001, b"\x03" + b"c" * 16)) == \
        (10001, b"\x03" + b"c" * 16)
    assert direct.find_hl(b"no command here" * 3) is None


def _plain(ft, frame_no, cidx, count, payload, start=False):
    """A plain media record: 8-byte outer header, 8 more bytes on start
    types, then channel/flags/chunk/count/index/size/prev/frame."""
    outer = bytes([5, ft]) + struct.pack("<HHH", 0x000C, 1, 0x65)
    extra = bytes(8) if start else b""
    inner = (bytes([5, 0]) + struct.pack("<HHHHH", 7, count, cidx, len(payload), 0)
             + struct.pack("<II", frame_no - 1, frame_no))
    return outer + extra + inner + payload


def test_parse_media_takes_the_plain_format():
    first = _plain(0x08, 9, 0, 3, b"\x00\x00\x00\x01\x67abc", start=True)
    mid = _plain(0x00, 9, 1, 3, b"middle")
    end = _plain(0x01, 9, 0x28, 3, b"tail" + bytes(40))
    assert parse_media(first) == (5, 9, 0, b"\x00\x00\x00\x01\x67abc", False, 3)
    assert parse_media(mid) == (5, 9, 1, b"middle", False, 3)
    assert parse_media(end) == (5, 9, 0xFFFF, b"tail", True, 3)
    # the wrapped form is the same record behind 8 more header bytes
    wrapped = b"\x0c" + mid[1:8] + bytes(8) + mid[8:]
    assert parse_media(wrapped) == parse_media(mid)
    assert parse_media(b"\x09\x00\x0c\x00" + bytes(40)) is None   # an ACK
