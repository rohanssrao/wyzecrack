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


def test_transcode_matches_go2rtc():
    """Vectors from go2rtc's pkg/tutk/crypto.go (TransCodeBlob,
    ReverseTransCodeBlob, TransCodePartial), run with Go."""
    from wyze_splice.tutk import (trans_code, trans_code_blob, untrans_code,
                                  untrans_code_blob)
    vectors = [
        ("0402",
         "6a47",
         "6a47"),
        ("0402190a0800000028041200",
         "476a78786469652041773274",
         "476a78786469652041773274"),
        ("0402190a080000002804120000000000",
         "4c6f8d0c40d040ca3d2da82dc0eecad8",
         "4c6f8d0c40d040ca3d2da82dc0eecad8"),
        ("04021a0248000000010621000000000041424344454647484a4b4c4d4e505152313131410000000000000000000000000000000001010204112233445566778801000000000000000000006f454a4e3954587000000000000000000000",
         "6e4c9d8c40d140ca2d2d882dc0e6cadcba9ac93c0dc4a5ee796a0c2814a04fbc6e2e8d8c40d040ca3e6d3b1f40a4cbd84f0ddf8a04a7194d2d6f280c50e48ac86e3ecd862f34125e2d6d280c40e4cbd8173011726c6965206973207468",
         "6e4c9d8c40d140ca2d2d882dc0e6cadcba9ac93c0dc4a5ee796a0c2814a04fbc6e2e8d8c40d040ca3e6d3b1f40a4cbd84f0ddf8a04a7194d2d6f280c50e48ac86e3ecd862f34125e2d6d280c40e4cbd8173011726c6965206973207468"),
        ("04021a0b2c00000307042100aabb00010c000000aabbccddeeff001116fefd000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
         "6e6c3df740dbe0da2d2d883d80eefada70de8272500e21c58da1280cede416635e3e8d8942b000ba2d6d280c40e4cad85f3f8c9953b001bb2de3989c80ee3a0818191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
         "6e6c3df740dbe0da2d2d883d80eefada70de8272500e21c58da1280cede416635e3e8d8942b000ba2d6d280c40e4cad85f3f8c9953b001bb2de3989c80ee3a085c3caf8962b202b82cf3999d81ff3a090f40594b414b446b"),
    ]
    for src, blob, partial in vectors:
        src, blob, partial = (bytes.fromhex(x) for x in (src, blob, partial))
        assert trans_code_blob(src) == blob
        assert untrans_code_blob(blob) == src
        assert trans_code(src) == partial
        assert untrans_code(partial) == src


def test_older_framing_packets_match_go2rtc_layout():
    d = _client()
    try:
        disco = d._iotc_disco(1)
        assert disco[:4] == b"\x04\x02\x1a\x02" and len(disco) == 16 + 72
        assert struct.unpack_from("<HHH", disco, 4) == (72, 0, 0x0601)
        assert disco[16:36] == UID.encode() and disco[16 + 48] == 1
        assert disco[16 + 58:16 + 66] == direct.auth_key(ENR, MAC)
        assert d._iotc_disco(2)[16 + 58:16 + 66] == bytes(8)
        sess = d._iotc_session()
        assert len(sess) == 52 and struct.unpack_from("<H", sess, 8)[0] == 0x0402
        assert sess[16 + 20:16 + 28] == d.sid
        data = d._iotc_data(b"x" * 100, 0)
        assert data[:4] == b"\x04\x02\x1a\x0b" and data[28:] == b"x" * 100
        assert struct.unpack_from("<HHH", data, 4) == (112, 0, 0x0407)
        assert data[14] == 0 and data[20:28] == d.sid
        assert d._iotc_data(b"", 0)[6] == 1          # sequence advances
    finally:
        d.close()
