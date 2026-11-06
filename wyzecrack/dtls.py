"""DTLS 1.2 ECDHE-PSK as ThroughTek's stack speaks it: the client side of a
direct session (direct.py).

TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 (0xCCAC) with X25519 and the
extended master secret, the PSK derived from the camera's ENR. The
ClientHello and ClientKeyExchange are the ones the Wyze app sends, with only
the random and the public key swapped in.

Key schedule (RFC 5246/7627, as pion/dtls in go2rtc), checked live on the
v3 (4.36.17.21) and the v2 (4.9.9.3006):
    premaster = u16(len Z) || Z || u16(len psk) || psk
    master    = PRF(premaster, "extended master secret", SHA256(CH..CKE))
    keys      = PRF(master, "key expansion", SR||CR)[:88]
               = clientKey(32) serverKey(32) clientIV(12) serverIV(12)
    Fin(client) = PRF(master, "client finished", SHA256(CH..CKE))[:12]
    Fin(server) = PRF(master, "server finished",
                     SHA256(CH..CKE + clientFin + NST))[:12]
"""
import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

RT_CCS, RT_ALERT, RT_HANDSHAKE, RT_APPDATA = 20, 21, 22, 23
HS_CH, HS_SH, HS_NST, HS_SKE, HS_SHD, HS_CKE, HS_FIN = 1, 2, 4, 12, 14, 16, 20

# The Wyze app's ClientHello body (the random at [2:34]) and
# ClientKeyExchange body (identity "AUTHPWD_admin", the public key at
# [16:48]), from a capture
CLIENT_HELLO = bytes.fromhex(
    "fefd6b7167050903a6da70766dee8ba8ab980bc16c9c2e523ad88dab37870e4b"
    "a1850000006cc02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023"
    "c0270067c00ac0140039c009c013003300ad00abccaeccadccac009d00a9ccab"
    "00ac00aa009c00a8003d003cc038c03600b700b300950091003500af008dc037"
    "c03500b600b200940090002f00ae008c00ff01000052000b000403000102000a"
    "000c000a001d0017001e00190018002300000016000000170000000d002a0028"
    "040305030603080708080809080a080b08040805080604010501060103030301"
    "0302040205020602")
CLIENT_KEY_EXCHANGE = bytes.fromhex(
    "000d415554485057445f61646d696e200b6720a3fab34de7dccf434465911df9"
    "beb4d5c4e9067b45d1257b01fac60746")


def prf(secret, label, seed, length):
    """The TLS 1.2 PRF (P_SHA256)."""
    label = label.encode()
    out = b""
    a = hmac.new(secret, label + seed, hashlib.sha256).digest()
    while len(out) < length:
        out += hmac.new(secret, a + label + seed, hashlib.sha256).digest()
        a = hmac.new(secret, a, hashlib.sha256).digest()
    return out[:length]


def derive_psk(enr):
    """go2rtc DerivePSK: SHA256(ENR) truncated at the first NUL byte,
    then ZERO-PADDED back to 32 bytes (go2rtc allocates a 32-byte buffer
    and copies only the truncated hash)."""
    full = hashlib.sha256(enr.encode()).digest()
    n = full.index(0x00) if 0x00 in full else 32
    return full[:n] + b"\x00" * (32 - n)


def build_record(rtype, epoch, seq, body, version=b"\xfe\xfd"):
    return (bytes([rtype]) + version + struct.pack(">H", epoch)
            + seq.to_bytes(6, "big") + struct.pack(">H", len(body)) + body)


def parse_records(payload):
    """DTLS byte stream -> [(rtype, ver, epoch, seq, body)]"""
    out = []
    off = 0
    while off + 13 <= len(payload):
        rtype = payload[off]
        ver = payload[off + 1:off + 3]
        epoch = struct.unpack(">H", payload[off + 3:off + 5])[0]
        seq = int.from_bytes(payload[off + 5:off + 11], "big")
        ln = struct.unpack(">H", payload[off + 11:off + 13])[0]
        body = payload[off + 13:off + 13 + ln]
        if len(body) != ln:
            break
        out.append((rtype, ver, epoch, seq, body))
        off += 13 + ln
    return out


def parse_hs(record_body):
    """Handshake record body -> [(mtype, mseq, full_msg)]"""
    out = []
    off = 0
    while off + 12 <= len(record_body):
        mtype = record_body[off]
        mlen = int.from_bytes(record_body[off + 1:off + 4], "big")
        msg = record_body[off:off + 12 + mlen]
        if len(msg) != 12 + mlen:
            break
        mseq = struct.unpack(">H", record_body[off + 4:off + 6])[0]
        out.append((mtype, mseq, msg))
        off += 12 + mlen
    return out


def hs_msg(mtype, mseq, body):
    return (bytes([mtype]) + len(body).to_bytes(3, "big")
            + struct.pack(">H", mseq) + b"\x00" * 3
            + len(body).to_bytes(3, "big") + body)


class BadRecord(ValueError):
    """A record that does not authenticate under the session's keys."""


def _nonce_aad(iv, rtype, ver, epoch, seq, length):
    es = struct.pack(">H", epoch) + seq.to_bytes(6, "big")
    nonce = iv[:4] + bytes(a ^ b for a, b in zip(iv[4:], es))
    return nonce, es + bytes([rtype]) + ver + struct.pack(">H", length)


def seal(key, iv, rtype, epoch, seq, plaintext):
    """An encrypted record."""
    nonce, aad = _nonce_aad(iv, rtype, b"\xfe\xfd", epoch, seq, len(plaintext))
    return build_record(rtype, epoch, seq,
                        ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad))


def unseal(key, iv, rtype, ver, epoch, seq, body):
    """An encrypted record's plaintext; BadRecord if it doesn't
    authenticate."""
    nonce, aad = _nonce_aad(iv, rtype, ver, epoch, seq, len(body) - 16)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, body, aad)
    except Exception as e:  # noqa: BLE001 - InvalidTag, short body
        raise BadRecord(f"record (epoch {epoch}, seq {seq}) doesn't "
                        f"authenticate") from e


def session_keys(psk, shared, transcript, client_random, server_random):
    """(master secret, client key, client IV, server key, server IV) for an
    ECDHE-PSK handshake whose CH..CKE messages are `transcript`."""
    pre = (struct.pack(">H", len(shared)) + shared
           + struct.pack(">H", len(psk)) + psk)
    master = prf(pre, "extended master secret",
                 hashlib.sha256(transcript).digest(), 48)
    kb = prf(master, "key expansion", server_random + client_random, 88)
    return master, kb[0:32], kb[64:76], kb[32:64], kb[76:88]


def finished(master, label, transcript):
    """The 12-byte verify_data of a Finished message."""
    return prf(master, label, hashlib.sha256(transcript).digest(), 12)


class DTLSClient:
    """The client side of one session. client_hello() starts it; the
    camera's handshake messages go to on_server_flight(), its CCS to
    on_ccs() and its decrypted Finished to on_fin(). last_flight is the
    flight to resend while the camera hasn't answered it."""

    def __init__(self, psk):
        self.psk = psk
        self.priv = X25519PrivateKey.generate()
        self.random = os.urandom(32)
        self.state = "start"
        self.transcript = b""      # whole handshake messages, CH..CKE
        self.server_random = self.cam_point = None
        self.master = self.keys = None
        self.my_fin = None
        self.cam_nst = None        # the camera's NST, hashed before its Fin
        self.epoch = self.seq = 0  # of our next record
        self.last_flight = b""
        self.handshake_done = False
        self._seen = set()         # handshake messages taken (resends repeat)

    def client_hello(self):
        """Our ClientHello flight."""
        ch = bytearray(CLIENT_HELLO)
        ch[2:34] = self.random
        msg = hs_msg(HS_CH, 0, bytes(ch))
        self.transcript += msg
        # record-layer version fe ff (DTLS 1.0), as the Wyze app sends its
        # ClientHello; later records use fe fd
        self.last_flight = build_record(RT_HANDSHAKE, 0, self.seq, msg,
                                        version=b"\xfe\xff")
        self.seq += 1
        return self.last_flight

    def on_server_flight(self, messages):
        """The camera's SH/SKE/SHD -> our CKE+CCS+Fin flight (None until
        the flight is whole, or for messages already taken)."""
        for mtype, mseq, m in messages:
            if (mtype, mseq) in self._seen:
                continue
            self._seen.add((mtype, mseq))
            if mtype == HS_NST:
                self.cam_nst = m
            elif self.state == "start" and mtype == HS_SH:
                self.transcript += m
                self.server_random = m[14:46]
                self.state = "got_sh"
            elif self.state == "got_sh" and mtype == HS_SKE:
                self.transcript += m
                self.cam_point = m[12:][6:38]
                if len(self.cam_point) != 32:
                    raise ValueError("bad SKE point")
                self.state = "got_ske"
            elif self.state == "got_ske" and mtype == HS_SHD:
                self.transcript += m
                self.state = "got_shd"
            else:
                raise ValueError(f"camera msg {mtype} in state {self.state}")
        if self.state != "got_shd":
            return None
        cke = bytearray(CLIENT_KEY_EXCHANGE)
        cke[16:48] = self.priv.public_key().public_bytes(Encoding.Raw,
                                                         PublicFormat.Raw)
        msg = hs_msg(HS_CKE, 1, bytes(cke))
        self.transcript += msg
        shared = self.priv.exchange(X25519PublicKey.from_public_bytes(self.cam_point))
        self.master, *self.keys = session_keys(
            self.psk, shared, self.transcript, self.random, self.server_random)
        ckey, civ = self.keys[0], self.keys[1]
        self.my_fin = hs_msg(HS_FIN, 2, finished(self.master, "client finished",
                                                 self.transcript))
        flight = (build_record(RT_HANDSHAKE, 0, self.seq, msg)
                  + build_record(RT_CCS, 0, self.seq + 1, b"\x01")
                  + seal(ckey, civ, RT_HANDSHAKE, 1, 0, self.my_fin))
        self.epoch, self.seq = 1, 1             # next appdata record: (1,1)
        self.state = "wait_cam_fin"
        self.last_flight = flight
        return flight

    def on_ccs(self):
        if self.state == "wait_cam_fin":
            self.state = "cam_fin"

    def on_fin(self, plaintext):
        """The camera's decrypted Finished: check it; the handshake is
        done."""
        for mtype, _mseq, msg in parse_hs(plaintext):
            if mtype != HS_FIN or self.state != "cam_fin":
                continue
            want = finished(self.master, "server finished",
                            self.transcript + self.my_fin + (self.cam_nst or b""))
            if not hmac.compare_digest(want, msg[12:24]):
                raise ValueError("camera Finished mismatch")
            self.state = "done"
            self.handshake_done = True

    def encrypt_record(self, rtype, plaintext):
        ckey, civ = self.keys[0], self.keys[1]
        rec = seal(ckey, civ, rtype, self.epoch, self.seq, plaintext)
        self.seq += 1
        return rec

    def decrypt_record(self, rtype, ver, epoch, seq, body):
        """The plaintext of an epoch-1 record from the camera; BadRecord if
        it doesn't authenticate."""
        if self.keys is None:
            raise BadRecord("no keys yet")
        return unseal(self.keys[2], self.keys[3], rtype, ver, epoch, seq, body)


class ReplayWindow:
    """Records seen per epoch, bounded: sequence numbers more than WINDOW
    below the highest seen count as replays (as in RFC 6347 4.1.2.6), so
    memory stays flat over a long session."""
    WINDOW = 4096

    def __init__(self):
        self.seen = set()
        self.top = {}

    def check(self, epoch, seq):
        """True if (epoch, seq) is new; records it."""
        top = self.top.get(epoch, -1)
        if seq <= top - self.WINDOW or (epoch, seq) in self.seen:
            return False
        self.seen.add((epoch, seq))
        if seq > top:
            self.top[epoch] = seq
            if len(self.seen) > 2 * self.WINDOW:
                floor = {e: t - self.WINDOW for e, t in self.top.items()}
                self.seen = {(e, q) for e, q in self.seen if q > floor[e]}
        return True
