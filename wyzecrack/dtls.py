"""DTLS 1.2 ECDHE-PSK as ThroughTek's stack speaks it, for direct.py.

TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 (0xCCAC) with X25519 and the
extended master secret, the PSK derived from the camera's ENR. DTLSLeg
plays the client (the tool's side of a direct session) or the server (the
camera's, in tests/fakecam.py); flights are built from templates of
captured ones, with only randoms and key material swapped.

Key schedule (RFC 5246/7627, as pion/dtls in go2rtc):
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
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

RT_CCS, RT_ALERT, RT_HANDSHAKE, RT_APPDATA = 20, 21, 22, 23
HS_CH, HS_SH, HS_NST, HS_SKE, HS_SHD, HS_CKE, HS_FIN = 1, 2, 4, 12, 14, 16, 20


def prf(secret, label, seed, length):
    label = label.encode() if isinstance(label, str) else label
    out = b""
    a = hmac.new(secret, label + seed, hashlib.sha256).digest()
    while len(out) < length:
        out += hmac.new(secret, a + label + seed, hashlib.sha256).digest()
        a = hmac.new(secret, a, hashlib.sha256).digest()
    return out[:length]


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


def derive_psk(enr):
    """go2rtc DerivePSK: SHA256(ENR) truncated at the first NUL byte,
    then ZERO-PADDED back to 32 bytes (go2rtc allocates a 32-byte buffer
    and copies only the truncated hash)."""
    full = hashlib.sha256(enr.encode()).digest()
    n = full.index(0x00) if 0x00 in full else 32
    return full[:n] + b"\x00" * (32 - n)


class DTLSLeg:
    """One DTLS session, RFC 5246/6347 key schedule with the extended
    master secret (what the cameras speak: v3 A 4.36.17.21 and
    the v2 4.9.9.3006, checked 2026-11-05).

    role='client' is the tool's side of a direct session; role='server'
    plays the camera in tests (tests/fakecam.py). The handshake methods
    return the next flight as concatenated records."""

    def __init__(self, role, psk, tpl):
        assert role in ("server", "client")
        self.role, self.psk, self.tpl = role, psk, tpl
        self.priv = X25519PrivateKey.generate()
        self.pub = self.priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        self.random = os.urandom(32)
        self.state = "start"
        self.transcript = b""      # full HS messages, wire order, CH..CKE
        self.client_random = self.server_random = None
        self.master = self.keys = None
        self.my_fin_msg = None     # our Finished (client role)
        self.cam_nst = None        # the server's NST, hashed before its Fin
        self.s_epoch = self.s_seq = 0
        self.last_flight = b""
        self.handshake_done = False
        self.seen_mseq = set()

    # ---------------------------------------------------------------- crypto
    def _derive(self, peer_point):
        shared = self.priv.exchange(X25519PublicKey.from_public_bytes(peer_point))
        pre = (struct.pack(">H", len(shared)) + shared
               + struct.pack(">H", len(self.psk)) + self.psk)
        self.master = prf(pre, "extended master secret",
                          hashlib.sha256(self.transcript).digest(), 48)
        kb = prf(self.master, "key expansion",
                 self.server_random + self.client_random, 88)
        self.keys = (kb[0:32], kb[64:76], kb[32:64], kb[76:88])  # cK cIV sK sIV

    def _fin(self, label, extra=b""):
        return prf(self.master, label,
                   hashlib.sha256(self.transcript + extra).digest(), 12)

    def _wk(self):
        """(write key, write IV, read key, read IV)"""
        ckey, civ, skey, siv = self.keys
        return (skey, siv, ckey, civ) if self.role == "server" else (ckey, civ, skey, siv)

    @staticmethod
    def _aad_nonce(iv, epoch, seq, rtype, ver, plen):
        es = struct.pack(">H", epoch) + seq.to_bytes(6, "big")
        nonce = bytes(iv[:4]) + bytes(a ^ b for a, b in zip(iv[4:], es))
        return nonce, es + bytes([rtype]) + ver + struct.pack(">H", plen)

    def encrypt_record_at(self, rtype, plaintext, epoch, seq):
        wkey, wiv, _, _ = self._wk()
        nonce, aad = self._aad_nonce(wiv, epoch, seq, rtype, b"\xfe\xfd",
                                     len(plaintext))
        ct = ChaCha20Poly1305(wkey).encrypt(nonce, plaintext, aad)
        return build_record(rtype, epoch, seq, ct)

    def encrypt_record(self, rtype, plaintext):
        rec = self.encrypt_record_at(rtype, plaintext, self.s_epoch, self.s_seq)
        self.s_seq += 1
        return rec

    def decrypt_record(self, rtype, ver, epoch, seq, body):
        """Plaintext of an epoch-1 record; BadRecord if it doesn't
        authenticate."""
        if self.keys is None:
            raise BadRecord("no keys yet")
        _, _, rkey, riv = self._wk()
        nonce, aad = self._aad_nonce(riv, epoch, seq, rtype, ver, len(body) - 16)
        try:
            return ChaCha20Poly1305(rkey).decrypt(nonce, body, aad)
        except Exception as e:  # noqa: BLE001 - InvalidTag, short body
            raise BadRecord(f"record (epoch {epoch}, seq {seq}) doesn't "
                            f"authenticate") from e

    def _dedupe_hs(self, msg):
        key = (msg[0], msg[1])
        if key in self.seen_mseq:
            return True
        self.seen_mseq.add(key)
        return False

    # =========================================================== server role
    def server_on_ch(self, ch_msg):
        """The client's ClientHello -> our SH+SKE+SHD flight; None for a
        retransmission (resend last_flight)."""
        if self._dedupe_hs(ch_msg):
            return None
        if self.state != "start":
            raise ValueError(f"CH in state {self.state}")
        msg = ch_msg[2]
        self.transcript += msg
        self.client_random = msg[14:46]
        self.server_random = self.random
        sh = bytearray(self.tpl.sh)
        sh[2:34] = self.random
        ske = bytearray(self.tpl.ske)
        ske[6:38] = self.pub
        flight = b""
        for mtype, mseq, body in ((HS_SH, 0, bytes(sh)), (HS_SKE, 1, bytes(ske)),
                                  (HS_SHD, 2, b"")):
            m = hs_msg(mtype, mseq, body)
            self.transcript += m
            flight += build_record(RT_HANDSHAKE, self.s_epoch, self.s_seq, m)
            self.s_seq += 1
        self.state = "wait_cke"
        self.last_flight = flight
        return flight

    def server_on_cke(self, cke_msg):
        """The client's ClientKeyExchange: derive the keys."""
        if self._dedupe_hs(cke_msg):
            return None
        if self.state != "wait_cke":
            raise ValueError(f"CKE in state {self.state}")
        msg = cke_msg[2]
        self.transcript += msg
        body = msg[12:]
        idlen = struct.unpack(">H", body[:2])[0]
        point = body[2 + idlen + 1:2 + idlen + 1 + 32]
        if len(point) != 32:
            raise ValueError("bad CKE point")
        self._derive(point)
        self.state = "wait_ccs"
        return b""

    def server_on_ccs(self):
        if self.state == "wait_ccs":
            self.state = "wait_fin"

    def server_on_fin(self, plaintext):
        """The client's decrypted Finished -> our NST+CCS+Fin flight."""
        for mtype, mseq, msg in parse_hs(plaintext):
            if mtype != HS_FIN or self.state != "wait_fin":
                continue
            if not hmac.compare_digest(self._fin("client finished"), msg[12:24]):
                raise ValueError("client Finished mismatch")
            nst = bytearray(self.tpl.nst)
            nst[6:] = os.urandom(len(nst) - 6)
            nst_msg = hs_msg(HS_NST, 3, bytes(nst))
            fin = hs_msg(HS_FIN, 4, self._fin("server finished", msg + nst_msg))
            flight = (build_record(RT_HANDSHAKE, 0, 3, nst_msg)
                      + build_record(RT_CCS, 0, 4, b"\x01")
                      + self.encrypt_record_at(RT_HANDSHAKE, fin, 1, 0))
            self.s_epoch, self.s_seq = 1, 1     # Fin took (1,0)
            self.state = "done"
            self.handshake_done = True
            self.last_flight = flight
            return flight
        return None

    # =========================================================== client role
    def client_hello(self):
        """Our ClientHello flight."""
        ch = bytearray(self.tpl.ch)
        ch[2:34] = self.random
        msg = hs_msg(HS_CH, 0, bytes(ch))
        self.transcript += msg
        self.client_random = self.random
        # record-layer version fe ff (DTLS 1.0), as the Wyze app sends its
        # ClientHello; later records use fe fd
        self.last_flight = build_record(RT_HANDSHAKE, self.s_epoch, self.s_seq,
                                        msg, version=b"\xfe\xff")
        self.s_seq += 1
        return self.last_flight

    def client_on_server_flight(self, messages):
        """The camera's SH/SKE/SHD -> our CKE+CCS+Fin flight (None until
        the flight is whole)."""
        for msg in messages:
            mtype, mseq, m = msg
            if self._dedupe_hs(msg):
                continue
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
        cke = bytearray(self.tpl.cke)
        cke[16:48] = self.pub
        msg = hs_msg(HS_CKE, 1, bytes(cke))
        self.transcript += msg
        self._derive(self.cam_point)
        self.my_fin_msg = hs_msg(HS_FIN, 2, self._fin("client finished"))
        flight = (build_record(RT_HANDSHAKE, self.s_epoch, self.s_seq, msg)
                  + build_record(RT_CCS, self.s_epoch, self.s_seq + 1, b"\x01")
                  + self.encrypt_record_at(RT_HANDSHAKE, self.my_fin_msg, 1, 0))
        self.s_epoch, self.s_seq = 1, 1         # next appdata record: (1,1)
        self.state = "wait_cam_fin"
        self.last_flight = flight
        return flight

    def client_on_ccs(self):
        if self.state == "wait_cam_fin":
            self.state = "cam_fin"

    def client_on_fin(self, plaintext):
        """The camera's decrypted Finished: verify; the handshake is done."""
        for mtype, mseq, msg in parse_hs(plaintext):
            if mtype != HS_FIN or self.state != "cam_fin":
                continue
            extra = self.my_fin_msg + (self.cam_nst or b"")
            if not hmac.compare_digest(self._fin("server finished", extra),
                                       msg[12:24]):
                raise ValueError("camera Finished mismatch")
            self.state = "done"
            self.handshake_done = True
            return b""
        return None


# ---------------------------------------------------------------------------
# Templates: verified bytes extracted from a live capture. Only randoms and
# key material are swapped.
# ---------------------------------------------------------------------------

_EMBEDDED = {
    "ch": (
        "fefd6b7167050903a6da70766dee8ba8ab980bc16c9c2e523ad88dab37870e4b"
        "a1850000006cc02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023"
        "c0270067c00ac0140039c009c013003300ad00abccaeccadccac009d00a9ccab"
        "00ac00aa009c00a8003d003cc038c03600b700b300950091003500af008dc037"
        "c03500b600b200940090002f00ae008c00ff01000052000b000403000102000a"
        "000c000a001d0017001e00190018002300000016000000170000000d002a0028"
        "040305030603080708080809080a080b08040805080604010501060103030301"
        "0302040205020602"
    ),
    "sh": (
        "fefdd010af85e5c5d1eb865c2737dc437e6919b1237ea1718c72ebdf12c53583"
        "40b900ccac00000dff010001000023000000170000"
    ),
    "ske": (
        "000003001d200f9ffdb778b04f8e9041be857c3c7c9e2740860a69907b512e9a"
        "a2c89e1f4972"
    ),
    "cke": (
        "000d415554485057445f61646d696e200b6720a3fab34de7dccf434465911df9"
        "beb4d5c4e9067b45d1257b01fac60746"
    ),
    "nst": (
        "00001c2000b0241735850abed933b6d433398597ee1c59bde947523fcadd9e72"
        "554acc679a1f0711f2dfcc23496ed169325ac66d4d32fdb24fcf508487f03733"
        "7d55dc235f11caf299c37399f2892976260f1680ab3a5e526ad9d80c16be436e"
        "3fc36600dda5b77e19ce77332a5a7a9604196aeae929f77c767d2503f722c32f"
        "38be24d6e362052f986423ecc6cc09dffd915624bc2ee71720786a2a733017c9"
        "d00b839c9a1a16daa7eb7b6f8a12be7040a81a59dbc2"
    ),
}


class BadRecord(ValueError):
    """A record that does not authenticate under the adopted keys."""


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

    def __contains__(self, key):
        epoch, seq = key
        return (key in self.seen
                or seq <= self.top.get(epoch, -1) - self.WINDOW)

    def add(self, key):
        self.check(*key)


class Templates:
    def __init__(self, ch, sh, ske, cke, nst):
        self.ch, self.sh, self.ske, self.cke, self.nst = ch, sh, ske, cke, nst
        # ch may carry an HVR cookie (test path); the rest are fixed
        assert len(ch) >= 232 and len(sh) == 53 and len(ske) == 38
        assert len(cke) == 48 and len(nst) == 182

    @classmethod
    def embedded(cls):
        return cls(*(bytes.fromhex(_EMBEDDED[k]) for k in
                     ("ch", "sh", "ske", "cke", "nst")))
