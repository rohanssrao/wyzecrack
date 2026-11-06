"""DTLS 1.2 ECDHE-PSK as ThroughTek's stack speaks it, for direct.py.

TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 (0xCCAC) with X25519 and the
extended master secret. DTLSLeg plays the client (the tool's side of a
direct session) or the server (the camera's, in tests/fakecam.py); flights
are built from templates of captured ones, so each is the same size as the
original.

The camera runs ThroughTek's own DTLS stack, which only has to interop with
itself, so it may deviate from RFC 6066/6347/6655 in the key schedule,
AAD/nonce shape, or Finished hashing. The reference construction (RFC,
verified against OpenSSL s_client/s_server) is tried first; when the peer's
first encrypted record fails to decrypt, a cascade of known construction
variants is tried and the winning one is adopted for the rest of the
session.

Key schedule (RFC reference; pion/dtls ground truth):
    premaster = u16(len Z) || Z || u16(len psk) || psk
    master    = PRF(premaster, "extended master secret", SHA256(CH..CKE))
    keys      = PRF(master, "key expansion", SR||CR)[:88]
               = clientKey(32) serverKey(32) clientIV(12) serverIV(12)
    Fin(client) = PRF(master, "client finished", SHA256(CH..CKE))[:12]
    Fin(server) = PRF(master, "server finished",
                     SHA256(CH..CKE + clientFin [+ NST]))[:12]
"""
import hashlib
import hmac
import json
import os
import struct
import time

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
    and copies only the truncated hash). Proven byte-exact against a live
    go2rtc/pion client interop: the padded PSK + EMS/h12/sr_cr/keys_first
    construction decrypts and verifies the real phone's Finished."""
    full = hashlib.sha256(enr.encode()).digest()
    n = full.index(0x00) if 0x00 in full else 32
    return full[:n] + b"\x00" * (32 - n)


# --------------------------------------------------------------------------
# Construction variants (TUTK's stack may deviate from RFC as long as both
# endpoints agree; each is cheap to test against one ciphertext)
# --------------------------------------------------------------------------

def _split_msgs(buf):
    msgs = []
    off = 0
    while off + 12 <= len(buf):
        mlen = int.from_bytes(buf[off + 1:off + 4], "big")
        msgs.append(buf[off:off + 12 + mlen])
        off += 12 + mlen
    return msgs


def _conv_h12(buf):
    return buf


def _conv_h4(buf):
    return b"".join(bytes([m[0]]) + m[1:4] + m[12:] for m in _split_msgs(buf))


def _conv_h0(buf):
    return b"".join(m[12:] for m in _split_msgs(buf))


HASH_CONVS = (("h12", _conv_h12), ("h4", _conv_h4), ("h0", _conv_h0))
AAD_VARIANTS = ("rfc", "aad_no_es", "aad_rechdr", "nonce_no_es")
FIN_LABELS = ("client finished", "server finished", "finished")


class Scheme:
    """One candidate key schedule."""

    def __init__(self, name, master, keys, hconv):
        self.name = name            # e.g. "ems/h12/sr_cr/keys_first"
        self.master = master
        self.keys = keys            # (ckey, civ, skey, siv)
        self.hconv = hconv          # transcript -> bytes hashed for Finished

    def fin(self, label, transcript, extra=b""):
        return prf(self.master, label,
                   hashlib.sha256(self.hconv(transcript + extra)).digest(), 12)


def _build_schemes(pre, pre_full, transcript, client_random, server_random):
    """Ordered candidate schemes; index 0 is the RFC reference."""
    out = []

    def add(kind, master, hname, hconv, seedname, seed, order):
        kb = prf(master, "key expansion", seed, 88)
        if order == "keys_first":       # RFC 5246
            keys = (kb[0:32], kb[64:76], kb[32:64], kb[76:88])
        else:                            # interleaved
            keys = (kb[0:32], kb[32:44], kb[44:76], kb[76:88])
        out.append(Scheme(f"{kind}/{hname}/{seedname}/{order}", master,
                          keys, hconv))

    sr_cr = server_random + client_random
    cr_sr = client_random + server_random
    for hname, hconv in HASH_CONVS:
        ems = prf(pre, "extended master secret",
                  hashlib.sha256(hconv(transcript)).digest(), 48)
        for seedname, seed in (("sr_cr", sr_cr), ("cr_sr", cr_sr)):
            for order in ("keys_first", "interleaved"):
                add("ems", ems, hname, hconv, seedname, seed, order)
    add("legacy", prf(pre, "master secret", cr_sr, 48),
        "h12", _conv_h12, "cr_sr", cr_sr, "keys_first")
    if pre_full:
        add("ems_fullpsk",
            prf(pre_full, "extended master secret",
                hashlib.sha256(_conv_h12(transcript)).digest(), 48),
            "h12", _conv_h12, "sr_cr", sr_cr, "keys_first")
    return out


class DTLSLeg:
    """One terminated DTLS session.

    role='server' terminates the phone (we play camera).
    role='client' originates toward the camera (we play phone).
    Outputs are complete flight blobs (concatenated records) whose sizes
    match the captured original flights exactly.
    """

    def __init__(self, role, psk, tpl, psk_full=None):
        assert role in ("server", "client")
        self.role = role
        self.psk = psk
        self.psk_full = psk_full    # untruncated SHA256(ENR), if known
        self.tpl = tpl
        self.priv = X25519PrivateKey.generate()
        self.priv_raw = self.priv.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self.pub = self.priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        self.random = os.urandom(32)
        self.state = "start"
        self.transcript = b""      # full HS messages, wire order, CH..CKE
        self.peer_fin_msg = None   # client-side Finished (for server Fin)
        self.my_fin_msg = None     # our client Finished (client role)
        self.cam_nst = None        # camera's NST (hashed before its Fin)
        self.client_random = None
        self.server_random = None
        self.schemes = []          # candidate schemes (set at _derive)
        self.scheme = None         # discovered/adopted scheme
        self.aad_variant = "rfc"   # discovered AAD/nonce shape
        self.peer_fin_label = None  # label that verified the peer's Fin
        self.shared = None
        self.s_epoch = 0           # send side
        self.s_seq = 0
        self.r_epoch = 0           # read side (after peer CCS)
        self.last_flight = b""     # DTLS payload bytes of last sent flight
        self.handshake_done = False
        self.failed = None
        self.seen_mseq = set()
        self.seen_rec = set()
        self.msg_seq_base = 0   # nonzero after HelloVerifyRequest (tests)
        self.journal = None     # callable(dict): key material, for debugging
        self.nst_in_hash = True  # server Fin: hash NST (openssl-verified)
        # flight components for rebuilds after scheme discovery
        self._nst_rec = None       # NST record bytes (server role)
        self._ccs_rec = None       # CCS record bytes
        self._fin_pt = None        # encrypted-Fin plaintext
        self._fin_pos = (0, 0)     # (epoch, seq) of the Fin record

    def _j(self, **kw):
        if self.journal:
            kw.setdefault("role", self.role)
            kw["t"] = time.time()
            self.journal(kw)

    # ---------------------------------------------------------------- crypto
    def _derive(self, peer_point):
        self.shared = self.priv.exchange(
            X25519PublicKey.from_public_bytes(peer_point))
        pre = (struct.pack(">H", len(self.shared)) + self.shared
               + struct.pack(">H", len(self.psk)) + self.psk)
        pre_full = None
        if self.psk_full:
            pre_full = (struct.pack(">H", len(self.shared)) + self.shared
                        + struct.pack(">H", len(self.psk_full)) + self.psk_full)
        self.schemes = _build_schemes(pre, pre_full, self.transcript,
                                      self.client_random, self.server_random)
        self._j(ev="derive", shared=self.shared.hex(), pre=pre.hex(),
                priv=self.priv_raw.hex(), random=self.random.hex(),
                pub=self.pub.hex(),
                client_random=(self.client_random or b"").hex(),
                server_random=(self.server_random or b"").hex(),
                transcript=self.transcript.hex(),
                schemes=[{"name": s.name, "master": s.master.hex(),
                          "keys": [k.hex() for k in s.keys]}
                         for s in self.schemes])

    def adopt_scheme_by_name(self, name):
        """Adopt the scheme with this name from our own candidate list
        (built over OUR transcript), mirroring a discovery on the other
        leg."""
        for s in self.schemes:
            if s.name == name:
                self.scheme = s
                return True
        return False

    def _wk(self, scheme=None):
        scheme = scheme or self.scheme or self.schemes[0]
        ckey, civ, skey, siv = scheme.keys
        if self.role == "server":
            return skey, siv, ckey, civ
        return ckey, civ, skey, siv

    @staticmethod
    def _aad_nonce(variant, iv, epoch, seq, rtype, ver, plen):
        es = struct.pack(">H", epoch) + seq.to_bytes(6, "big")
        nonce = bytearray(iv)
        if variant == "nonce_no_es":
            for i in range(6):
                nonce[6 + i] ^= seq.to_bytes(6, "big")[i]
        else:
            for i in range(8):
                nonce[4 + i] ^= es[i]
        if variant == "rfc" or variant == "nonce_no_es":
            aad = es + bytes([rtype]) + ver + struct.pack(">H", plen)
        elif variant == "aad_no_es":
            aad = bytes([rtype]) + ver + struct.pack(">H", plen)
        elif variant == "aad_rechdr":
            aad = (bytes([rtype]) + ver + struct.pack(">H", epoch)
                   + seq.to_bytes(6, "big") + struct.pack(">H", plen))
        return bytes(nonce), aad

    def encrypt_record_at(self, rtype, plaintext, epoch, seq):
        wkey, wiv, _, _ = self._wk()
        nonce, aad = self._aad_nonce(self.aad_variant, wiv, epoch, seq,
                                     rtype, b"\xfe\xfd", len(plaintext))
        ct = ChaCha20Poly1305(wkey).encrypt(nonce, plaintext, aad)
        return build_record(rtype, epoch, seq, ct)

    def encrypt_record(self, rtype, plaintext):
        rec = self.encrypt_record_at(rtype, plaintext, self.s_epoch,
                                     self.s_seq)
        self.s_seq += 1
        return rec

    def _try_decrypt(self, scheme, variant, rtype, ver, epoch, seq, body):
        _, _, rkey, riv = self._wk(scheme)
        try:
            nonce, aad = self._aad_nonce(variant, riv, epoch, seq, rtype,
                                         ver, len(body) - 16)
            return ChaCha20Poly1305(rkey).decrypt(nonce, body, aad)
        except Exception:  # noqa: BLE001
            return None

    def decrypt_record(self, rtype, ver, epoch, seq, body):
        """Decrypt an epoch-1 record; cascades construction variants until
        one works, then adopts it. Returns plaintext."""
        if self.scheme is not None:
            pt = self._try_decrypt(self.scheme, self.aad_variant, rtype,
                                   ver, epoch, seq, body)
            if pt is not None:
                return pt
            self._j(ev="adopted_decrypt_failed",
                    scheme=self.scheme.name, aad=self.aad_variant,
                    rtype=rtype, epoch=epoch, seq=seq, body=body.hex())
            raise BadRecord(
                f"decrypt failed with adopted {self.scheme.name}/"
                f"{self.aad_variant}")
        for scheme in self.schemes:
            for variant in AAD_VARIANTS:
                pt = self._try_decrypt(scheme, variant, rtype, ver, epoch,
                                       seq, body)
                if pt is not None:
                    self.scheme = scheme
                    self.aad_variant = variant
                    self._j(ev="discover", scheme=scheme.name, aad=variant)
                    return pt
        self._j(ev="decrypt_exhausted", rtype=rtype, epoch=epoch, seq=seq,
                body=body.hex())
        raise ValueError("no construction variant decrypts the record")

    def _fin(self, label, extra=b""):
        scheme = self.scheme or self.schemes[0]
        return scheme.fin(label, self.transcript, extra)

    def _dedupe_hs(self, msg):
        key = (msg[0], msg[1])
        if key in self.seen_mseq:
            return True
        self.seen_mseq.add(key)
        return False

    # =========================================================== server role
    def server_on_ch(self, ch_msg):
        """Phone's ClientHello -> my SH+SKE+SHD flight (166 B)."""
        mtype, mseq, msg = ch_msg
        if self._dedupe_hs(ch_msg):
            return None            # retransmission: caller resends last flight
        if self.state != "start":
            raise ValueError(f"CH in state {self.state}")
        self.transcript += msg
        self.client_random = msg[14:46]

        sh = bytearray(self.tpl.sh)
        sh[2:34] = self.random
        ske = bytearray(self.tpl.ske)
        ske[6:38] = self.pub
        flight = b""
        for mtype_, mseq_, body in ((HS_SH, 0, bytes(sh)),
                                    (HS_SKE, 1, bytes(ske)),
                                    (HS_SHD, 2, b"")):
            m = hs_msg(mtype_, mseq_, body)
            self.transcript += m
            flight += build_record(RT_HANDSHAKE, self.s_epoch, self.s_seq, m)
            self.s_seq += 1
        self.server_random = bytes(self.random)
        self.state = "wait_cke"
        self.last_flight = flight
        self._j(ev="sh_flight", flight=flight.hex())
        return flight

    def server_on_cke(self, cke_msg):
        """Phone's CKE: derive keys. No output (flight follows their Fin)."""
        mtype, mseq, msg = cke_msg
        if self._dedupe_hs(cke_msg):
            return None
        if self.state != "wait_cke":
            raise ValueError(f"CKE in state {self.state}")
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
            self.r_epoch = 1
            self.state = "wait_fin"

    def server_on_fin(self, plaintext):
        """Decrypted phone Finished -> my NST+CCS+Fin flight (274 B)."""
        for mtype, mseq, msg in parse_hs(plaintext):
            if mtype != HS_FIN:
                continue
            if self.state != "wait_fin":
                return None
            verified = None
            for label in FIN_LABELS[:1] + FIN_LABELS[2:]:
                if hmac.compare_digest(self._fin(label), msg[12:24]):
                    verified = label
                    break
            if verified is None:
                self._j(ev="fin_verify_failed", direction="phone",
                        plaintext=plaintext.hex())
                raise ValueError("phone Finished mismatch")
            self.peer_fin_label = verified
            self.peer_fin_msg = msg
            return self._build_nst_flight()
        return None

    def _build_nst_flight(self):
        if getattr(self, "skip_nst", False):
            # pion-compat test path: no session ticket (pion clients don't
            # advertise 0x0023, so a TUTK camera wouldn't send NST either)
            self._nst_rec = b""
            self._ccs_rec = build_record(RT_CCS, 0, 3, b"\x01")
            self.s_epoch, self.s_seq = 1, 1  # Fin took (1,0); appdata: (1,1)+
            return self._finish_nst_flight()
        nst = bytearray(self.tpl.nst)
        nst[6:] = os.urandom(len(nst) - 6)
        nst_msg = hs_msg(HS_NST, 3, bytes(nst))
        self._nst_rec = build_record(RT_HANDSHAKE, 0, 3, nst_msg)
        self._ccs_rec = build_record(RT_CCS, 0, 4, b"\x01")
        self.s_epoch, self.s_seq = 1, 1  # Fin took (1,0); appdata: (1,1)+
        return self._finish_nst_flight()

    def _finish_nst_flight(self):
        """(Re)build the NST+CCS+Fin flight with the current scheme."""
        nst = self._nst_msg() if (self._nst_rec and self.nst_in_hash) else b""
        extra = self.peer_fin_msg + nst
        self._fin_pt = hs_msg(
            HS_FIN, 4 if self._nst_rec else 3,
            self._fin("server finished", extra))
        fin_rec = self.encrypt_record_at(RT_HANDSHAKE, self._fin_pt, 1, 0)
        flight = self._nst_rec + self._ccs_rec + fin_rec
        self.state = "done"
        self.handshake_done = True
        self.last_flight = flight
        self._j(ev="nst_flight", nst_in_hash=self.nst_in_hash,
                flight=flight.hex())
        return flight

    def _nst_msg(self):
        # the NST handshake message inside the stored NST record
        return self._nst_rec[13:]

    def server_retry_nst_flight(self):
        """Phone retransmitted its CKE flight after our NST flight: try the
        alternate NST-in-hash formula."""
        self.nst_in_hash = not self.nst_in_hash
        return self._finish_nst_flight()

    # =========================================================== client role
    def client_hello(self):
        """My ClientHello flight (257 B)."""
        ch = bytearray(self.tpl.ch)
        ch[2:34] = self.random
        msg = hs_msg(HS_CH, self.msg_seq_base, bytes(ch))
        self.transcript += msg
        self.client_random = bytes(self.random)
        # record-layer version fe ff (DTLS 1.0), as the real phone sends
        # its ClientHello (run8 capture); later records use fe fd
        self.last_flight = build_record(RT_HANDSHAKE, self.s_epoch,
                                        self.s_seq, msg, version=b"\xfe\xff")
        self.s_seq += 1
        self._j(ev="ch_flight", flight=self.last_flight.hex(),
                priv=self.priv_raw.hex(), random=self.random.hex())
        return self.last_flight

    def client_on_server_flight(self, messages):
        """Camera's SH/SKE/SHD -> my CKE+CCS+Fin flight (140 B)."""
        for msg in messages:
            mtype, mseq, m = msg
            if self._dedupe_hs(msg):
                continue
            if mtype == HS_NST:
                self.cam_nst = m    # hashed before the camera's Fin
                continue
            if self.state == "start" and mtype == HS_SH:
                self.transcript += m
                self.server_random = m[14:46]
                self.state = "got_sh"
            elif self.state == "got_sh" and mtype == HS_SKE:
                self.transcript += m
                body = m[12:]
                self.cam_point = body[6:38]
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
        return self._build_cke_flight()

    def _build_cke_flight(self):
        cke = bytearray(self.tpl.cke)
        cke[16:48] = self.pub
        msg = hs_msg(HS_CKE, self.msg_seq_base + 1, bytes(cke))
        self.transcript += msg
        self._derive(self.cam_point)
        prefix = build_record(RT_HANDSHAKE, self.s_epoch, self.s_seq, msg)
        self.s_seq += 1
        self._ccs_rec = build_record(RT_CCS, self.s_epoch, self.s_seq,
                                     b"\x01")
        self.s_seq += 1
        self._fin_pt = hs_msg(HS_FIN, self.msg_seq_base + 2,
                              self._fin("client finished"))
        self.my_fin_msg = self._fin_pt
        self._fin_pos = (1, 0)
        fin_rec = self.encrypt_record_at(RT_HANDSHAKE, self._fin_pt, 1, 0)
        self.s_epoch, self.s_seq = 1, 1  # next appdata record: (1,1)
        flight = prefix + self._ccs_rec + fin_rec
        self.state = "wait_cam_fin"
        self.last_flight = flight
        self._j(ev="cke_flight", flight=flight.hex())
        return flight

    def client_rebuild_flight(self):
        """Re-derive and re-encrypt the client Fin under the CURRENT scheme
        (an adopted scheme changes the master, hence the verify_data); same
        record positions, same sizes."""
        if self._fin_pt is None:
            return None
        label = ("finished" if getattr(self, "_fin_label_alt", False)
                 else "client finished")
        self._fin_pt = hs_msg(HS_FIN, self.msg_seq_base + 2,
                              self._fin(label))
        self.my_fin_msg = self._fin_pt
        fin_rec = self.encrypt_record_at(RT_HANDSHAKE, self._fin_pt,
                                         *self._fin_pos)
        # last_flight = CKE rec + CCS rec + Fin rec (Fin last, same length)
        self.last_flight = self.last_flight[:len(self.last_flight) - len(fin_rec)] + fin_rec
        self._j(ev="cke_flight_rebuilt", scheme=(self.scheme.name if
                                                  self.scheme else None),
                flight=self.last_flight.hex())
        return self.last_flight

    def client_retry_flight(self):
        """Camera rejected our CKE flight again: flip the client-Finished
        label ('client finished' <-> 'finished') and rebuild."""
        if self._fin_pt is None:
            return None
        self._fin_label_alt = not getattr(self, "_fin_label_alt", False)
        label = "finished" if self._fin_label_alt else "client finished"
        self._fin_pt = hs_msg(HS_FIN, self.msg_seq_base + 2,
                              self._fin(label))
        self.my_fin_msg = self._fin_pt
        self._j(ev="cke_flight_label_retry", label=label)
        return self.client_rebuild_flight()

    def client_on_ccs(self):
        if self.state == "wait_cam_fin":
            self.r_epoch = 1
            self.state = "cam_fin"

    def client_on_fin(self, plaintext):
        """Decrypted camera Finished -> verify; handshake complete."""
        for mtype, mseq, msg in parse_hs(plaintext):
            if mtype != HS_FIN:
                continue
            if self.state != "cam_fin":
                return None
            verified = None
            for label in FIN_LABELS[1:]:
                extra = self.my_fin_msg + (self.cam_nst or b"")
                if hmac.compare_digest(self._fin(label, extra), msg[12:24]):
                    verified = label
                    break
                if self.cam_nst:
                    # alternate: camera Fin hash excludes the NST
                    if hmac.compare_digest(
                            self._fin(label, self.my_fin_msg), msg[12:24]):
                        verified = label + "/no_nst"
                        break
            if verified is None:
                self._j(ev="fin_verify_failed", direction="camera",
                        plaintext=plaintext.hex())
                raise ValueError("camera Finished mismatch")
            self.peer_fin_label = verified
            self.state = "done"
            self.handshake_done = True
            self._j(ev="handshake_done", fin_label=verified)
            return b""
        return None


# ---------------------------------------------------------------------------
# Templates: verified bytes extracted from a live capture. Only randoms and
# key material are swapped.
# ---------------------------------------------------------------------------

FLIGHT_SIZES = {"ch": 257, "sh_flight": 166, "cke_flight": 140,
                "nst_flight": 274}

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

    @classmethod
    def from_json(cls, path):
        with open(path) as f:
            d = json.load(f)["templates"]
        return cls(*(bytes.fromhex(d[k]) for k in
                     ("ch", "sh", "ske", "cke_body", "nst")))
