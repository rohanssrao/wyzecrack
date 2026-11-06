"""A fake Wyze camera, for tests of direct.py (on localhost) and the lab
(`python tests/fakecam.py --host 10.99.0.20 ...` in the camera namespace).

It answers a LAN session the way the real cameras do, in either framing
(0xCC51 like the v3, TransCode IOTC like the v2): discovery, DTLS-PSK as
the server (dtls.DTLSLeg's server role), the AV login, the K10000/K10002
challenge, K10056 and K10010, and then it streams the H.264 access units
it was given, one plain-format record per frame, plus a keepalive every
second. Knobs for the failure cases: login_delay (a slow camera),
ignore_logins (sessions whose AV login is never answered), and
quiet (stop sending everything, as when a camera drops off its Wi-Fi;
quiet_after sets it that many seconds into the live view, quiet_for ends
it after that long).
"""
import hashlib
import hmac
import json
import os
import select
import socket
import struct
import threading
import time

from wyzecrack import direct
from wyzecrack.dtls import (HS_CH, HS_CKE, RT_APPDATA, RT_CCS, RT_HANDSHAKE,
                              DTLSLeg, Templates, derive_psk, parse_hs,
                              parse_records)
from wyzecrack.tutk import trans_code_blob, untrans_code_blob

CC51, IOTC = "cc51", "iotc"


def xxtea_encrypt(data, key):
    """XXTEA encryption, the inverse of direct.xxtea_decrypt."""
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


def media_record(frame_no, au, key, version=0x0C, channel=None):
    """One plain-format record carrying a whole frame (FrameInfo after it)."""
    ch = channel if channel is not None else (5 if key else 7)
    info = bytes((0x4E, 0, 1 if key else 0)) + bytes(37)
    payload = au + info
    outer = bytes((ch, 0x01)) + struct.pack("<HHH", version, frame_no & 0xFFFF, 0)
    inner = (bytes((ch, 1)) + struct.pack("<HHHHH", frame_no & 0xFFFF, 1, 0x28,
                                          len(payload), 0)
             + struct.pack("<II", max(frame_no - 1, 0), frame_no))
    return outer + inner + payload


class FakeCamera:
    def __init__(self, uid, enr, mac, framing=CC51, frames=(), login_delay=0.0,
                 fps=20.0, host="127.0.0.1", disco_port=0, quiet_after=None,
                 quiet_for=None, ignore_logins=()):
        self.uid, self.enr, self.framing = uid.encode(), enr, framing
        self.authkey = direct.auth_key(enr, mac)
        self.key = self.uid + self.authkey
        self.frames, self.login_delay, self.fps = list(frames), login_delay, fps
        self.disco = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.disco.bind((host, disco_port))
        self.p2p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.p2p.bind((host, 0))
        self.disco_port = self.disco.getsockname()[1]
        self.ticket, self.sid, self.client = 0x4D2, None, None
        self.events = []                     # what the client did, in order
        self.sessions = 0
        self._new_session()
        self.quiet = False
        self.quiet_after = quiet_after
        self.quiet_for = quiet_for          # None: quiet for good
        self.quiet_since = None
        self.ignore_logins = set(ignore_logins)   # sessions (1, 2, ...) left waiting
        self._stop = threading.Event()
        self._tx_seq = 0
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _new_session(self):
        """A client started over (a new session id): forget the last one."""
        self.leg = None
        self.login_at = None                 # when the AV login arrived
        self.answered_login = False
        self.secret = os.urandom(16)
        self.media_on = {1: False, 2: False}
        self.live_at = None                  # when media was switched on
        self.next_frame = 0                  # frame numbers restart too
        self.sessions += 1

    def close(self):
        self._stop.set()
        self.thread.join(2)
        self.disco.close()
        self.p2p.close()

    # ------------------------------------------------------------ framing
    def _cc51(self, cmd, head_tail=b"", extra=b""):
        b = bytearray(28)
        b[0:2] = b"\x51\xcc"
        struct.pack_into("<HH", b, 4, cmd, 16 + len(extra) + 20)
        b[8:28] = head_tail.ljust(20, b"\0")[:20]
        return bytes(b) + extra + hmac.new(self.key, bytes(b), hashlib.sha1).digest()

    def _iotc(self, cmd, body, mode=0x02, channel=None):
        if channel is None:
            h = bytearray(16)
            h[0:4] = bytes((0x04, 0x02, 0x1A, mode))
            struct.pack_into("<HHHH", h, 4, len(body), 0, cmd, 0x0021)
            return trans_code_blob(bytes(h) + body)
        h = bytearray(28)
        h[0:4] = b"\x04\x02\x1a\x0b"
        struct.pack_into("<HHHH", h, 4, 12 + len(body), self._tx_seq, cmd, 0x0021)
        self._tx_seq = (self._tx_seq + 1) & 0xFFFF
        h[12:14] = (self.sid or bytes(8))[:2]
        h[14], h[15] = channel, 1
        struct.pack_into("<I", h, 16, 0x0C)
        h[20:28] = self.sid or bytes(8)
        return trans_code_blob(bytes(h) + body)

    def _send_records(self, records):
        if self.client is None or self.quiet:
            return
        if self.framing == CC51:
            head = bytearray(20)
            struct.pack_into("<HH", head, 4, 0x0010, self.ticket)
            head[8:16] = self.sid
            struct.pack_into("<I", head, 16, 1)
            pkt = self._cc51(direct.CMD_DTLS, bytes(head), records)
        else:
            pkt = self._iotc(direct.IOTC_DATA_RX, records, channel=0)
        self.p2p.sendto(pkt, self.client)

    def _send_app(self, plaintext):
        self._send_records(self.leg.encrypt_record(RT_APPDATA, plaintext))

    def _reply(self, cmd, payload):
        self._send_app(struct.pack("<HH", direct.MAGIC_IOCTRL, direct.PROTO)
                       + bytes(28) + direct.hl(cmd, payload))

    # ------------------------------------------------------------- loop
    def _run(self):
        last_ka = 0.0
        while not self._stop.is_set():
            now = time.monotonic()
            if self.client and not self.quiet and now - last_ka >= 1.0:
                self._keepalive()
                last_ka = now
            if (self.login_at is not None and not self.answered_login
                    and now - self.login_at >= self.login_delay):
                self._answer_login()
            if self.live_at is None and self.media_on[1]:
                self.live_at = now
            if (self.quiet_after is not None and self.live_at is not None
                    and now - self.live_at >= self.quiet_after and not self.quiet
                    and self.quiet_since is None):
                self.quiet, self.quiet_since = True, now
                self.events.append("went quiet")
            if (self.quiet and self.quiet_for is not None
                    and now - self.quiet_since >= self.quiet_for):
                self.quiet = False           # back, for a new session
                self.client = None
                self.media_on = {1: False, 2: False}
                self.events.append("back")
            self._stream(now)
            r, _, _ = select.select([self.disco, self.p2p], [], [], 0.01)
            for s in r:
                try:
                    d, addr = s.recvfrom(65535)
                except OSError:
                    continue
                if not self.quiet:
                    self._packet(d, addr)

    def _keepalive(self):
        if self.framing == CC51:
            head = bytearray(20)
            struct.pack_into("<I", head, 8, int(time.time()) & 0xFFFFFFFF)
            head[12:20] = self.sid or bytes(8)
            self.p2p.sendto(self._cc51(direct.CMD_KEEPALIVE, bytes(head)), self.client)
        else:
            self.p2p.sendto(self._iotc(direct.IOTC_KEEPALIVE_RES, os.urandom(8),
                                       mode=0x0A), self.client)

    def _stream(self, now):
        if not (self.media_on[1] and self.frames and self.leg
                and self.leg.handshake_done):
            return
        if now < getattr(self, "_frame_due", 0):
            return
        self._frame_due = now + 1 / self.fps
        i = self.next_frame % len(self.frames)
        au = self.frames[i]
        version = 0x0C if self.framing == CC51 else 0x0B
        self._send_app(media_record(self.next_frame + 1, au, key=(i == 0),
                                    version=version))
        self.next_frame += 1

    def _packet(self, d, addr):
        if self.framing == CC51:
            if d[:2] != b"\x51\xcc" or len(d) < 48:
                return
            cmd = struct.unpack_from("<H", d, 4)[0]
            span = 32 if cmd == direct.CMD_DISCO else 28
            if not hmac.compare_digest(
                    hmac.new(self.key, d[:span], hashlib.sha1).digest(), d[-20:]):
                self.events.append("bad trailer")
                return
            if cmd == direct.CMD_DISCO:
                seq = struct.unpack_from("<H", d, 12)[0]
                self.client = addr
                if seq == 0:
                    if self.sid is not None and d[16:24] != self.sid:
                        self._new_session()
                    self.sid = d[16:24]
                    self.events.append("discovery")
                    self._disco_reply(1)
                elif seq == 2:
                    self._disco_reply(3)
            elif cmd == direct.CMD_DTLS:
                self._records(d[28:-20])
            elif cmd == direct.CMD_KEEPALIVE and "keepalive" not in self.events:
                self.events.append("keepalive")
            elif cmd == direct.CMD_CLOSE and d[20:28] == self.sid and self.client:
                self.events.append("close")          # the session ends now
                self.client = None
                self.media_on = {1: False, 2: False}
            return
        if d[:2] == b"\x51\xcc":
            return                               # this camera only speaks IOTC
        p = untrans_code_blob(d)
        if p[:2] != b"\x04\x02":
            return
        cmd = struct.unpack_from("<H", p, 8)[0]
        stage = p[16 + 48] if len(p) > 16 + 48 else 0
        if (cmd == direct.IOTC_DISCO_REQ and p[16:36].rstrip(b"\0") == self.uid
                and stage == 1):
            if p[16 + 58:16 + 66] != self.authkey:
                self.events.append("bad authkey")
                return
            self.client = addr
            if self.sid is not None and p[16 + 40:16 + 48] != self.sid:
                self._new_session()
            self.sid = p[16 + 40:16 + 48]
            self.events.append("discovery")
            self.p2p.sendto(self._iotc(direct.IOTC_DISCO_RES, bytes(72)), addr)
        elif cmd == direct.IOTC_SESSION_REQ and self.client == addr:
            self.p2p.sendto(self._iotc(direct.IOTC_SESSION_RES, bytes(36)), addr)
        elif cmd == direct.IOTC_DATA_TX and len(p) > 28:
            self._records(p[28:])
        elif cmd == direct.IOTC_KEEPALIVE_REQ and "keepalive" not in self.events:
            self.events.append("keepalive")

    def _disco_reply(self, seq):
        head = bytearray(20)
        struct.pack_into("<HHH", head, 0, 0xFFFF, 0, 0)
        struct.pack_into("<HH", head, 4, seq, self.ticket)
        head[8:16] = self.sid
        head[16:20] = direct.SDK_VERSION
        b = bytearray(32)
        b[0:2] = b"\x51\xcc"
        struct.pack_into("<HH", b, 4, direct.CMD_DISCO, 0x28)
        b[8:28] = head
        b[28] = 0x1D
        self.p2p.sendto(bytes(b) + hmac.new(self.key, bytes(b), hashlib.sha1).digest(),
                        self.client)

    # ------------------------------------------------------------- DTLS + AV
    def _records(self, payload):
        if self.leg is None:
            self.leg = DTLSLeg("server", derive_psk(self.enr), Templates.embedded())
        leg, out = self.leg, b""
        for rtype, ver, epoch, seq, body in parse_records(payload):
            if rtype == RT_HANDSHAKE and epoch == 0:
                for msg in parse_hs(body):
                    if msg[0] == HS_CH:
                        f = leg.server_on_ch(msg)
                        out = f if f is not None else leg.last_flight
                    elif msg[0] == HS_CKE:
                        leg.server_on_cke(msg)
            elif rtype == RT_CCS:
                leg.server_on_ccs()
            elif epoch == 1:
                try:
                    pt = leg.decrypt_record(rtype, ver, epoch, seq, body)
                except Exception:  # noqa: BLE001
                    self.events.append("undecryptable")
                    continue
                if rtype == RT_HANDSHAKE:
                    f = leg.server_on_fin(pt)
                    if f:
                        self.events.append("handshake")
                        out = f
                elif rtype == RT_APPDATA:
                    self._app(pt)
        if out:
            self._send_records(out)

    def _app(self, pt):
        magic = struct.unpack_from("<H", pt, 0)[0] if len(pt) >= 2 else None
        if magic in (0x0000, 0x2000) and len(pt) in (570, 572):
            if self.sessions in self.ignore_logins:
                return                   # a real camera does this at times
            if self.login_at is None:
                self.login_at = time.monotonic()
                self.events.append("login")
            return
        r = direct.find_hl(pt) if magic == direct.PROTO else None
        if not r or not self.answered_login:
            return
        cmd, payload = r
        self.events.append(f"K{cmd}" + (f" {payload.hex()}" if cmd == direct.K_CHANNEL else ""))
        if cmd == direct.K_AUTH:
            key = self.enr.encode()[:16].ljust(16, b"\0")
            self._reply(direct.K_CHALLENGE, bytes((3,)) + xxtea_encrypt(self.secret, key))
        elif cmd == direct.K_CHALLENGE_RESP:
            ok = payload[:16] == self.secret
            self._reply(direct.K_AUTH_RESULT, json.dumps(
                {"connectionRes": "1" if ok else "2",
                 "cameraInfo": {"videoParm": {"type": "H264"}}}).encode())
            if ok and len(payload) >= 22:
                self.media_on = {1: payload[20] == 1, 2: payload[21] == 1}
        elif cmd == direct.K_RESOLUTION:
            self._reply(direct.K_RESOLUTION_RESP, b"\x01")
        elif cmd == direct.K_CHANNEL and len(payload) >= 2:
            self.media_on[payload[0]] = payload[1] == 1
            self._reply(direct.K_CHANNEL_RESP, bytes((payload[0], 1)))

    def _answer_login(self):
        self.answered_login = True
        b = bytearray(60)
        struct.pack_into("<HH", b, 0, direct.MAGIC_LOGIN_RESP, direct.PROTO)
        b[4] = 0x10
        struct.pack_into("<I", b, 16, 0x24)
        b[29], b[31] = 1, 1
        self._send_app(bytes(b))


def main():
    """The lab's camera: serve until --seconds pass, then write what the
    client did (events, frames sent) as JSON to stdout."""
    import argparse
    import sys
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--mac", required=True)
    ap.add_argument("--uid", default="ABCDEFGHJKLMNPQR111A")
    ap.add_argument("--enr", default="gekMdn0XjZoWF/mD")
    ap.add_argument("--framing", choices=(CC51, IOTC), default=CC51)
    ap.add_argument("--seconds", type=float, default=20)
    ap.add_argument("--login-delay", type=float, default=0)
    ap.add_argument("--quiet-after", type=float)
    ap.add_argument("--quiet-for", type=float)
    a = ap.parse_args()
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from test_jpegfeed import _h264_frames
    cam = FakeCamera(a.uid, a.enr, a.mac, a.framing, frames=_h264_frames(n=20),
                     login_delay=a.login_delay, host=a.host,
                     disco_port=direct.DISCO_PORT, quiet_after=a.quiet_after,
                     quiet_for=a.quiet_for)
    print(f"fake camera on {a.host}:{direct.DISCO_PORT} ({a.framing})",
          file=sys.stderr, flush=True)
    try:
        time.sleep(a.seconds)
    finally:
        cam.close()
    print(json.dumps({"events": cam.events, "frames_sent": cam.next_frame}))


if __name__ == "__main__":
    main()
