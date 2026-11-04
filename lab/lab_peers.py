"""Fake camera / fake phone-via-relay for the netns splice lab.

Both speak format-exact 0xCC51 wrappers and real DTLS (dtls_splice.DTLSLeg),
shaped after the real run7 relay sessions (2026-10-25 11:40, phone on
cellular):

  * camera opens a relay channel with a 0x1102 exchange, phone's plain
    ClientHello follows ~450 ms later, phone retransmits it after ~1 s
  * the camera sends every media datagram twice, plus 0x1202 keepalives
    every second on every relay tuple it ever opened (they outlive the
    session, like the ghost keepalives on :12977)
  * FAIL_FIRST=1: the first session fails AT THE CAMERA the way 12977 did
    (it answers the CH, never accepts the CKE flight, retransmits its server
    flight with backoff); the phone gives up after ~2 s and the camera opens
    a second relay port 13 s after the first, where the session works
  * CAM_IGNORE_FIRST_CH=1: the camera ignores the first ClientHello of each
    session and answers the retransmit (the 11781 session did this)

Each side logs the source address of everything it receives, so 5-tuple
corruption by the splice shows up directly.
"""
import hashlib
import json
import os
import socket
import struct
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [REPO, os.path.join(REPO, "tests")]
from test_engine_roundtrip import wrap, unwrap, PSK   # noqa: E402
from wyze_splice.dtls import (DTLSLeg, Templates, RT_APPDATA, RT_HANDSHAKE,  # noqa: E402
                              RT_CCS, HS_CH, HS_CKE, parse_records, parse_hs)

CAM = ("10.99.0.20", 33446)
RELAYS = [("203.0.113.1", 12977), ("203.0.113.1", 11781)]
STUN = ("203.0.113.2", 3478)
# MULTIPATH=1: as seen live -- the phone's ClientHello (and its
# retransmits) travel via the STUN relay as cmd 0x1402; the camera answers on
# the data relay and the session continues there
MULTIPATH = os.environ.get("MULTIPATH") == "1"
FAIL_FIRST = os.environ.get("FAIL_FIRST") == "1"
IGNORE_FIRST_CH = os.environ.get("CAM_IGNORE_FIRST_CH") == "1"
# DIE_FIRST=1: run8's failure. The first session completes its handshake, the
# camera answers a few app messages, then closes that relay channel for good
# (no media, no keepalives, ignores everything) while the phone keeps sending;
# the camera opens a second relay port 13 s later, where the session works.
DIE_FIRST = os.environ.get("DIE_FIRST") == "1"
MEDIA_SECS = float(os.environ.get("MEDIA_SECS", "8"))
MEDIA_PPS = int(os.environ.get("MEDIA_PPS", "60"))
SIZES = (1060, 1060, 800, 60, 1060, 45, 1060, 300)


def media_pt(i):
    n = SIZES[i % len(SIZES)]
    seed = hashlib.sha256(struct.pack("<I", i)).digest()
    return b"\x0c\x00" + struct.pack("<I", i) + (seed * (n // 32 + 1))[:n]


def tag(w, port):
    """Stamp a per-session wrapper ticket (bytes 14:16) and session id
    (bytes 16:24), as real sessions have: both differ between sessions."""
    w = bytearray(w)
    w[14:16] = struct.pack("<H", port & 0xffff)
    w[16:18] = struct.pack("<H", port & 0xffff)
    return bytes(w)


# live (2026-11-04): a session's 0x1402 wrappers on the STUN-relay path
# carry a different ticket than its 0x1502 wrappers on the data relay;
# the session id (16:24) is the same on both
STUN_TICKET_XOR = 0xD18B


def as_stun(w):
    """The same wrapper as sent over the STUN relay: cmd 0x1402 and that
    path's own ticket."""
    w = bytearray(w)
    struct.pack_into("<H", w, 4, 0x1402)
    t = struct.unpack_from("<H", w, 14)[0]
    struct.pack_into("<H", w, 14, t ^ STUN_TICKET_XOR)
    return bytes(w)


def ctl(cmd, size):
    h = bytearray(size)
    h[0:2] = b"\x51\xcc"
    struct.pack_into("<H", h, 4, cmd)
    struct.pack_into("<H", h, 6, size - 12)
    return bytes(h)


def cmd_of(d):
    return struct.unpack("<H", d[4:6])[0] if len(d) >= 8 and d[:2] == b"\x51\xcc" else None


class CamSession:
    def __init__(self, relay, broken):
        self.relay = relay
        self.broken = broken
        self.leg = DTLSLeg("server", PSK, Templates.embedded())
        self.opens = 0
        self.ch_seen = 0
        self.media_i = 0
        self.next_media = None
        self.retx_at = None
        self.retx_gap = 0.5
        self.acks = set()
        self.dead = False


def run_cam(dur):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(CAM)
    s.settimeout(0.005)
    t0 = time.time()
    sessions = {RELAYS[0]: CamSession(RELAYS[0], FAIL_FIRST)}
    s.sendto(ctl(0x1102, 52), RELAYS[0])
    sessions[RELAYS[0]].opens = 1
    srcs, last_ka = {}, 0.0
    n_media = int(MEDIA_SECS * MEDIA_PPS)
    while time.time() - t0 < dur:
        now = time.time()
        if (FAIL_FIRST or DIE_FIRST) and RELAYS[1] not in sessions and now - t0 > 13.0:
            sessions[RELAYS[1]] = CamSession(RELAYS[1], False)
            s.sendto(ctl(0x1102, 52), RELAYS[1])
            sessions[RELAYS[1]].opens = 1
        if now - last_ka > 1.0:
            for r, cs_ in sessions.items():
                if not cs_.dead:
                    s.sendto(ctl(0x1202, 48), r)
            s.sendto(ctl(0x0502, 24), STUN)
            last_ka = now
        for cs in sessions.values():
            leg = cs.leg
            if cs.broken and cs.retx_at and now >= cs.retx_at:
                # the 12977 failure: keep retransmitting the server flight
                s.sendto(tag(wrap(leg.last_flight, cam_side=True), cs.relay[1]), cs.relay)
                cs.retx_gap *= 2
                cs.retx_at = now + cs.retx_gap
            if (leg.handshake_done and not cs.dead and cs.media_i < n_media
                    and (cs.next_media is None or now >= cs.next_media)):
                w = tag(wrap(leg.encrypt_record(RT_APPDATA, media_pt(cs.media_i)), cam_side=True), cs.relay[1])
                s.sendto(w, cs.relay)
                s.sendto(w, cs.relay)
                cs.media_i += 1
                cs.next_media = now + 1.0 / MEDIA_PPS
        try:
            d, a = s.recvfrom(65535)
        except socket.timeout:
            continue
        srcs[f"{a[0]}:{a[1]}"] = srcs.get(f"{a[0]}:{a[1]}", 0) + 1
        c = cmd_of(d)
        if a == STUN and c == 0x1402:
            # same session, other path: the wrapper ticket names the session
            ticket = struct.unpack("<H", d[14:16])[0] ^ STUN_TICKET_XOR
            a = next((r for r in sessions if r[1] & 0xffff == ticket), RELAYS[0])
            cs, c = sessions.get(a), 0x1502           # camera answers on the data relay
        else:
            cs = sessions.get(a)
        if cs is None or cs.dead:
            continue
        if c == 0x1102 and cs.opens < 3:
            s.sendto(ctl(0x1102, 52), a)
            cs.opens += 1
        elif c == 0x1502:
            leg, out = cs.leg, b""
            for rtype, ver, epoch, seq, body in parse_records(unwrap(d)):
                if rtype == RT_HANDSHAKE and epoch == 0:
                    for msg in parse_hs(body):
                        if msg[0] == HS_CH:
                            cs.ch_seen += 1
                            if IGNORE_FIRST_CH and cs.ch_seen == 1:
                                continue
                            f = leg.server_on_ch(msg)
                            out = f if f is not None else leg.last_flight
                            if cs.broken:
                                cs.retx_at = time.time() + cs.retx_gap
                        elif msg[0] == HS_CKE and not cs.broken:
                            leg.server_on_cke(msg)
                elif cs.broken:
                    continue
                elif rtype == RT_CCS:
                    leg.server_on_ccs()
                elif epoch == 1:
                    try:
                        pt = leg.decrypt_record(rtype, ver, epoch, seq, body)
                    except Exception:
                        continue
                    if rtype == RT_HANDSHAKE:
                        f = leg.server_on_fin(pt)
                        if f:
                            out = f
                        elif leg.handshake_done:
                            out = leg.last_flight
                    elif rtype == RT_APPDATA:
                        cs.acks.add(pt)
                        if DIE_FIRST and cs.relay == RELAYS[0] and len(cs.acks) >= 3:
                            cs.dead = True
                            break
            if out and not cs.dead:
                s.sendto(tag(wrap(out, cam_side=True), cs.relay[1]), a)
    print(json.dumps({"role": "cam", "srcs": srcs, "sessions": {
        f"{r[1]}": {"handshake_done": cs.leg.handshake_done, "ch_seen": cs.ch_seen,
                    "sent_media": cs.media_i, "acks_unique": len(cs.acks),
                    "broken": cs.broken, "closed": cs.dead} for r, cs in sessions.items()}}))


class PhoneSession:
    def __init__(self, sock):
        self.s = sock
        self.leg = DTLSLeg("client", PSK, Templates.embedded())
        self.cam = None
        self.opened_at = None
        self.ch_sent = 0
        self.last_ch = 0.0
        self.first_ch = None
        self.last_ack = 0.0
        self.got = set()
        self.bad = 0
        self.decrypt_fail = 0
        self.gave_up = False
        self.srcs = {}


def run_phone(dur):
    socks = []
    for r in RELAYS:
        x = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        x.bind(r)
        x.setblocking(False)
        socks.append(PhoneSession(x))
    stun = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stun.bind(STUN)
    stun.setblocking(False)
    cam_via_stun = [None]
    t0 = time.time()
    import select
    while time.time() - t0 < dur:
        now = time.time()
        for ps in socks:
            leg = ps.leg
            if ps.gave_up:
                continue
            if ps.first_ch and not leg.handshake_done and now - ps.first_ch > 2.0:
                ps.gave_up = True        # the app abandons a stalled attempt at ~2 s
                continue
            if (ps.opened_at and leg.state == "start" and now - ps.opened_at > 0.45
                    and now - ps.last_ch > 1.0):
                f = leg.client_hello() if ps.ch_sent == 0 else leg.last_flight
                wch = tag(wrap(f, cam_side=False), ps.s.getsockname()[1])
                if MULTIPATH and cam_via_stun[0]:
                    stun.sendto(as_stun(wch), cam_via_stun[0])
                else:
                    ps.s.sendto(wch, ps.cam)
                ps.ch_sent += 1
                ps.last_ch = now
                ps.first_ch = ps.first_ch or now
            if leg.handshake_done and now - ps.last_ack > 0.1:
                p = leg.encrypt_record(RT_APPDATA, b"\x09\x00" + struct.pack("<I", int(now * 1000) & 0xffffffff)
                                       + struct.pack("<H", len(ps.got)) + b"\x00" * 14)
                ps.s.sendto(tag(wrap(p, cam_side=False), ps.s.getsockname()[1]), ps.cam)
                ps.last_ack = now
        ready, _, _ = select.select([ps.s for ps in socks] + [stun], [], [], 0.005)
        if stun in ready:
            while True:
                try:
                    d, a = stun.recvfrom(65535)
                except (BlockingIOError, OSError):
                    break
                if cmd_of(d) == 0x0502:
                    cam_via_stun[0] = a
                    stun.sendto(ctl(0x0502, 40), a)
        for ps in socks:
            if ps.s not in ready:
                continue
            while True:
                try:
                    d, a = ps.s.recvfrom(65535)
                except (BlockingIOError, OSError):
                    break
                ps.srcs[f"{a[0]}:{a[1]}"] = ps.srcs.get(f"{a[0]}:{a[1]}", 0) + 1
                c = cmd_of(d)
                if c == 0x1102:
                    ps.cam = a
                    ps.s.sendto(ctl(0x1102, 52), a)
                    ps.opened_at = ps.opened_at or time.time()
                elif c == 0x1202:
                    ps.s.sendto(ctl(0x1202, 48), a)
                elif c == 0x1502 and ps.cam and not ps.gave_up:
                    leg, out = ps.leg, b""
                    for rtype, ver, epoch, seq, body in parse_records(unwrap(d)):
                        if rtype == RT_HANDSHAKE and epoch == 0:
                            msgs = parse_hs(body)
                            if msgs:
                                f = leg.client_on_server_flight(msgs)
                                if f:
                                    out = f
                                elif leg.state == "wait_cam_fin":
                                    out = leg.last_flight
                        elif rtype == RT_CCS:
                            leg.client_on_ccs()
                        elif epoch == 1:
                            try:
                                pt = leg.decrypt_record(rtype, ver, epoch, seq, body)
                            except Exception:
                                ps.decrypt_fail += 1
                                continue
                            if rtype == RT_HANDSHAKE:
                                leg.client_on_fin(pt)
                            elif rtype == RT_APPDATA:
                                i = struct.unpack("<I", pt[2:6])[0]
                                if pt == media_pt(i):
                                    ps.got.add(i)
                                else:
                                    ps.bad += 1
                    if out:
                        ps.s.sendto(tag(wrap(out, cam_side=False), ps.s.getsockname()[1]), ps.cam)
    print(json.dumps({"role": "phone", "expected_media": int(MEDIA_SECS * MEDIA_PPS), "sessions": {
        f"{ps.s.getsockname()[1]}": {"handshake_done": ps.leg.handshake_done, "ch_sent": ps.ch_sent,
                                     "gave_up": ps.gave_up, "media_ok": len(ps.got), "media_bad": ps.bad,
                                     "decrypt_fail": ps.decrypt_fail, "srcs": ps.srcs}
        for ps in socks}}))


if __name__ == "__main__":
    (run_cam if sys.argv[1] == "cam" else run_phone)(float(sys.argv[2]))
