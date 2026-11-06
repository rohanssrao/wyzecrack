"""Watch a Wyze camera straight over the LAN, the way the Wyze app does when
it is on the camera's Wi-Fi: no phone, no interception.

This needs three per-camera values: its MAC, its ENR (read off the
camera's own HTTPS, see cloud.py) and its TUTK UID (which the Wyze cloud
returns for MAC + ENR, see cloud.fetch_uid).

The packets come in one of two framings, after go2rtc's pkg/tutk/dtls
and pkg/wyze, which interoperate with both. Discovery tries both, and the
camera's answer picks one.

SDK 4.3 (0xCC51; Wyze Cam v3 on 4.36.16 and 4.36.17):
  discovery  cmd 0x1002 to udp/32761. The camera answers from its P2P
             port with a ticket; four packets, seq 0..3.
  data       cmd 0x1502: a 28-byte header, DTLS records, a 20-byte trailer.
  keepalive  cmd 0x1202, both ways.
  trailer    HMAC-SHA1 keyed by UID + AuthKey over the first 28 bytes
             (32 for discovery). AuthKey comes from ENR + MAC. The camera
             ignores packets whose trailer is wrong.

The older IOTC framing (SDK 3.x/4.2; the Wyze Cam v2), obfuscated with
TransCode (tutk.py):
  discovery  cmd 0x0601 (UID and AuthKey in the body) to udp/32761, the
             camera answers 0x0602; then a session request 0x0402 -> 0x0404.
  data       cmd 0x0407 out, 0x0408 in: a 28-byte header, DTLS records.
  keepalive  the camera's 0x0428 is answered with a 0x0427 echo.

Inside the DTLS session (PSK from the ENR, see dtls.py): an AV login
whose password is the ENR, the K10000/K10002 challenge (XXTEA with the
ENR), then the camera streams. Every decrypted record goes to on_av and
av.bin, which live.py and media.py read.
"""
import base64
import hashlib
import hmac
import json
import os
import socket
import struct
import threading
import time

from .dtls import (HS_SH, HS_SHD, HS_SKE, RT_ALERT, RT_APPDATA, RT_CCS,
                   RT_HANDSHAKE, BadRecord, DTLSLeg, ReplayWindow, Templates,
                   derive_psk, parse_hs, parse_records)
from .tutk import trans_code_blob, untrans_code_blob

DISCO_PORT = 32761
CMD_DISCO, CMD_KEEPALIVE, CMD_DTLS = 0x1002, 0x1202, 0x1502
# the session close, laid out like a keepalive. The camera sends it (4x)
# when it gives up on a session; sent to it, it ends the session at once.
# Otherwise the camera keeps a closed session for its 30 s alive timeout,
# and it holds at most 5 (IOTC_Set_Max_Session_Number(5) in the firmware).
CMD_CLOSE = 0x1302
# the older IOTC framing
IOTC_DISCO_REQ, IOTC_DISCO_RES = 0x0601, 0x0602
IOTC_SESSION_REQ, IOTC_SESSION_RES = 0x0402, 0x0404
IOTC_DATA_TX, IOTC_DATA_RX = 0x0407, 0x0408
IOTC_KEEPALIVE_REQ, IOTC_KEEPALIVE_RES = 0x0427, 0x0428
IOTC_SDK_VERSION = b"\x01\x01\x02\x04"     # 4.2.1.1, as go2rtc sends
SDK_VERSION = b"\x00\x08\x03\x04"           # 4.3.8.0, as the app sends
PROTO = 0x000C
MAGIC_LOGIN_RESP, MAGIC_IOCTRL, MAGIC_ACK = 0x2100, 0x7000, 0x0009
CAPS = 0x001F07FB
K_AUTH, K_CHALLENGE, K_CHALLENGE_RESP, K_AUTH_RESULT = 10000, 10001, 10002, 10003
K_RESOLUTION, K_RESOLUTION_RESP = 10056, 10057
K_CHANNEL, K_CHANNEL_RESP = 10010, 10011    # [media, 1 on / 2 off]
MEDIA_VIDEO, MEDIA_AUDIO, CHANNEL_OFF = 1, 2, 2
OPEN_TIMEOUT = 30
# A camera answers some sessions' AV login (or DTLS handshake) at once and
# others only after 5-25 s, or never before it drops them at 30 s. Sessions
# are slow independently of each other: of two opened together, one logged
# in after 0.2 s and the other after 21 s (both v3s, 2026-11-05). So
# open_first() starts a second session beside a slow one and keeps
# whichever logs in first.
HEDGE_AFTER = 2.0         # a second session if the first hasn't logged in
ROTATE_EVERY = 6.0        # then the older one is replaced this often
AT_ONCE = 2               # the camera holds 5 sessions; others may be viewers
LOGIN_EVERY = 0.5         # the answer follows the first resend it takes
# a camera that is on answers discovery within 0.1 s; one that is switched
# off, offline, or set up again (a new key) never does
DISCO_GIVE_UP = 10.0
# a live view reconnects when the camera hangs up, and gives up after this
# many sessions in a row without a picture (the page and `watch` both)
RETRIES = 3
HD_1080P, BITRATE_MAX = 1, 0xF0             # K10056 frame size 0 (+1), kbps
ACK_EVERY = 0.1
SILENT_AFTER = 6.0                          # camera quiet this long: gone


class CameraGone(Exception):
    """The camera did not answer (or hung up)."""


def disco_packet(key, sid, seq=0, ticket=0):
    """A 0x1002 discovery packet (52 bytes) with its HMAC trailer."""
    b = bytearray(32)
    b[0:2] = b"\x51\xcc"
    struct.pack_into("<HH", b, 4, CMD_DISCO, 0x28)
    struct.pack_into("<HH", b, 12, seq, ticket)
    b[16:24] = sid
    b[24:28] = SDK_VERSION
    b[28] = 0x1D
    return bytes(b) + hmac.new(key, bytes(b), hashlib.sha1).digest()


def answers(ip, uid, enr, mac, iface, timeout=1.5):
    """True if the camera answers LAN discovery (in either framing), i.e.
    it is switched on and its P2P stack runs. The answer is read off an
    AF_PACKET socket, so no firewall rule is needed (the host firewall may
    then drop it)."""
    from .rawnet import parse_udp, sniff, udp_filter
    probe = Direct.__new__(Direct)        # just for the discovery packets
    probe.uid, probe.authkey = uid.encode(), auth_key(enr, mac)
    probe.sid = os.urandom(8)
    got = threading.Event()

    def on(p):
        d = p.payload
        if p.src != ip or len(d) < 16:
            return
        if d[:2] == b"\x51\xcc":
            if (len(d) >= 52 and struct.unpack_from("<H", d, 4)[0] == CMD_DISCO
                    and struct.unpack_from("<H", d, 12)[0] == 1):
                got.set()
        elif struct.unpack_from("<H", untrans_code_blob(d), 8)[0] == IOTC_DISCO_RES:
            got.set()

    t = threading.Thread(target=sniff, daemon=True,
                         args=(iface, udp_filter([ip]), parse_udp, on,
                               got.is_set, timeout + 0.5))
    t.start()
    time.sleep(0.1)                       # the sniffer is listening
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        pkts = (disco_packet(probe.uid + probe.authkey, probe.sid),
                trans_code_blob(probe._iotc_disco(1)))
        for _ in range(3):
            for pkt in pkts:
                s.sendto(pkt, (ip, DISCO_PORT))
            if got.wait(timeout / 3):
                break
    return got.is_set()


def open_firewall(changes, ip, port):
    """Let the camera's answers reach our socket. They come from its P2P
    port, not the port we wrote to, so a stateful host firewall (NixOS,
    ufw, firewalld) sees an unrelated packet and drops it. Journaled, so
    it is undone however we exit. Returns the journal token."""
    from .netutil import ipt
    spec = ["-s", ip, "-p", "udp", "--dport", str(port), "-j", "ACCEPT"]
    tok = changes.add("ipt", args=["-D", "INPUT", *spec])
    r = ipt("-I", "INPUT", "1", *spec)
    if r.returncode:
        changes.forget([tok])
        raise SystemExit(f"iptables INPUT failed: {r.stderr.strip()}")
    return tok


def auth_key(enr, mac):
    """The 8-character IOTC AuthKey: base64 of SHA256(ENR + MAC)[:6] with
    +/= replaced by Z/9/A."""
    h = hashlib.sha256((enr + mac.replace(":", "").upper()).encode()).digest()
    return (base64.b64encode(h[:6]).replace(b"+", b"Z").replace(b"/", b"9")
            .replace(b"=", b"A"))


def xxtea_decrypt(data, key):
    """XXTEA (corrected block TEA) decryption of a whole multiple of 4
    bytes with a 16-byte key, little-endian words."""
    n = len(data) // 4
    v = list(struct.unpack(f"<{n}I", data[:n * 4]))
    k = struct.unpack("<4I", key[:16])
    delta, mask = 0x9E3779B9, 0xFFFFFFFF
    rounds = 6 + 52 // n
    total = (rounds * delta) & mask
    y = v[0]
    for _ in range(rounds):
        e = (total >> 2) & 3
        for p in range(n - 1, -1, -1):
            z = v[p - 1] if p else v[n - 1]
            mx = ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) & mask) ^ \
                 (((total ^ y) + (k[(p & 3) ^ e] ^ z)) & mask)
            v[p] = (v[p] - mx) & mask
            y = v[p]
        total = (total - delta) & mask
    return struct.pack(f"<{n}I", *v)


def challenge_response(challenge, enr, status):
    """The K10002 answer to a K10001 challenge. Status 3 (these cameras)
    decrypts with ENR[:16]; status 6 decrypts twice, with ENR[:16] then
    ENR[16:32]; anything else uses the default key."""
    enr_b = enr.encode()
    if status == 3:
        return xxtea_decrypt(challenge, enr_b[:16].ljust(16, b"\0"))
    if status == 6:
        first = xxtea_decrypt(challenge, enr_b[:16].ljust(16, b"\0"))
        second = enr_b[16:32].ljust(16, b"\0") if len(enr_b) > 16 else b"F" * 16
        return xxtea_decrypt(first, second)
    return xxtea_decrypt(challenge, b"F" * 16)


def hl(cmd, payload=b""):
    """A Wyze K-command: 'HL', version 5, cmd, length, 8 reserved bytes."""
    return (b"HL\x05\x00" + struct.pack("<HH", cmd, len(payload)) + bytes(8)
            + payload)


def find_hl(data):
    """(cmd, payload) of the K-command inside a camera control message."""
    i = data.find(b"HL", 28)
    if i < 0 or len(data) < i + 16:
        return None
    cmd, n = struct.unpack_from("<HH", data, i + 4)
    return cmd, data[i + 16:i + 16 + n]


def open_first(make, timeout=OPEN_TIMEOUT, stop=None, av_log=None, on_av=None,
               resolution=HD_1080P):
    """A session opened like Direct.open(), hedged: make(stop_event) returns
    a new Direct that gives up when stop_event is set. When the first
    hasn't logged in after HEDGE_AFTER s, a second runs beside it, and every
    ROTATE_EVERY s after that the older is replaced, at most AT_ONCE at a
    time. The first to log in is opened (with av_log and on_av); the others
    hang up at once. A camera that doesn't answer discovery gets one
    session only. Raises CameraGone, saying how far the best one got."""
    began = time.monotonic()
    deadline = began + timeout
    won, lock = threading.Event(), threading.Lock()
    tries = []                        # (direct, thread, stop event, result)

    def run(d, box, n):
        t0 = time.monotonic()
        try:
            d.login(deadline)
            with lock:
                if not won.is_set():
                    box["won"] = True
                    won.set()
                    return
        except CameraGone:
            pass
        except Exception as e:  # noqa: BLE001 - a bad packet ends this try only
            box["error"] = e
        if os.environ.get("WYZECRACK_DEBUG"):
            d.log(f"[d] session {n} ended at the {d.stage()} after "
                  f"{time.monotonic() - t0:.1f} s"
                  + (f": {box['error']!r}" if "error" in box else ""))
        d.close()                     # lost or gave up: free its camera slot

    def launch():
        ev = threading.Event()
        d, box = make(ev), {}
        t = threading.Thread(target=run, args=(d, box, len(tries) + 1),
                             daemon=True)
        tries.append((d, t, ev, box))
        t.start()

    winner = None
    try:
        launch()
        next_try = time.monotonic() + HEDGE_AFTER
        while not won.wait(0.05):
            now = time.monotonic()
            if stop is not None and stop.is_set():
                raise CameraGone("stopped")
            answered = any(x[0].framing for x in tries)
            if now > deadline or (not answered and now - began > DISCO_GIVE_UP):
                best = max((x[0].stage() for x in tries), key=_STAGES.index)
                raise CameraGone(f"the camera did not answer ({best})")
            running = [x for x in tries if x[1].is_alive()]
            if now < next_try or (running and not any(x[0].framing
                                                      for x in running)):
                continue              # a camera that isn't answering at all
            if len(running) >= AT_ONCE:
                running[0][2].set()   # the older one steps aside
            launch()
            next_try = now + ROTATE_EVERY
        winner = next(x for x in tries if x[3].get("won"))
    finally:
        for x in tries:
            if x is not winner:
                x[2].set()
        for x in tries:
            if x is not winner:
                x[1].join(3)
    d = winner[0]
    d.stop, d.tries = stop, len(tries)
    d.record(av_log, on_av)
    try:
        d.finish(deadline, resolution)
    except BaseException:
        d.close()
        raise
    return d


_STAGES = ["discovery", "DTLS handshake", "AV login", "logged in"]

class Direct:
    """One live session with one camera. open() connects and authenticates;
    pump() then runs the session (call it in a loop); close() hangs up."""

    def __init__(self, ip, uid, enr, mac, local_ip=None, on_av=None,
                 av_log=None, log=print, stop=None, framing=None,
                 disco_port=DISCO_PORT):
        self.ip, self.enr, self.mac, self.log = ip, enr, mac, log
        self.disco_port = disco_port          # another one only in tests
        self.known_framing = framing          # from a previous session
        self.stop = stop                      # threading.Event: give up
        self.uid, self.authkey = uid.encode(), auth_key(enr, mac)
        self.key = self.uid + self.authkey
        self.framing = None                   # "cc51" or "iotc", from discovery
        self.tx_seq = 0                       # iotc data packets
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # a 1080p stream is ~200 datagrams/s; the default buffer holds
        # under half a second of it
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        self.sock.bind((local_ip or "0.0.0.0", 0))
        self.peer = (ip, disco_port)          # becomes the camera's P2P port
        self.sid, self.ticket = os.urandom(8), 0
        self.leg = DTLSLeg("client", derive_psk(enr), Templates.embedded())
        self.av_seq = self.cmd_seq = self.ka_seq = self.ack_flags = 0
        self.rx_start = self.rx_end = 0xFFFF
        self.rx_init = False
        self.ctrl = []                        # control replies not yet read
        self.login_resp = None
        self.streaming = False                # set once open() is done
        self.next_ack = None                  # acking starts after login
        self.last_rx = time.monotonic()
        self.on_av, self.av_f = None, None
        self.record(av_log, on_av)
        self.info = {}                        # the camera's K10003 JSON
        self.seen = ReplayWindow()            # the camera sends media twice
        self.stats = {"rx": 0, "tx": 0, "bad_trailer": 0, "bad_record": 0,
                      "duplicate": 0}

    @property
    def port(self):
        return self.sock.getsockname()[1]

    # ------------------------------------------------------------- framing
    def _trailer(self, head):
        return hmac.new(self.key, head, hashlib.sha1).digest()

    def _disco(self, seq):
        return disco_packet(self.key, self.sid, seq, self.ticket)

    def _wrap(self, records, channel=0):
        h = bytearray(28)
        h[0:2] = b"\x51\xcc"
        struct.pack_into("<HH", h, 4, CMD_DTLS, 16 + len(records) + 20)
        struct.pack_into("<HH", h, 12, 0x0010 | (channel << 8), self.ticket)
        h[16:24] = self.sid
        struct.pack_into("<I", h, 24, 1)
        return bytes(h) + records + self._trailer(bytes(h))

    def _keepalive(self, cmd=CMD_KEEPALIVE):
        self.ka_seq += 2
        b = bytearray(28)
        b[0:2] = b"\x51\xcc"
        struct.pack_into("<HH", b, 4, cmd, 0x24)
        struct.pack_into("<I", b, 16, self.ka_seq & 0xFFFFFFFF)
        b[20:28] = self.sid
        return bytes(b) + self._trailer(bytes(b))

    def _iotc(self, cmd, flags, body, mode=0x02):
        """An older-framing packet before TransCode: header, then body."""
        h = bytearray(16)
        h[0:4] = bytes((0x04, 0x02, 0x1A, mode))
        struct.pack_into("<HHHH", h, 4, len(body), 0, cmd, flags)
        return bytes(h) + bytes(body)

    def _iotc_disco(self, stage):
        b = bytearray(72)
        b[0:20] = self.uid
        b[36:40] = IOTC_SDK_VERSION
        b[40:48] = self.sid
        b[48] = stage
        if stage == 1:
            b[58:66] = self.authkey
        return self._iotc(IOTC_DISCO_REQ, 0x0021, b)

    def _iotc_session(self):
        b = bytearray(36)
        b[0:20] = self.uid
        b[20:28] = self.sid
        struct.pack_into("<I", b, 32, int(time.time()) & 0xFFFFFFFF)
        return self._iotc(IOTC_SESSION_REQ, 0x0033, b)

    def _iotc_data(self, payload, channel=0):
        b = bytearray(28)
        b[0:4] = b"\x04\x02\x1a\x0b"
        struct.pack_into("<HHHH", b, 4, 12 + len(payload), self.tx_seq,
                         IOTC_DATA_TX, 0x0021)
        self.tx_seq = (self.tx_seq + 1) & 0xFFFF
        b[12:14] = self.sid[:2]
        b[14], b[15] = channel, 0x01
        struct.pack_into("<I", b, 16, 0x0C)
        b[20:28] = self.sid
        return bytes(b) + payload

    def _send(self, pkt, to=None):
        self.sock.sendto(pkt, to or self.peer)
        self.stats["tx"] += 1

    def _send_iotc(self, pkt, to=None):
        self._send(trans_code_blob(pkt), to)

    def _send_dtls(self, records):
        if self.framing == "iotc":
            self._send_iotc(self._iotc_data(records))
        else:
            self._send(self._wrap(records))

    def _send_app(self, plaintext):
        self._send_dtls(self.leg.encrypt_record(RT_APPDATA, plaintext))

    def _recv(self, timeout):
        """(framing, packet) from the camera, or None: a CC51 packet with a
        valid trailer, or an older-framing one with TransCode undone."""
        self.sock.settimeout(max(timeout, 0.001))
        try:
            data, addr = self.sock.recvfrom(4096)
        except (socket.timeout, BlockingIOError):
            return None
        if addr[0] != self.ip or len(data) < 16:
            self.stats["ignored"] = self.stats.get("ignored", 0) + 1
            return None
        if data[:2] == b"\x51\xcc" and self.framing != "iotc":
            if len(data) < 48:
                return None
            cmd = struct.unpack_from("<H", data, 4)[0]
            span = 32 if cmd == CMD_DISCO else 28
            if not hmac.compare_digest(self._trailer(data[:span]), data[-20:]):
                self.stats["bad_trailer"] += 1
                return None
            kind = "cc51"
        elif self.framing != "cc51":
            data = untrans_code_blob(data)
            if data[:2] != b"\x04\x02":    # [2] is a version that varies
                self.stats["ignored"] = self.stats.get("ignored", 0) + 1
                return None
            kind = "iotc"
        else:
            return None
        self.peer = addr
        self.last_rx = time.monotonic()
        self.stats["rx"] += 1
        return kind, data

    # ------------------------------------------------------------- session
    def record(self, av_log=None, on_av=None):
        """Append what the camera sends, decrypted, to av_log, and/or hand
        it to on_av(time, plaintext). (What the tool sends is left out: its
        AV login carries the ENR.)"""
        self.on_av = on_av
        if av_log:
            self.av_f = open(av_log, "ab")
            # media.SESSION_MARK: frame numbers start over from here
            self.av_f.write(struct.pack("<BdI", 255, time.time(), 0))

    def open(self, timeout=OPEN_TIMEOUT, resolution=HD_1080P):
        deadline = time.monotonic() + timeout
        self.login(deadline)
        self.finish(deadline, resolution)
        return self

    def login(self, deadline):
        """Discovery, the DTLS handshake and the AV login: what a camera is
        sometimes slow to answer (see open_first)."""
        self._discover(deadline)
        self._handshake(deadline)
        self._av_login(deadline)

    def finish(self, deadline, resolution=HD_1080P):
        """Authenticate and pick the resolution; media flows from here."""
        self._authenticate(deadline)
        self.command(K_RESOLUTION, bytes([resolution])
                     + struct.pack("<HH", BITRATE_MAX, 0), K_RESOLUTION_RESP)
        self.streaming = True

    def stage(self):
        """How far login() got."""
        if self.login_resp is not None:
            return "logged in"
        if self.leg.handshake_done:
            return "AV login"
        return "DTLS handshake" if self.framing else "discovery"

    def _until(self, deadline, what, send, done, every=0.5):
        """Send `send()` every `every` s, pumping replies, until done()."""
        nxt = 0
        while not done():
            if self.stop is not None and self.stop.is_set():
                raise CameraGone("stopped")
            now = time.monotonic()
            if now > deadline:
                raise CameraGone(f"the camera did not answer ({what})")
            if now >= nxt:
                send()
                nxt = now + every
            self.pump(0.05)

    def _discover(self, deadline):
        got = {}

        def on(kind, d):
            if kind == "iotc":
                cmd = struct.unpack_from("<H", d, 8)[0]
                if cmd == IOTC_DISCO_RES:
                    got.setdefault("framing", "iotc")
                elif cmd == IOTC_SESSION_RES:
                    got["done"] = True
                return
            if struct.unpack_from("<H", d, 4)[0] != CMD_DISCO:
                return
            seq = struct.unpack_from("<H", d, 12)[0]
            if seq == 1 and "framing" not in got:
                got.update(framing="cc51",
                           ticket=struct.unpack_from("<H", d, 14)[0],
                           sid=d[16:24])
            elif seq == 3:
                got["done"] = True

        def hello():
            # both framings, unless an earlier session told us which one
            # the camera speaks: whichever it speaks, it answers
            if self.known_framing in (None, "cc51"):
                self._send(self._disco(0), (self.ip, self.disco_port))
            if self.known_framing in (None, "iotc"):
                self._send_iotc(self._iotc_disco(1), (self.ip, self.disco_port))

        self._on_disco = on
        self._until(deadline, "discovery", hello, lambda: "framing" in got)
        self.framing = got["framing"]
        if self.framing == "cc51":
            self.ticket, self.sid = got["ticket"], got["sid"]
            self._until(deadline, "discovery",
                        lambda: self._send(self._disco(2)),
                        lambda: "done" in got)
        else:
            self._send_iotc(self._iotc_disco(2))
            time.sleep(0.1)
            self._until(deadline, "session",
                        lambda: self._send_iotc(self._iotc_session()),
                        lambda: "done" in got)
        self._on_disco = None

    def _handshake(self, deadline):
        self._flight = self.leg.client_hello()
        self._until(deadline, "DTLS handshake",
                    lambda: self._send_dtls(self._flight),
                    lambda: self.leg.handshake_done, every=1.0)

    def _av_login(self, deadline):
        rid = os.urandom(4)
        p1 = self._login_msg(0x0000, 570, 0x0001, rid)
        p2 = self._login_msg(0x2000, 572, 0x0000,
                             bytes([(rid[0] + 1) & 0xFF]) + rid[1:])

        def send():
            self._send_app(p1)
            time.sleep(0.01)
            self._send_app(p2)

        self._until(deadline, "AV login", send,
                    lambda: self.login_resp is not None, every=LOGIN_EVERY)
        self._ack()
        self.next_ack = time.monotonic() + ACK_EVERY

    def _login_msg(self, magic, size, flags, rid):
        b = bytearray(size)
        struct.pack_into("<HH", b, 0, magic, PROTO)
        struct.pack_into("<HH", b, 16, size - 24, flags)
        b[20:24] = rid
        b[24:29] = b"admin"
        b[280:280 + len(self.enr)] = self.enr.encode()
        struct.pack_into("<I", b, 540, 4)
        struct.pack_into("<I", b, 552, CAPS)
        return bytes(b)

    def _authenticate(self, deadline):
        hello = json.dumps({"cameraInfo": {
            "mac": self.mac.replace(":", "").upper(), "encFlag": 0,
            "wakeupFlag": 0, "audioEncoderList": [137, 143, 140]}},
            separators=(",", ":")).encode()
        r = self.command(K_AUTH, hello, K_CHALLENGE)
        if len(r) < 17:
            raise CameraGone("short K10001 challenge")
        answer = challenge_response(r[1:17], self.enr, r[0])
        r = self.command(K_CHALLENGE_RESP,
                         answer[:16] + os.urandom(4) + b"\x01\x01",
                         K_AUTH_RESULT)
        i = r.find(b"{")
        try:
            self.info = json.loads(r[i:].rstrip(b"\0")) if i >= 0 else {}
        except ValueError:
            self.info = {}
        if self.info.get("connectionRes") not in (None, "1"):
            raise CameraGone(f"the camera refused the login "
                             f"(connectionRes {self.info.get('connectionRes')})")

    def command(self, cmd, payload, want, timeout=6):
        """Send K-command `cmd` (resent every second) and return the
        payload of the camera's `want` reply."""
        frame = self._ioctrl(hl(cmd, payload))
        reply = []
        deadline = time.monotonic() + timeout

        def done():
            while self.ctrl:
                r = find_hl(self.ctrl.pop(0))
                self._ack()
                if r and r[0] == want:
                    reply.append(r[1])
            return bool(reply)

        self._until(deadline, f"K{cmd}", lambda: self._send_app(frame), done,
                    every=1.0)
        return reply[0]

    def _ioctrl(self, payload):
        b = bytearray(40)
        struct.pack_into("<HHI", b, 0, PROTO, PROTO, self.av_seq)
        struct.pack_into("<HH", b, 16, MAGIC_IOCTRL, self.cmd_seq)
        struct.pack_into("<III", b, 20, 1, len(payload) + 4, self.cmd_seq)
        b[37] = 1
        self.av_seq += 1
        self.cmd_seq += 1
        return bytes(b) + payload

    def _ack(self):
        self.ack_flags = (self.ack_flags + 1) & 0xFFFF
        b = bytearray(24)
        struct.pack_into("<HHI", b, 0, MAGIC_ACK, PROTO, self.av_seq)
        struct.pack_into("<HHH", b, 8, self.rx_start, self.rx_end,
                         self.ack_flags)
        struct.pack_into("<I", b, 16, (self.ack_flags << 16) & 0xFFFFFFFF)
        struct.pack_into("<H", b, 20, int(time.time() * 1000) & 0xFFFF)
        self.av_seq += 1
        if self.rx_init:
            self.rx_start = self.rx_end
        self._send_app(bytes(b))

    # ----------------------------------------------------------- receiving
    def pump(self, timeout=0.1):
        """Handle what the camera sent within `timeout` s; keeps the
        session alive (ACKs, keepalives). Raises CameraGone when it has been
        silent too long after the handshake."""
        end = time.monotonic() + timeout
        while True:
            now = time.monotonic()
            if self.next_ack is not None and now >= self.next_ack:
                self._ack()
                self.next_ack = now + ACK_EVERY
            got = self._recv(min(end - now, ACK_EVERY))
            if got is not None:
                self._dispatch(*got)
            if time.monotonic() >= end:
                break
        if (self.leg.handshake_done
                and time.monotonic() - self.last_rx > SILENT_AFTER):
            if os.environ.get("WYZECRACK_DEBUG"):
                print(f"[d] quiet: last packet {time.monotonic() - self.last_rx:.1f} s "
                      f"ago, socket {self.sock.getsockname()}, peer {self.peer}")
            raise CameraGone("the camera went quiet")

    def _dispatch(self, kind, d):
        if kind == "iotc":
            cmd = struct.unpack_from("<H", d, 8)[0]
            seen = self.stats.setdefault("iotc_cmds", {})
            seen[hex(cmd)] = seen.get(hex(cmd), 0) + 1
            if cmd in (IOTC_DISCO_RES, IOTC_SESSION_RES):
                if getattr(self, "_on_disco", None):
                    self._on_disco(kind, d)
            elif cmd == IOTC_KEEPALIVE_RES and len(d) >= 24:
                self._send_iotc(self._iotc(IOTC_KEEPALIVE_REQ, 0x0021,
                                           d[16:24], mode=0x0A))
            elif cmd == IOTC_DATA_RX and len(d) > 28 and d[14] == 0:
                self._records(d[28:])
            return
        cmd = struct.unpack_from("<H", d, 4)[0]
        if cmd == CMD_DISCO:
            if getattr(self, "_on_disco", None):
                self._on_disco(kind, d)
        elif cmd == CMD_KEEPALIVE:
            self._send(self._keepalive())
        elif cmd == CMD_DTLS:
            channel = struct.unpack_from("<H", d, 12)[0] >> 8
            if channel == 0:
                self._records(d[28:-20])

    def _records(self, payload):
        for rtype, ver, epoch, seq, body in parse_records(payload):
            if rtype == RT_ALERT:
                raise CameraGone("the camera closed the session (DTLS alert)")
            if epoch == 0:
                if rtype == RT_HANDSHAKE:
                    self._server_flight(parse_hs(body))
                elif rtype == RT_CCS:
                    self.leg.client_on_ccs()
                continue
            if not self.seen.check(epoch, seq):
                self.stats["duplicate"] += 1
                continue
            try:
                pt = self.leg.decrypt_record(rtype, ver, epoch, seq, body)
            except BadRecord:
                if not self.leg.handshake_done:
                    raise
                self.stats["bad_record"] += 1     # drop it, keep the session
                continue
            if rtype == RT_HANDSHAKE:
                self.leg.client_on_fin(pt)
            elif rtype == RT_APPDATA:
                self._app(pt)

    def _server_flight(self, msgs):
        if not msgs:
            return
        flight = self.leg.client_on_server_flight(msgs)
        if flight:
            self._flight = flight
            self._send_dtls(flight)
        elif (self.leg.state == "wait_cam_fin"
              and all(m[0] in (HS_SH, HS_SKE, HS_SHD) for m in msgs)):
            # the camera repeated its flight: ours was lost
            self._send_dtls(self._flight)

    def _app(self, pt):
        self._log_av(pt)
        if len(pt) < 2:
            return
        magic = struct.unpack_from("<H", pt, 0)[0]
        if magic == MAGIC_LOGIN_RESP:
            self.login_resp = pt
        elif magic == PROTO:
            if len(pt) >= 8:
                seq = struct.unpack_from("<H", pt, 4)[0]
                self.rx_init = True
                if seq > self.rx_end or self.rx_end == 0xFFFF:
                    self.rx_end = seq
            self.ctrl.append(pt)
        elif magic == MAGIC_IOCTRL:
            self.ctrl.append(pt)

    def _log_av(self, plaintext):
        now = time.time()
        if self.av_f:
            self.av_f.write(struct.pack("<BdI", 1, now, len(plaintext))
                            + plaintext)
        if self.on_av:
            try:
                self.on_av(now, plaintext)
            except Exception as e:  # noqa: BLE001
                self.log(f"[!] live view callback failed: {e!r}")

    def _stop_media(self, wait=1.0):
        """Ask the camera to stop video and audio (K10010 off). Without it
        the camera keeps streaming to this session for about 30 s after we
        hang up (both models), which costs its Wi-Fi bandwidth and overlaps a
        reconnect; with it the stream stops at once. Waits up to `wait` s
        for both answers."""
        for media in (MEDIA_VIDEO, MEDIA_AUDIO):
            self._send_app(self._ioctrl(hl(K_CHANNEL, bytes((media, CHANNEL_OFF)))))
        answered = set()
        end = time.monotonic() + wait
        while len(answered) < 2 and time.monotonic() < end:
            self.pump(0.05)
            while self.ctrl:
                r = find_hl(self.ctrl.pop(0))
                if r and r[0] == K_CHANNEL_RESP and r[1]:
                    answered.add(r[1][0])

    def close(self):
        try:
            if self.streaming:
                self.streaming = False
                self._stop_media()
        except (OSError, CameraGone, ValueError):
            pass
        try:
            if self.leg.handshake_done:
                # a DTLS close_notify; the camera also times out on its own
                self._send_dtls(self.leg.encrypt_record(RT_ALERT, b"\x01\x00"))
            if self.framing == "cc51" and self.sid is not None:
                for _ in range(4):           # as the camera does: UDP
                    self._send(self._keepalive(CMD_CLOSE))
        except OSError:
            pass
        self.sock.close()
        if self.av_f:
            self.av_f.close()
            self.av_f = None
