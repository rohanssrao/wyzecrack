"""Watch a Wyze camera straight over the LAN, the way the Wyze app does when
it is on the camera's Wi-Fi: no phone, no interception.

This needs three per-camera values: its MAC, its ENR (read off the
camera's own HTTPS, see cloud.py) and its TUTK UID (which the Wyze cloud
returns for MAC + ENR, see cloud.fetch_uid).

The protocol is ThroughTek's SDK 4.3 framing as these cameras speak it
(go2rtc's pkg/tutk/dtls and pkg/wyze interoperate with it too):

  discovery  cmd 0x1002 to udp/32761. The camera answers from its P2P
             port with a ticket; four packets, seq 0..3.
  data       cmd 0x1502: a 28-byte header, DTLS records, a 20-byte trailer.
  keepalive  cmd 0x1202, both ways.
  trailer    HMAC-SHA1 keyed by UID + AuthKey over the first 28 bytes
             (32 for discovery). AuthKey comes from ENR + MAC. The camera
             ignores packets whose trailer is wrong.

Inside the DTLS session (PSK from the ENR, see dtls.py): an AV login
whose password is the ENR, the K10000/K10002 challenge (XXTEA with the
ENR), then the camera streams. Every decrypted record goes to on_av and
av.bin in the same form the splice writes, so live.py and media.py work
unchanged.
"""
import base64
import hashlib
import hmac
import json
import os
import socket
import struct
import time

from .dtls import (HS_SH, HS_SHD, HS_SKE, RT_ALERT, RT_APPDATA, RT_CCS,
                   RT_HANDSHAKE, DTLSLeg, Templates, derive_psk, parse_hs,
                   parse_records)

DISCO_PORT = 32761
CMD_DISCO, CMD_KEEPALIVE, CMD_DTLS = 0x1002, 0x1202, 0x1502
SDK_VERSION = b"\x00\x08\x03\x04"           # 4.3.8.0, as the app sends
PROTO = 0x000C
MAGIC_LOGIN_RESP, MAGIC_IOCTRL, MAGIC_ACK = 0x2100, 0x7000, 0x0009
CAPS = 0x001F07FB
K_AUTH, K_CHALLENGE, K_CHALLENGE_RESP, K_AUTH_RESULT = 10000, 10001, 10002, 10003
K_RESOLUTION, K_RESOLUTION_RESP = 10056, 10057
HD_1080P, BITRATE_MAX = 1, 0xF0             # K10056 frame size 0 (+1), kbps
ACK_EVERY = 0.1
SILENT_AFTER = 6.0                          # camera quiet this long: gone


class CameraGone(Exception):
    """The camera did not answer (or hung up)."""


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


class Direct:
    """One live session with one camera. open() connects and authenticates;
    pump() then runs the session (call it in a loop); close() hangs up."""

    def __init__(self, ip, uid, enr, mac, local_ip=None, on_av=None,
                 av_log=None, log=print):
        self.ip, self.enr, self.mac, self.log = ip, enr, mac, log
        self.key = uid.encode() + auth_key(enr, mac)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((local_ip or "0.0.0.0", 0))
        self.peer = (ip, DISCO_PORT)          # becomes the camera's P2P port
        self.sid, self.ticket = os.urandom(8), 0
        full = hashlib.sha256(enr.encode()).digest()
        self.leg = DTLSLeg("client", derive_psk(enr), Templates.embedded(), full)
        self.av_seq = self.cmd_seq = self.ka_seq = self.ack_flags = 0
        self.rx_start = self.rx_end = 0xFFFF
        self.rx_init = False
        self.ctrl = []                        # control replies not yet read
        self.login_resp = None
        self.next_ack = None                  # acking starts after login
        self.last_rx = time.monotonic()
        self.on_av = on_av
        self.av_f = open(av_log, "ab") if av_log else None
        self.info = {}                        # the camera's K10003 JSON
        self.stats = {"rx": 0, "tx": 0, "bad_trailer": 0}

    @property
    def port(self):
        return self.sock.getsockname()[1]

    # ------------------------------------------------------------- framing
    def _trailer(self, head):
        return hmac.new(self.key, head, hashlib.sha1).digest()

    def _disco(self, seq):
        b = bytearray(32)
        b[0:2] = b"\x51\xcc"
        struct.pack_into("<HH", b, 4, CMD_DISCO, 0x28)
        struct.pack_into("<HH", b, 12, seq, self.ticket)
        b[16:24] = self.sid
        b[24:28] = SDK_VERSION
        b[28] = 0x1D
        return bytes(b) + self._trailer(bytes(b))

    def _wrap(self, records, channel=0):
        h = bytearray(28)
        h[0:2] = b"\x51\xcc"
        struct.pack_into("<HH", h, 4, CMD_DTLS, 16 + len(records) + 20)
        struct.pack_into("<HH", h, 12, 0x0010 | (channel << 8), self.ticket)
        h[16:24] = self.sid
        struct.pack_into("<I", h, 24, 1)
        return bytes(h) + records + self._trailer(bytes(h))

    def _keepalive(self):
        self.ka_seq += 2
        b = bytearray(28)
        b[0:2] = b"\x51\xcc"
        struct.pack_into("<HH", b, 4, CMD_KEEPALIVE, 0x24)
        struct.pack_into("<I", b, 16, self.ka_seq & 0xFFFFFFFF)
        b[20:28] = self.sid
        return bytes(b) + self._trailer(bytes(b))

    def _send(self, pkt, to=None):
        self.sock.sendto(pkt, to or self.peer)
        self.stats["tx"] += 1

    def _send_dtls(self, records):
        self._send(self._wrap(records))

    def _send_app(self, plaintext):
        self._log_av(0, plaintext)
        self._send_dtls(self.leg.encrypt_record(RT_APPDATA, plaintext))

    def _recv(self, timeout):
        """One authenticated CC51 packet from the camera, or None."""
        self.sock.settimeout(max(timeout, 0.001))
        try:
            data, addr = self.sock.recvfrom(4096)
        except (socket.timeout, BlockingIOError):
            return None
        if addr[0] != self.ip or len(data) < 48 or data[:2] != b"\x51\xcc":
            return None
        cmd = struct.unpack_from("<H", data, 4)[0]
        span = 32 if cmd == CMD_DISCO else 28
        if not hmac.compare_digest(self._trailer(data[:span]), data[-20:]):
            self.stats["bad_trailer"] += 1
            return None
        self.peer = addr
        self.last_rx = time.monotonic()
        self.stats["rx"] += 1
        return data

    # ------------------------------------------------------------- session
    def open(self, timeout=12, resolution=HD_1080P):
        deadline = time.monotonic() + timeout
        self._discover(deadline)
        self._handshake(deadline)
        self._av_login(deadline)
        self._authenticate(deadline)
        self.command(K_RESOLUTION, bytes([resolution])
                     + struct.pack("<HH", BITRATE_MAX, 0), K_RESOLUTION_RESP)
        return self

    def _until(self, deadline, what, send, done, every=0.5):
        """Send `send()` every `every` s, pumping replies, until done()."""
        nxt = 0
        while not done():
            now = time.monotonic()
            if now > deadline:
                raise CameraGone(f"the camera did not answer ({what})")
            if now >= nxt:
                send()
                nxt = now + every
            self.pump(0.05)

    def _discover(self, deadline):
        got = {}

        def on(d):
            cmd = struct.unpack_from("<H", d, 4)[0]
            if cmd != CMD_DISCO:
                return
            seq = struct.unpack_from("<H", d, 12)[0]
            if seq == 1 and "ticket" not in got:
                got["ticket"] = struct.unpack_from("<H", d, 14)[0]
                got["sid"] = d[16:24]
            elif seq == 3:
                got["done"] = True

        self._on_disco = on
        self._until(deadline, "discovery",
                    lambda: self._send(self._disco(0), (self.ip, DISCO_PORT)),
                    lambda: "ticket" in got)
        self.ticket, self.sid = got["ticket"], got["sid"]
        self._until(deadline, "discovery",
                    lambda: self._send(self._disco(2)), lambda: "done" in got)
        self._on_disco = None

    def _handshake(self, deadline):
        self._flight = self.leg.client_hello()
        self._cam_repeats = 0
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
                    lambda: self.login_resp is not None, every=1.0)
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
            d = self._recv(min(end - now, ACK_EVERY))
            if d is not None:
                self._dispatch(d)
            if time.monotonic() >= end:
                break
        if (self.leg.handshake_done
                and time.monotonic() - self.last_rx > SILENT_AFTER):
            raise CameraGone("the camera went quiet")

    def _dispatch(self, d):
        cmd = struct.unpack_from("<H", d, 4)[0]
        if cmd == CMD_DISCO:
            if getattr(self, "_on_disco", None):
                self._on_disco(d)
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
            pt = self.leg.decrypt_record(rtype, ver, epoch, seq, body)
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
            # the camera repeated its flight: ours was lost, or it rejected
            # our Finished; dtls.py's retries cover the known variants
            self._cam_repeats += 1
            if self._cam_repeats % 2 == 0:
                new = (self.leg.client_rebuild_flight() if self._cam_repeats == 2
                       else self.leg.client_retry_flight())
                self._flight = new or self._flight
            self._send_dtls(self._flight)

    def _app(self, pt):
        self._log_av(1, pt)
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

    def _log_av(self, direction, plaintext):
        now = time.time()
        if self.av_f:
            self.av_f.write(struct.pack("<BdI", direction, now, len(plaintext))
                            + plaintext)
        if self.on_av:
            try:
                self.on_av(direction, now, plaintext)
            except Exception as e:  # noqa: BLE001
                self.log(f"[!] live view callback failed: {e!r}")

    def close(self):
        try:
            if self.leg.handshake_done:
                # a DTLS close_notify; the camera also times out on its own
                self._send_dtls(self.leg.encrypt_record(RT_ALERT, b"\x01\x00"))
        except OSError:
            pass
        self.sock.close()
        if self.av_f:
            self.av_f.close()
            self.av_f = None
