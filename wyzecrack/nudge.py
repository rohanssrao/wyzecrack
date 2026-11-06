"""Getting the camera to send its ENR now, without cutting it off.

Every request the camera makes to Wyze's device API carries its ENR, but
it makes few of them. The one that comes most often is the metrics
report (device-api.wyzecam.com/ddc/v1/metrics_list/report, with
`device_enr`). In firmware 4.36.17.21 (libwyzeUtils.so,
ms_upload_handler) the camera sends it at a random time 0 to 20 minutes
after the previous one, or as soon as its 5120-byte metrics buffer is
full.

Each time the camera's MQTT connection to aws-iot.wyzecam.com drops, it
logs about 1 KB of metrics (status changes, then the messages it
publishes when it reconnects). So resetting that one TCP connection a few
times fills the buffer and the report goes out within seconds. The
camera stays online apart from a few seconds per reconnect, and its other
traffic (live views included) is untouched. The internet cuts used
before produced a report only when their burst of events happened to
overflow the buffer.

Live on v3 A (fw 4.36.17.21): the report came after 4 to 6
resets. On a Wyze Cam v2 (4.9.9.3006, MQTT in its separate iotclient
process) one reset was enough: within seconds the camera posted
set_device_info, with its ENR, to api.wyzecam.com.

A reset is a TCP RST sent to the camera as if from the broker, with the
sequence number the camera's own last segment acknowledged, so it takes
effect at once. An iptables REJECT for that connection backs it up: if
the RST missed, the camera's next segment on it gets one from the kernel.
"""
import os
import socket
import struct
import threading
import time

from .rawnet import (ACCEPT, DROP, JEQ_K, LD_B_ABS, LD_H_ABS, LD_W_ABS,
                     PACKET_OUTGOING, RET_K, _ip, open_raw)

DEBUG = bool(os.environ.get("WYZECRACK_DEBUG"))
MQTT_PORT = 8883
SETTLE = 5          # s after a reconnect: let it publish (that logs metrics)
MAX_RESETS = 8      # each adds ~1 KB; the buffer holds 5 KB


def tcp_from(host):
    """BPF: IPv4 TCP frames from host."""
    return [(LD_H_ABS, 0, 0, 12), (JEQ_K, 0, 5, 0x0800),
            (LD_B_ABS, 0, 0, 23), (JEQ_K, 0, 3, socket.IPPROTO_TCP),
            (LD_W_ABS, 0, 0, 26), (JEQ_K, 0, 1, _ip(host)),
            (RET_K, 0, 0, ACCEPT), (RET_K, 0, 0, DROP)]


def mqtt_segment(frame):
    """(source port, is a SYN, broker address, ack number) of a frame from
    the camera to tcp/8883, or None."""
    if len(frame) < 34 or frame[12:14] != b"\x08\x00" or frame[23] != 6:
        return None
    tcp = 14 + (frame[14] & 0x0F) * 4
    if len(frame) < tcp + 14:
        return None
    sport, dport, _seq, ack = struct.unpack_from("!HHII", frame, tcp)
    if dport != MQTT_PORT:
        return None
    flags = frame[tcp + 13]
    return (sport, bool(flags & 0x02) and not flags & 0x10,
            socket.inet_ntoa(frame[30:34]), ack if flags & 0x10 else None)


def _checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def rst_packet(src, sport, dst, dport, seq):
    """An IPv4 TCP RST from src:sport to dst:dport with this sequence."""
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x04, 0, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", _checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return ip + tcp


class MqttNudge:
    """Resets the camera's MQTT connections (it keeps two) in rounds until
    stop is set or MAX_RESETS rounds: each round resets every live one, and
    the next starts SETTLE s after the camera's newest reconnect. Each reset
    is a spoofed RST plus an iptables REJECT for that connection's source
    port, journaled in `changes` and removed after STALE s. Runs in its own
    thread: start(), then stop.set()."""

    STALE = 30          # s: a connection this quiet is gone

    def __init__(self, changes, cam_ip, iface, log=print):
        self.changes, self.cam, self.iface, self.log = changes, cam_ip, iface, log
        self.stop = threading.Event()
        self.resets = 0
        self.failed = None            # why it gave up, if it did
        self._rules = {}              # port -> (journal token, when)

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _reject(self, port):
        from .netutil import ipt
        spec = ["-s", self.cam, "-p", "tcp", "--sport", str(port),
                "--dport", str(MQTT_PORT), "-j", "REJECT",
                "--reject-with", "tcp-reset"]
        tok = self.changes.add("ipt", args=["-D", "FORWARD", *spec])
        if ipt("-I", "FORWARD", "1", *spec).returncode:
            self.changes.forget([tok])
            return False
        self._rules[port] = (tok, time.monotonic())
        return True

    def _release(self, older_than=0):
        now = time.monotonic()
        done = [p for p, (_, t) in self._rules.items() if now - t >= older_than]
        if done:
            self.changes.undo([self._rules.pop(p)[0] for p in done])

    def _run(self):
        try:
            sock = open_raw(self.iface, tcp_from(self.cam))
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except OSError as e:
            self.failed = f"can't watch the camera's traffic ({e})"
            return
        sock.settimeout(0.5)
        live = {}                     # port -> [broker, last ack, first, last]
        last_round = None
        try:
            while not self.stop.is_set():
                try:
                    frame, addr = sock.recvfrom(65535)
                except socket.timeout:
                    frame = None
                now = time.monotonic()
                seg = (mqtt_segment(frame) if frame is not None
                       and addr[2] != PACKET_OUTGOING else None)
                if seg and seg[0] not in self._rules:
                    port, syn, broker, ack = seg
                    c = live.get(port)
                    if c is None:
                        c = live[port] = [broker, None, now, now]
                        if DEBUG:
                            self.log(f"[d] {time.strftime('%T')} MQTT connection "
                                     f"from port {port}{' (new)' if syn else ''}")
                    c[0], c[3] = broker, now
                    if ack is not None:
                        c[1] = ack
                for p in [p for p, c in live.items() if now - c[3] > self.STALE]:
                    del live[p]
                self._release(older_than=self.STALE)
                newest = max((c[2] for c in live.values()), default=None)
                if (newest is not None and now - newest >= SETTLE
                        and (last_round is None or now - last_round >= SETTLE)):
                    if self.resets >= MAX_RESETS:
                        return
                    for p, (broker, ack, _, _) in list(live.items()):
                        if not self._reject(p):
                            self.failed = "iptables refused the reset rule"
                            return
                        if ack is not None:
                            try:
                                raw.sendto(rst_packet(broker, MQTT_PORT, self.cam,
                                                      p, ack), (self.cam, 0))
                            except OSError:
                                pass          # the REJECT rule still works
                    live.clear()
                    last_round = now
                    self.resets += 1
                    self.log(f"[*] resetting the camera's cloud connection "
                             f"({self.resets}/{MAX_RESETS}) so it reports in"
                             + (f" [{time.strftime('%T')}]" if DEBUG else ""))
        finally:
            self._release()
            sock.close()
            raw.close()
