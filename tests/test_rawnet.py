"""Raw framing and BPF programs. The live-socket test needs Linux + root."""
import os
import socket
import struct
import sys
import time
import unittest

from wyze_splice import rawnet


def _udp_frame(src, dst, sport, dport, payload, proto=17):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(payload), 0, 0, 64,
                     proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return b"\x11" * 6 + b"\x22" * 6 + b"\x08\x00" + ip + udp + payload


def run_bpf(prog, pkt):
    """Tiny interpreter for the opcodes rawnet emits."""
    pc, a = 0, 0
    while True:
        code, jt, jf, k = prog[pc]
        pc += 1
        if code == rawnet.LD_W_ABS:
            a = struct.unpack("!I", pkt[k:k + 4])[0]
        elif code == rawnet.LD_H_ABS:
            a = struct.unpack("!H", pkt[k:k + 2])[0]
        elif code == rawnet.LD_B_ABS:
            a = pkt[k]
        elif code == rawnet.JEQ_K:
            pc += jt if a == k else jf
        elif code == rawnet.RET_K:
            return k


class TestFilters(unittest.TestCase):
    def test_udp_filter(self):
        prog = rawnet.udp_filter(["192.168.1.20"], ["192.168.1.2"])
        ok = rawnet.ACCEPT
        self.assertEqual(run_bpf(prog, _udp_frame("192.168.1.20", "1.2.3.4", 1, 2, b"x")), ok)
        self.assertEqual(run_bpf(prog, _udp_frame("1.2.3.4", "192.168.1.20", 1, 2, b"x")), ok)
        self.assertEqual(run_bpf(prog, _udp_frame("1.2.3.4", "192.168.1.2", 1, 2, b"x")), ok)
        # our own outbound traffic is not the camera's
        self.assertEqual(run_bpf(prog, _udp_frame("192.168.1.2", "1.2.3.4", 1, 2, b"x")), 0)
        self.assertEqual(run_bpf(prog, _udp_frame("192.168.1.20", "1.2.3.4", 1, 2, b"x", proto=6)), 0)
        arp = b"\x11" * 12 + b"\x08\x06" + bytes(28)
        self.assertEqual(run_bpf(prog, arp), 0)
        self.assertEqual(run_bpf(rawnet.arp_filter(), arp), ok)

    def test_parse_udp(self):
        p = rawnet.parse_udp(_udp_frame("192.168.1.20", "198.51.100.151", 4000, 7345,
                                        b"\x51\xcc" + bytes(10)) + b"\x00" * 6)
        self.assertEqual(p, ("192.168.1.20", "198.51.100.151", 4000, 7345,
                             b"\x51\xcc" + bytes(10)))   # Ethernet padding cut

    def test_arp_reply_roundtrip(self):
        me, cam = b"\x02\x00\x00\x00\x00\x01", b"\xd0\x3f\x27\xa1\xb2\xc3"
        f = rawnet.arp_reply(me, cam, "192.168.1.1", me, "192.168.1.20", cam)
        self.assertEqual(f[:6], cam)
        p = rawnet.parse_arp(f)
        self.assertEqual((p.op, p.sha, p.spa, p.tha, p.tpa),
                         (2, me, "192.168.1.1", cam, "192.168.1.20"))


@unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                     "AF_PACKET needs Linux + root")
class TestLiveFilter(unittest.TestCase):
    def test_kernel_accepts_and_applies_the_filter(self):
        got = []
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0))
        port = rx.getsockname()[1]
        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        deadline = time.time() + 2

        def on(p):
            if p.dport == port:
                got.append(p)
        import threading
        t = threading.Thread(target=rawnet.sniff, args=(
            "lo", rawnet.udp_filter(["127.0.0.1"]), rawnet.parse_udp, on,
            lambda: bool(got) or time.time() > deadline))
        t.start()
        time.sleep(0.3)
        tx.sendto(b"hello", ("127.0.0.1", port))
        t.join(3)
        rx.close()
        tx.close()
        self.assertTrue(got and got[0].payload == b"hello")
