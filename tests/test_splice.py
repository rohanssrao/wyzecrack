"""Tests for the splice's latch logic, teardown timing, divert rules and
sockets. The socket tests need Linux + root; the rest run anywhere."""
import io
import os
import socket
import subprocess
import struct
import sys
import tempfile
import time
import unittest
import unittest.mock

from wyze_splice.splice import StormGuard


class TestStormGuard(unittest.TestCase):
    def test_identical_burst_is_capped_per_second(self):
        g = StormGuard(limit=100)
        src = ("192.168.1.20", 38217)
        pkt = b"\x51\xcc" + b"\x00" * 50
        # 150 identical packets inside one 1-second bucket
        passed = sum(g.allow(src, pkt, now=1000.0) for _ in range(150))
        self.assertEqual(passed, 100)
        self.assertEqual(g.dropped, 50)

    def test_window_resets_after_a_second(self):
        # splice3's failure mode: the camera re-sends one keepalive
        # forever; the guard must keep letting a trickle through so the
        # relay can eventually ACK it if the path recovers
        g = StormGuard(limit=100)
        src = ("192.168.1.20", 38217)
        pkt = b"\x51\xcc" + b"\x00" * 50
        for sec in range(5):
            for i in range(150):
                g.allow(src, pkt, now=1000.0 + sec + i * 0.001)
        # 5 seconds x 100 passed = 500, 5 x 50 dropped
        self.assertEqual(g.dropped, 250)

    def test_legit_keepalive_cadence_is_never_dropped(self):
        # identical keepalives every 200ms: 5/sec, far below the limit,
        # and each new second starts a fresh bucket
        g = StormGuard(limit=100)
        src = ("192.168.1.20", 38217)
        pkt = b"keepalive"
        for i in range(150):  # 30 seconds
            t = 1000.0 + i * 0.2
            self.assertTrue(g.allow(src, pkt, now=t))
        self.assertEqual(g.dropped, 0)

    def test_distinct_packets_are_never_dropped(self):
        g = StormGuard(limit=100)
        src = ("192.168.1.20", 38217)
        for i in range(1000):
            pkt = struct.pack(">I", i) + b"\x00" * 46
            self.assertTrue(g.allow(src, pkt, now=1000.0 + i * 0.001))
        self.assertEqual(g.dropped, 0)

    def test_sources_are_tracked_separately(self):
        g = StormGuard(limit=100)
        pkt = b"same"
        for _ in range(100):
            g.allow(("192.168.1.20", 1), pkt, now=1000.0)
        self.assertTrue(g.allow(("192.168.1.20", 2), pkt, now=1000.0))
        self.assertTrue(g.allow(("198.51.100.129", 53070), pkt, now=1000.0))


class TestWatcherLatch(unittest.TestCase):
    """The watcher must latch on the DTLS data flow (cmd-0x1502
    wrappers carrying epoch-0 handshake records), not on IOTC probe
    bursts (0x1102/0x1202), STUN, or established media (rt=23)."""

    def _pkt(self, src, dst, sport, dport, payload):
        from scapy.all import IP, UDP, Raw
        return IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(payload)

    def _watcher(self):
        from wyze_splice.splice import RelayFlowWatcher
        return RelayFlowWatcher("192.168.1.20", masq_ip="192.168.1.2")

    @staticmethod
    def _wrapper(body, cmd=0x1502, direction=0xFFFF):
        import struct as _s
        plen = 20 + len(body)  # plen = total - 12
        return (b"\x51\xcc\x00\x00" + _s.pack("<H", cmd)
                + _s.pack("<H", plen) + _s.pack("<H", direction)
                + b"\x00\x00"            # x @10:12
                + b"\x00\x10" + b"\x34\x12"   # ch, ticket
                + b"\xaa" * 8 + b"\x01\x00\x00\x00"
                + body + b"\xbb" * 20)

    @classmethod
    def _hs_flight(cls, msg=0):
        # rt=22, ver fefd, epoch 0, 6B seq, 2B rlen, hs msg type @13
        return cls._wrapper(b"\x16\xfe\xfd\x00\x00" + b"\x00" * 6
                            + b"\x00\x50" + bytes([msg]) + b"\x00" * 50)

    @classmethod
    def _plain_ch(cls):
        # msg type 1 (ClientHello), cookie_len at body[60] == 0
        return cls._wrapper(b"\x16\xfe\xfd\x00\x00" + b"\x00" * 6
                            + b"\x01\x40" + b"\x01" + b"\x00" * 71)

    @classmethod
    def _media(cls):
        # established appdata: rt=23, epoch 1
        return cls._wrapper(b"\x17\xfe\xfd\x00\x01" + b"\x00" * 56)

    def test_1502_wrapper_latches_immediately(self):
        w = self._watcher()
        with unittest.mock.patch("wyze_splice.splice.ipt") as ipt, \
                unittest.mock.patch("wyze_splice.splice.ip_cmd") as ip_cmd, \
                unittest.mock.patch("wyze_splice.netutil.local_ip_for",
                                    lambda dst: "192.168.1.2"):
            ipt.return_value.returncode = 0
            ip_cmd.return_value.returncode = 0
            # a couple of probes first
            probe = bytes.fromhex("51cc000002112800ffff0000") + b"\x00" * 40
            w._cb(self._pkt("192.168.1.20", "198.51.100.82", 50169, 3638, probe))
            w._cb(self._pkt("192.168.1.20", "198.51.100.52", 50169, 3635, probe))
            self.assertFalse(w.found.is_set())
            # the phone's plain CH (retransmissions) arrive on the same
            # reversed 5-tuple before the camera's first DTLS flight
            w._cb(self._pkt("198.51.100.101", "192.168.1.20", 24520, 50169,
                            self._plain_ch()))
            # the camera's first DTLS flight (SH) on the data flow
            w._cb(self._pkt("192.168.1.20", "198.51.100.101", 50169, 24520,
                            self._hs_flight()))
            self.assertTrue(w.found.is_set())
            self.assertEqual((w.relay_ip, w.relay_port),
                             ("198.51.100.101", 24520))
            self.assertEqual(w.cam_port, 50169)
            # the watcher installs no rules itself -- arming happens in
            # main() once the reader loop is about to run
            self.assertEqual(ipt.call_count, 0)
            self.assertEqual(ip_cmd.call_count, 0)

    def test_probe_burst_alone_does_not_latch_early(self):
        w = self._watcher()
        with unittest.mock.patch("wyze_splice.splice.ipt") as ipt, \
                unittest.mock.patch("wyze_splice.splice.ip_cmd") as ip_cmd, \
                unittest.mock.patch("wyze_splice.netutil.local_ip_for",
                                    lambda dst: "192.168.1.2"):
            ipt.return_value.returncode = 0
            ip_cmd.return_value.returncode = 0
            probe = bytes.fromhex("51cc000002112800ffff0000") + b"\x00" * 40
            for i in range(5):  # under the burst threshold, no 1502
                w._cb(self._pkt("192.168.1.20", "198.51.100.82", 50169, 3638,
                                bytes(probe[:8]) + bytes([i]) + probe[9:]))
                self.assertFalse(w.found.is_set())

    def test_stun_burst_never_latches(self):
        w = self._watcher()
        with unittest.mock.patch("wyze_splice.splice.ipt") as ipt:
            ipt.return_value.returncode = 0
            stun = b"\x00\x01\x00\x02" + b"\x00" * 40  # not 0xCC51
            for _ in range(20):
                w._cb(self._pkt("192.168.1.20", "198.51.100.168", 50169, 10240, stun))
            self.assertFalse(w.found.is_set())

    def test_media_on_stun_port_3478_latches(self):
        """2026-10-25: relay sessions can carry the DTLS data flow on the
        STUN relay's :3478. The watcher must not exclude that port."""
        w = self._watcher()
        with unittest.mock.patch("wyze_splice.splice.ipt") as ipt, \
                unittest.mock.patch("wyze_splice.splice.ip_cmd") as ip_cmd, \
                unittest.mock.patch("wyze_splice.netutil.local_ip_for",
                                    lambda dst: "192.168.1.2"):
            ipt.return_value.returncode = 0
            ip_cmd.return_value.returncode = 0
            # phone-side plain CH arrives on the reversed 3478 tuple first
            w._cb(self._pkt("198.51.100.52", "192.168.1.20", 3478, 36795,
                            self._plain_ch()))
            w._cb(self._pkt("192.168.1.20", "198.51.100.52", 36795, 3478,
                            self._hs_flight()))
            self.assertTrue(w.found.is_set())
            self.assertEqual((w.relay_ip, w.relay_port),
                             ("198.51.100.52", 3478))

    def test_p2p_handshake_burst_on_3478_does_not_latch(self):
        """The ECDSA-signed 0x0202 P2P handshake retransmits in tight
        bursts (15 in 200us observed). It must not trip the rate
        fallback -- only 0x1502 data wrappers may."""
        w = self._watcher()
        with unittest.mock.patch("wyze_splice.splice.ipt") as ipt, \
                unittest.mock.patch("wyze_splice.splice.ip_cmd") as ip_cmd:
            ipt.return_value.returncode = 0
            ip_cmd.return_value.returncode = 0
            # real 0x0202 header shape: cmd 0x0202, plen 280, dir ffff
            hs = (bytes.fromhex("51cc000002021801ffff0000")
                  + b"\x00" * 34 + bytes.fromhex("30593013")) + b"\x8e" * 242
            self.assertEqual(len(hs), 292)
            for _ in range(20):
                w._cb(self._pkt("192.168.1.20", "198.51.100.52", 36795, 3478, hs))
            self.assertFalse(w.found.is_set())

    def test_racer_flow_without_inbound_never_latches(self):
        """run-6: dying racer flows retransmit camera-side 0x1502 with
        no phone leg. Without fresh inbound 0x1502 on the same tuple,
        the outbound packets must never latch."""
        w = self._watcher()
        with unittest.mock.patch("wyze_splice.splice.ipt") as ipt, \
                unittest.mock.patch("wyze_splice.splice.ip_cmd") as ip_cmd:
            ipt.return_value.returncode = 0
            ip_cmd.return_value.returncode = 0
            dtls = self._hs_flight()
            # the racer's camera-side flight, retransmitted far beyond
            # the burst threshold -- but no phone-side 0x1502 ever
            # arrives on (198.51.100.151, 12977)
            for _ in range(30):
                w._cb(self._pkt("192.168.1.20", "198.51.100.151", 36795, 12977, dtls))
            self.assertFalse(w.found.is_set())

    def test_stale_inbound_does_not_latch(self):
        """A phone-side mark older than INBOUND_TTL seconds must not
        confirm an outbound 0x1502 (dead flow's stale retransmit)."""
        import time as _time
        w = self._watcher()
        with unittest.mock.patch("wyze_splice.splice.ipt") as ipt, \
                unittest.mock.patch("wyze_splice.splice.ip_cmd") as ip_cmd:
            ipt.return_value.returncode = 0
            ip_cmd.return_value.returncode = 0
            from wyze_splice.splice import INBOUND_TTL
            w.inbound_1502[("198.51.100.101", 24520)] = _time.time() - INBOUND_TTL - 5
            dtls = self._hs_flight()
            w._cb(self._pkt("192.168.1.20", "198.51.100.101", 50169, 24520, dtls))
            self.assertFalse(w.found.is_set())

    def test_established_media_never_latches(self):
        """run-6: after a stale teardown the app's WORKING session is
        mid-media (rt=23/ep=1, bidirectional). A relatch on it would
        divert live video into a not-yet-started engine and kill it.
        Neither the confirmed path nor the rate fallback may latch."""
        w = self._watcher()
        with unittest.mock.patch("wyze_splice.splice.ipt") as ipt, \
                unittest.mock.patch("wyze_splice.splice.ip_cmd") as ip_cmd:
            ipt.return_value.returncode = 0
            ip_cmd.returncode.returncode = 0
            media = self._media()
            # fresh inbound media marks + outbound media, single + burst
            w._cb(self._pkt("198.51.100.101", "192.168.1.20", 24520, 50169, media))
            w._cb(self._pkt("192.168.1.20", "198.51.100.101", 50169, 24520, media))
            self.assertFalse(w.found.is_set())
            for _ in range(30):
                w._cb(self._pkt("198.51.100.101", "192.168.1.20", 24520, 50169,
                                self._wrapper(b"\x17\xfe\xfd" + b"\x00" * 30)))
                w._cb(self._pkt("192.168.1.20", "198.51.100.101", 50169, 24520,
                                self._wrapper(b"\x17\xfe\xfd" + b"\x00" * 30)))
            self.assertFalse(w.found.is_set())

    def test_inbound_plain_ch_latches_fast(self):
        """The phone's plain CH arrives ~1.1s before the camera's first
        outbound flight: latching on it gives the rule install a wide
        window and the engine a clean plain-CH entry (splice3-style)."""
        w = self._watcher()
        with unittest.mock.patch("wyze_splice.splice.ipt") as ipt, \
                unittest.mock.patch("wyze_splice.splice.ip_cmd") as ip_cmd:
            ipt.return_value.returncode = 0
            ip_cmd.returncode.returncode = 0
            # the camera's 0x1102 channel-open to the relay comes first
            probe = self._wrapper(b"\x00" * 40, cmd=0x1102)
            w._cb(self._pkt("192.168.1.20", "198.51.100.101", 50169, 24520, probe))
            self.assertFalse(w.found.is_set())
            # then the phone's plain CH from the same relay endpoint
            w._cb(self._pkt("198.51.100.101", "192.168.1.20", 24520, 50169,
                            self._plain_ch()))
            self.assertTrue(w.found.is_set())
            self.assertEqual((w.relay_ip, w.relay_port),
                             ("198.51.100.101", 24520))
            self.assertEqual(w.cam_port, 50169)

    def test_inbound_ch_from_unknown_flow_ignored(self):
        """A plain CH from a relay endpoint the camera never opened a
        flow to must not latch (the latch tuple must be a real camera
        flow)."""
        w = self._watcher()
        with unittest.mock.patch("wyze_splice.splice.ipt") as ipt, \
                unittest.mock.patch("wyze_splice.splice.ip_cmd") as ip_cmd:
            ipt.return_value.returncode = 0
            ip_cmd.returncode.returncode = 0
            w._cb(self._pkt("198.51.100.9", "192.168.1.20", 41002, 50169,
                            self._plain_ch()))
            self.assertFalse(w.found.is_set())


    def test_cookie_ch_retransmit_does_not_mark(self):
        """Ghost flows from abandoned sessions retransmit cookie-CHs and
        CKEs for 15s+; only a PLAIN CH may mark the tuple, or camera-
        side retransmits on the dead tuple re-latch it across the app's
        retry window."""
        w = self._watcher()
        with unittest.mock.patch("wyze_splice.splice.ipt") as ipt, \
                unittest.mock.patch("wyze_splice.splice.ip_cmd") as ip_cmd:
            ipt.return_value.returncode = 0
            ip_cmd.returncode.returncode = 0
            cookie_ch = self._wrapper(
                b"\x16\xfe\xfd\x00\x00" + b"\x00" * 6 + b"\x01\x40"
                + b"\x01" + b"\x00" * 46 + b"\x08" + b"\x00" * 10)
            w._cb(self._pkt("198.51.100.101", "192.168.1.20", 24520, 50169,
                            cookie_ch))
            w._cb(self._pkt("192.168.1.20", "198.51.100.101", 50169, 24520,
                            self._hs_flight()))
            self.assertFalse(w.found.is_set())

    def test_pre_ch_channel_open_latches(self):
        """The camera's 0x1102 channel-open to a fresh tuple that answers
        back is the data flow being born ~440ms before the phone's CH:
        arming there gives the clean splice3 entry."""
        w = self._watcher()
        with unittest.mock.patch("wyze_splice.splice.ipt") as ipt, \
                unittest.mock.patch("wyze_splice.splice.ip_cmd") as ip_cmd:
            ipt.return_value.returncode = 0
            ip_cmd.returncode.returncode = 0
            ch_open = self._wrapper(b"\x00" * 40, cmd=0x1102)
            w._cb(self._pkt("192.168.1.20", "198.51.100.101", 50169, 24520, ch_open))
            self.assertFalse(w.found.is_set())
            # the relay answers from the same tuple
            w._cb(self._pkt("198.51.100.101", "192.168.1.20", 24520, 50169, ch_open))
            self.assertFalse(w.found.is_set())
            # the camera's next channel-open retransmit latches
            w._cb(self._pkt("192.168.1.20", "198.51.100.101", 50169, 24520, ch_open))
            self.assertTrue(w.found.is_set())
            self.assertEqual((w.relay_ip, w.relay_port),
                             ("198.51.100.101", 24520))
            self.assertEqual(w.cam_port, 50169)

    def test_one_way_channel_open_spray_ignored(self):
        """The camera sprays 0x1102s at unreachable candidates (run-6:
        AWS-internal 10.80.246.69) with no response -- no latch."""
        w = self._watcher()
        with unittest.mock.patch("wyze_splice.splice.ipt") as ipt:
            ipt.return_value.returncode = 0
            ch_open = self._wrapper(b"\x00" * 40, cmd=0x1102)
            for _ in range(10):
                w._cb(self._pkt("192.168.1.20", "198.51.100.30", 50169, 43001,
                                ch_open))
            self.assertFalse(w.found.is_set())

    def test_old_flow_channel_open_ignored(self):
        """A tuple the camera has been talking to for >10s is not a
        fresh data flow (ghost keepalives, long-lived control flows)."""
        import time as _time
        w = self._watcher()
        with unittest.mock.patch("wyze_splice.splice.ipt") as ipt:
            ipt.return_value.returncode = 0
            w.seen[("198.51.100.31", 43002)] = [_time.time() - 15, 5]
            ch_open = self._wrapper(b"\x00" * 40, cmd=0x1102)
            w._cb(self._pkt("198.51.100.31", "192.168.1.20", 43002, 50169, ch_open))
            w._cb(self._pkt("192.168.1.20", "198.51.100.31", 50169, 43002, ch_open))
            w._cb(self._pkt("192.168.1.20", "198.51.100.31", 50169, 43002, ch_open))
            self.assertFalse(w.found.is_set())

    def test_tried_tuple_not_re_latched_but_plain_ch_still_latches(self):
        """After a teardown the same tuple must not re-latch on channel-
        open noise (the app retries on a NEW port), but a plain CH on
        it still means a fresh session attempt."""
        w = self._watcher()
        with unittest.mock.patch("wyze_splice.splice.ipt") as ipt, \
                unittest.mock.patch("wyze_splice.splice.ip_cmd") as ip_cmd:
            ipt.return_value.returncode = 0
            ip_cmd.return_value.returncode = 0
            ch_open = self._wrapper(b"\x00" * 40, cmd=0x1102)
            w._cb(self._pkt("198.51.100.101", "192.168.1.20", 24520, 50169, ch_open))
            w._cb(self._pkt("192.168.1.20", "198.51.100.101", 50169, 24520, ch_open))
            self.assertTrue(w.found.is_set())
            # simulate the relatch cycle
            w.found.clear()
            w.relay_ip = w.relay_port = w.cam_port = None
            # channel-open noise on the burned tuple: no re-latch
            for _ in range(5):
                w._cb(self._pkt("198.51.100.101", "192.168.1.20", 24520, 50169, ch_open))
                w._cb(self._pkt("192.168.1.20", "198.51.100.101", 50169, 24520, ch_open))
            self.assertFalse(w.found.is_set())
            # but a plain CH on it (fresh session) still latches
            w._cb(self._pkt("198.51.100.101", "192.168.1.20", 24520, 50169,
                            self._plain_ch()))
            self.assertTrue(w.found.is_set())


class TestRelatchReason(unittest.TestCase):
    """Teardown timing: the app retries a stalled session on a NEW
    relay port ~13s after its first CH; every teardown must fire well
    inside that or the retry passes un-spliced."""

    class _Leg:
        def __init__(self, done):
            self.handshake_done = done

    class _Engine:
        def __init__(self, started, failed, cam_done):
            self.started = started
            self.failed = failed
            self.client_leg = TestRelatchReason._Leg(cam_done)

    def test_not_started_within_5s_keeps_waiting(self):
        from wyze_splice.splice import _relatch_reason
        e = self._Engine(False, False, False)
        self.assertIsNone(_relatch_reason(e, 100.0, 100.0, 104.9))

    def test_not_started_after_5s_is_stale(self):
        from wyze_splice.splice import _relatch_reason
        e = self._Engine(False, False, False)
        self.assertIn("stale", _relatch_reason(e, 100.0, 100.0, 105.1))

    def test_camera_leg_stall_tears_down(self):
        from wyze_splice.splice import _relatch_reason
        # run-6 flow 12977: the phone's CH arrived (engine started)
        # but the camera never completed its server flight
        e = self._Engine(True, False, False)
        self.assertIn("stalled", _relatch_reason(e, 100.0, 100.0, 105.1))
        self.assertIsNone(_relatch_reason(e, 100.0, 100.0, 104.9))

    def test_failed_tears_down_despite_busy_traffic(self):
        from wyze_splice.splice import _relatch_reason
        # a failed engine's tuple stays busy with retransmits; the
        # teardown must follow latch age, not packet quiet
        e = self._Engine(True, True, False)
        self.assertIn("failed", _relatch_reason(e, 100.0, 108.1, 108.1))
        self.assertIsNone(_relatch_reason(e, 100.0, 100.0, 107.0))

    def test_healthy_session_keeps_running(self):
        from wyze_splice.splice import _relatch_reason
        e = self._Engine(True, False, True)
        self.assertIsNone(_relatch_reason(e, 100.0, 100.0, 120.0))

    def test_established_session_quiet_30s_tears_down(self):
        from wyze_splice.splice import _relatch_reason
        e = self._Engine(True, False, True)
        r = _relatch_reason(e, 100.0, 100.0, 130.1)
        self.assertIn("quiet", r)

    def test_camera_silent_after_handshake_tears_down(self):
        from wyze_splice.splice import _relatch_reason
        e = self._Engine(True, None, True)
        # phone still chatty (last_packet fresh), camera quiet > 3 s
        r = _relatch_reason(e, 100.0, 110.0, 110.0, last_cam=106.9)
        self.assertIn("camera silent", r)
        self.assertIsNone(_relatch_reason(e, 100.0, 110.0, 110.0,
                                          last_cam=107.5))

    def test_no_engine_stale_pass_through_rearms(self):
        from wyze_splice.splice import _relatch_reason
        # alive while the camera talks, released once it goes silent 3 s
        self.assertIsNone(_relatch_reason(None, 100.0, 120.0, 120.0,
                                          last_cam=119.0))
        self.assertIn("silent", _relatch_reason(None, 100.0, 120.0, 120.0,
                                                last_cam=116.9))
        self.assertIn("quiet", _relatch_reason(None, 100.0, 100.0, 130.1,
                                               last_cam=130.0))

    def _install(self, peers):
        from wyze_splice.splice import install_splice_rules
        with unittest.mock.patch("wyze_splice.splice.ipt_restore") as restore, \
                unittest.mock.patch("wyze_splice.splice.ip_cmd") as ip_cmd:
            restore.return_value.returncode = 0
            ip_cmd.return_value.returncode = 0
            cleanup = install_splice_rules("192.168.1.2", "192.168.1.20", 52586,
                                           peers)
            self.assertEqual(restore.call_count, 1)   # one spawn
            self.assertTrue(any("rule" in " ".join(c.args)
                                for c in ip_cmd.call_args_list))
            return restore.call_args[0][0], cleanup

    def test_install_splice_rules_pins_the_camera_side(self):
        blob, cleanup = self._install([("198.51.100.152", 44369)])
        # only the camera's side is diverted; the relay reaches our own
        # address, through an INPUT hole
        self.assertEqual(blob.count("TPROXY"), 1)
        self.assertIn("-s 192.168.1.20 -p udp --sport 52586 -d 198.51.100.152 "
                      "--dport 44369", blob)
        self.assertIn("-s 198.51.100.152 -p udp --sport 44369 -d 192.168.1.2 "
                      "--dport 52586 -j ACCEPT", blob)
        self.assertNotIn("SNAT", blob)
        undo = [" ".join(a) for _k, a in cleanup]
        self.assertTrue(any("mangle" in u and "--sport 52586" in u for u in undo))
        self.assertTrue(any("INPUT" in u and "ACCEPT" in u for u in undo))
        self.assertTrue(any(u.startswith("rule del") for u in undo))
        self.assertTrue(any(u.startswith("route del") for u in undo))
        self.assertEqual(len(cleanup), 4)

    def test_install_splice_rules_extra_stun_paths(self):
        blob, cleanup = self._install([("198.51.100.151", 7345),
                                       ("198.51.100.82", 3478),
                                       ("198.51.100.52", 3478)])
        self.assertEqual(blob.count("TPROXY"), 3)
        self.assertIn("-d 198.51.100.82 --dport 3478", blob)
        self.assertEqual(blob.count("-j ACCEPT"), 3)
        self.assertEqual(len(cleanup), 2 * 3 + 2)

    def test_watcher_sees_relay_replies_to_our_nat_address(self):
        from scapy.all import IP, UDP
        from wyze_splice.splice import RelayFlowWatcher
        w = RelayFlowWatcher("192.168.1.20", masq_ip="192.168.1.2")
        open_ = (b"\x51\xcc\x00\x00\x02\x11\x28\x00" + bytes(44))
        cam = IP(src="192.168.1.20", dst="198.51.100.152") / UDP(sport=52586, dport=44369) / open_
        rly = IP(src="198.51.100.152", dst="192.168.1.2") / UDP(sport=44369, dport=52586) / open_
        w._cb(cam)          # camera opens; its port becomes known
        w._cb(rly)          # relay answers our NAT address
        w._cb(cam)          # camera's next channel-open latches
        self.assertTrue(w.found.is_set())
        self.assertEqual((w.relay_ip, w.relay_port, w.cam_port),
                         ("198.51.100.152", 44369, 52586))

    def test_0x1402_clienthello_is_recognised(self):
        from wyze_splice.splice import is_clienthello_flight, is_dtls_wrap
        ch = bytearray(305)
        ch[0:2] = b"\x51\xcc"
        struct.pack_into("<H", ch, 4, 0x1402)
        ch[28] = 22                    # handshake record
        ch[28 + 13] = 1                # ClientHello
        self.assertTrue(is_dtls_wrap(bytes(ch)))
        self.assertTrue(is_clienthello_flight(bytes(ch)))

    def test_install_splice_rules_fails_cleanly(self):
        from wyze_splice.splice import install_splice_rules
        with unittest.mock.patch("wyze_splice.splice.ipt_restore") as restore:
            bad = subprocess.CompletedProcess([], 1)
            bad.stderr = "iptables-restore: bad rule"
            restore.return_value = bad
            self.assertIsNone(install_splice_rules(
                "192.168.1.2", "192.168.1.20", 59344, [("198.51.100.101", 34952)]))


@unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                     "transparent sockets need Linux + root")
class TestOpenFaces(unittest.TestCase):
    def test_ttl_mirror_sets_arrival_minus_one(self):
        from wyze_splice.splice import TtlMirror, IP_TTL
        f = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            m = TtlMirror(f)
            m.follow(50)
            self.assertEqual(f.getsockopt(socket.IPPROTO_IP, IP_TTL), 49)
            m.follow(None)       # no cmsg: keep the last value
            self.assertEqual(f.getsockopt(socket.IPPROTO_IP, IP_TTL), 49)
        finally:
            f.close()

    def test_faces_bind_spoofed_and_connect(self):
        from wyze_splice.netutil import local_ip_for
        from wyze_splice.splice import open_faces
        us = local_ip_for("8.8.8.8")
        cam_face, relay_face = open_faces(("192.0.2.42", 40001),
                                          ("198.51.100.7", 40002), us)
        try:
            # cam_face impersonates the relay toward the camera
            self.assertEqual(cam_face.getsockname(), ("198.51.100.7", 40002))
            self.assertEqual(cam_face.getpeername(), ("192.0.2.42", 40001))
            # relay_face is our NAT address on the camera's port
            self.assertEqual(relay_face.getsockname(), (us, 40001))
            self.assertEqual(relay_face.getpeername(), ("198.51.100.7", 40002))
        finally:
            cam_face.close()
            relay_face.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
