"""Full-engine media round-trip test, entirely in-process.

Two DTLSLeg instances play the phone (client role) and the camera (server
role). All their packets are wrapped in format-exact 0x1502 wrappers and fed
through a real SpliceEngine; the engine's emissions are unwrapped and fed to
the peer leg. This exercises the plumbing that leg-level interop tests cannot
see: wrapper-cache take()/add() accounting across a whole session, record
seq/epoch management on both legs, dedupe, and the media re-emission path
(camera appdata -> decrypt -> re-encrypt on the phone leg -> wrapped emission).

Validates the open question from splice3: the engine completed both legs and
emitted media with no pending/dropped logs, yet the phone's AV ACKs stayed
rx=0xffff. If media round-trips byte-exact here, the engine's DTLS and
wrapper layers are exonerated and a live failure must be network-layer
(relay/SNAT), which run-6's E/e instrumentation and wire pcap will expose.
"""

from __future__ import annotations

import os
import struct
import sys


from wyzecrack.dtls import (  # noqa: E402
    DTLSLeg, HS_CH, HS_CKE, RT_APPDATA, RT_CCS, RT_HANDSHAKE, SpliceEngine,
    Templates, derive_psk, parse_hs, parse_records,
)

ENR = "gekMdn0XjZoWF/mD"
PSK = derive_psk(ENR)
TICK = 0xAB59
SID = bytes.fromhex("5af37da2072fd650")


def wrap(payload: bytes, cam_side: bool) -> bytes:
    """Format-exact 0x1502 wrapper: 28B header + payload + 20B trailer."""
    header = bytearray(28)
    struct.pack_into("<H", header, 0, 0xCC51)
    struct.pack_into("<H", header, 4, 0x1502)
    struct.pack_into("<H", header, 6, len(payload) + 36)  # plen = total-12
    struct.pack_into("<H", header, 8, 0xFFFF if cam_side else 0x0000)
    struct.pack_into("<H", header, 12, 0x0010)
    struct.pack_into("<H", header, 14, TICK)
    header[16:24] = SID
    header[24:28] = b"\x01\x00\x00\x00"
    return bytes(header) + payload + b"\xAA" * 20


def unwrap(w: bytes) -> bytes:
    return w[28:-20]


def drive_server(leg, payload):
    out = b""
    for rtype, ver, epoch, seq, body in parse_records(payload):
        if rtype == RT_HANDSHAKE and epoch == 0:
            for msg in parse_hs(body):
                if msg[0] == HS_CH:
                    out = leg.server_on_ch(msg)
                elif msg[0] == HS_CKE:
                    leg.server_on_cke(msg)
        elif rtype == RT_CCS:
            leg.server_on_ccs()
        elif epoch == 1:
            pt = leg.decrypt_record(rtype, ver, epoch, seq, body)
            if rtype == RT_HANDSHAKE:
                f = leg.server_on_fin(pt)
                if f:
                    out = f
    return out


def drive_client(leg, payload, started):
    out = b""
    for rtype, ver, epoch, seq, body in parse_records(payload):
        if rtype == RT_HANDSHAKE and epoch == 0:
            msgs = parse_hs(body)
            if msgs and not started[0]:
                out = leg.client_hello()
                started[0] = True
            elif msgs:
                f = leg.client_on_server_flight(msgs)
                if f:
                    out = f
        elif rtype == RT_CCS:
            leg.client_on_ccs()
        elif epoch == 1:
            pt = leg.decrypt_record(rtype, ver, epoch, seq, body)
            if rtype == RT_HANDSHAKE:
                leg.client_on_fin(pt)
    return out


def feed(engine, cam_started, phone_started, to_cam=None, to_phone=None):
    """Deliver engine emissions to the fake peers; return their replies."""
    replies = []
    for w in (to_cam or []):
        flight = drive_server(engine_camera, unwrap(w))
        if flight:
            replies.append(("cam", flight))
    for w in (to_phone or []):
        flight = drive_client(engine_phone, unwrap(w), phone_started)
        if flight:
            replies.append(("phone", flight))
    return replies


engine_phone = None
engine_camera = None
VERBOSE = os.environ.get("TRACE") == "1"


def run_session(media_plaintexts, ack_plaintexts, split=False):
    global engine_phone, engine_camera
    engine = SpliceEngine(ENR)
    engine_phone = DTLSLeg("client", PSK, Templates.embedded())
    engine_camera = DTLSLeg("server", PSK, Templates.embedded())
    phone_started = [True]  # kickoff CH was already sent by run_session

    def deliver(replies):
        """Feed peer replies through the engine; loop until quiescent."""
        rounds = 0
        while replies and rounds < 20:
            rounds += 1
            nxt = []
            if split:
                from wyzecrack.dtls import split_records
                replies = [(side, r) for side, f in replies
                           for r in (split_records(f) or [f])]
            for side, flight in replies:
                if VERBOSE:
                    recs = parse_records(flight)
                    kinds = ";".join(f"t{r}/e{e}/" + "/".join(str(m[0]) for m in parse_hs(b)) for r, v, e, s, b in recs)
                    print(f"[trace] {side} -> engine: {len(flight)}B | {kinds}")
                if side == "phone":
                    to_cam, to_phone = engine.on_phone_packet(wrap(flight, cam_side=False))
                else:
                    to_cam, to_phone = engine.on_cam_packet(wrap(flight, cam_side=True))
                assert engine.failed is None, f"engine failed: {engine.failed}"
                for w in to_cam:
                    if VERBOSE:
                        print(f"[trace] engine -> cam: {len(w)}B")
                    f = drive_server(engine_camera, unwrap(w))
                    if f:
                        nxt.append(("cam", f))
                for w in to_phone:
                    if VERBOSE:
                        recs = parse_records(unwrap(w))
                        kinds = ";".join(f"t{r}/e{e}/" + "/".join(str(m[0]) for m in parse_hs(b)) for r, v, e, s, b in recs)
                        print(f"[trace] engine -> phone: {len(w)}B | {kinds}")
                    f = drive_client(engine_phone, unwrap(w), phone_started)
                    if f:
                        nxt.append(("phone", f))
            replies = nxt

    # kickoff: the phone's ClientHello starts everything
    ch = engine_phone.client_hello()
    deliver([("phone", ch)])
    assert engine.started, "engine never saw the phone ClientHello"
    assert engine.server_leg.handshake_done, "phone leg handshake incomplete"
    assert engine.client_leg.handshake_done, "camera leg handshake incomplete"

    # media: camera -> phone (decrypted by engine, re-emitted re-encrypted)
    got_media = []
    for pt in media_plaintexts:
        rec = engine_camera.encrypt_record(RT_APPDATA, pt)
        to_cam, to_phone = engine.on_cam_packet(wrap(rec, cam_side=True))
        assert engine.failed is None, engine.failed
        assert len(to_phone) == 1, f"expected 1 re-emission, got {len(to_phone)}"
        for rtype, ver, epoch, seq, body in parse_records(unwrap(to_phone[0])):
            got_media.append(engine_phone.decrypt_record(rtype, ver, epoch, seq, body))
        # camera-side emissions (if any) go back to the fake camera's peer
        for w in to_cam:
            drive_server(engine_camera, unwrap(w))

    # acks: phone -> camera
    got_acks = []
    for pt in ack_plaintexts:
        rec = engine_phone.encrypt_record(RT_APPDATA, pt)
        to_cam, to_phone = engine.on_phone_packet(wrap(rec, cam_side=False))
        assert engine.failed is None, engine.failed
        assert len(to_cam) == 1, f"expected 1 re-emission, got {len(to_cam)}"
        for rtype, ver, epoch, seq, body in parse_records(unwrap(to_cam[0])):
            got_acks.append(engine_camera.decrypt_record(rtype, ver, epoch, seq, body))
        for w in to_phone:
            drive_client(engine_phone, unwrap(w), phone_started)

    assert not engine.pending["to_cam"], f"unwrapped to_cam pending: {engine.pending['to_cam']}"
    assert not engine.pending["to_phone"], f"unwrapped to_phone pending: {engine.pending['to_phone']}"
    return engine, got_media, got_acks


def test_engine_media_roundtrip():
    media = [b"\x0a\x00" + bytes([i]) * (40 + i) for i in range(12)]
    acks = [b"\x09\x00" + struct.pack("<I", i) + b"\xff\xff\xff\xff" for i in range(3)]
    engine, got_media, got_acks = run_session(media, acks)
    assert got_media == media, "camera media did not round-trip byte-exact"
    assert got_acks == acks, "phone acks did not round-trip byte-exact"
    assert engine.server_leg.handshake_done and engine.client_leg.handshake_done


def test_engine_split_flights():
    """Both peers send each record of a handshake flight in its own
    datagram (live 2026-11-04): the engine must answer the same way, since
    no whole-flight-sized wrapper ever arrives."""
    media = [b"\x0a\x00" + bytes([i]) * (40 + i) for i in range(4)]
    acks = [b"\x09\x00" + struct.pack("<I", 1) + b"\xff\xff\xff\xff"]
    engine, got_media, got_acks = run_session(media, acks, split=True)
    assert got_media == media and got_acks == acks


def test_engine_media_roundtrip_varied_sizes():
    # exercise the wrapper cache across many payload lengths, incl. sizes
    # that force separate cached wrappers per length
    media = [b"\x0a\x01" + os.urandom(n) for n in (16, 33, 62, 89, 120, 244, 501)]
    engine, got_media, _ = run_session(media, [])
    assert got_media == media


if __name__ == "__main__":
    test_engine_media_roundtrip()
    test_engine_media_roundtrip_varied_sizes()
    print("ok engine media round-trip (handshake + media + acks, both legs)")
