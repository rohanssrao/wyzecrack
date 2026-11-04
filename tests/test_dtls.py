#!/usr/bin/env python3
"""Offline tests for dtls_splice: crypto loopback, flight sizes, template
fidelity, and a full SpliceEngine loopback against mock phone/camera
endpoints (which are themselves DTLSLeg instances) with wrapper reuse."""
import struct
import sys
import time

from wyze_splice.dtls import (  # noqa: E402
    DTLSLeg, FLIGHT_SIZES, HS_CH, HS_CKE, HS_FIN, HS_NST, RT_APPDATA,
    RT_CCS, RT_HANDSHAKE, SpliceEngine, Templates, WRAPPER_HDR,
    WRAPPER_TRL, build_record, derive_psk, parse_hs, parse_records,
)

ENR = "gekMdn0XjZoWF/mD"
PSK_HEX = ("cad9cb845808bd1baa377ceda71a843e30269d5b2aaacae6c975913266500000")


def wrap(payload, seq, direction):
    header = bytearray(28)
    header[0:2] = b"\x51\xcc"
    header[4:6] = struct.pack("<H", 0x1502)
    header[6:8] = struct.pack("<H", len(payload) + 36)  # real plen semantics
    header[8:10] = struct.pack("<H", direction)
    header[12:14] = struct.pack("<H", seq)
    return bytes(header) + payload + b"\x00" * WRAPPER_TRL


def unwrap(w):
    return w[WRAPPER_HDR:-WRAPPER_TRL]


def drive_server(leg, payload):
    """Feed a flight payload to a server-role leg; return its next flight."""
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
    """Feed a flight payload to a client-role leg; return its next flight."""
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


def test_psk():
    psk = derive_psk(ENR)
    assert psk.hex() == PSK_HEX, psk.hex()
    assert len(psk) == 32
    assert psk.hex().endswith("0000"), "must be zero-padded to 32B"
    print("ok psk derivation (NUL-truncated SHA256, zero-padded to 32B)")


def test_templates():
    tpl = Templates.embedded()
    assert FLIGHT_SIZES == {"ch": 257, "sh_flight": 166, "cke_flight": 140,
                            "nst_flight": 274}
    print("ok templates load, flight sizes 257/166/140/274")


def test_flight_sizes():
    tpl = Templates.embedded()
    psk = derive_psk(ENR)
    c = DTLSLeg("client", psk, tpl)
    s = DTLSLeg("server", psk, tpl)
    ch = c.client_hello()
    assert len(ch) == FLIGHT_SIZES["ch"], len(ch)
    sh = s.server_on_ch(parse_hs(parse_records(ch)[0][4])[0])
    assert len(sh) == FLIGHT_SIZES["sh_flight"], len(sh)
    cke = c.client_on_server_flight(
        [m for r in parse_records(sh) for m in parse_hs(r[4])])
    assert len(cke) == FLIGHT_SIZES["cke_flight"], len(cke)
    print("ok flight payload sizes match capture (257/166/140)")


def test_ch_template_fidelity():
    tpl = Templates.embedded()
    psk = derive_psk(ENR)
    c = DTLSLeg("client", psk, tpl)
    ch_payload = c.client_hello()
    my_ch = parse_hs(parse_records(ch_payload)[0][4])[0][2][12:]
    assert my_ch[:2] == tpl.ch[:2]
    assert my_ch[34:] == tpl.ch[34:], "CH tail (suites/ext) must be template"
    assert my_ch[2:34] == c.random
    print("ok my ClientHello == template except random")


def test_leg_loopback():
    """My client leg and server leg complete a handshake with each other."""
    tpl = Templates.embedded()
    psk = derive_psk(ENR)
    c = DTLSLeg("client", psk, tpl)
    s = DTLSLeg("server", psk, tpl)

    ch = c.client_hello()
    sh = s.server_on_ch(parse_hs(parse_records(ch)[0][4])[0])
    cke = c.client_on_server_flight(
        [m for r in parse_records(sh) for m in parse_hs(r[4])])
    nst = drive_server(s, cke)
    assert s.handshake_done and len(nst) == FLIGHT_SIZES["nst_flight"]
    # client consumes NST flight
    started = [True]
    out = drive_client(c, nst, started)
    assert out == b""
    assert c.handshake_done

    # appdata both directions
    a = c.encrypt_record(RT_APPDATA, b"hello-from-client")
    r = parse_records(a)[0]
    assert s.decrypt_record(*r) == b"hello-from-client"
    b_ = s.encrypt_record(RT_APPDATA, b"hi-from-server")
    r = parse_records(b_)[0]
    assert c.decrypt_record(*r) == b"hi-from-server"
    # finished-verify already implied by handshake_done
    print("ok leg loopback: handshake + appdata round-trip")


def test_engine_loopback():
    """Full SpliceEngine against mock phone (client leg) and mock camera
    (server leg), with wrappers, pending flushes, and appdata crossing."""
    tpl = Templates.embedded()
    psk = derive_psk(ENR)
    eng = SpliceEngine(ENR, tpl)
    phone = DTLSLeg("client", psk, tpl)   # the real phone
    camera = DTLSLeg("server", psk, tpl)  # the real camera
    seq = {"ph": 0, "cam": 0}

    def ph_send(payload):
        seq["ph"] += 1
        return wrap(payload, seq["ph"], 0x0000)

    def cam_send(payload):
        seq["cam"] += 1
        return wrap(payload, seq["cam"], 0xFFFF)

    # 1. phone CH
    to_cam, to_phone = eng.on_phone_packet(ph_send(phone.client_hello()))
    assert to_phone == [], "SH flight must pend (no 166 wrapper yet)"
    assert len(to_cam) == 1 and len(unwrap(to_cam[0])) == FLIGHT_SIZES["ch"]
    assert to_cam[0][:WRAPPER_HDR] == eng.to_cam.last_header, \
        "my CH must reuse the phone CH wrapper header"
    my_ch = to_cam[0]

    # 2. camera SH flight (in response to my CH)
    cam_flight = drive_server(camera, unwrap(my_ch))
    assert len(cam_flight) == FLIGHT_SIZES["sh_flight"]
    to_cam, to_phone = eng.on_cam_packet(cam_send(cam_flight))
    assert len(to_phone) == 1, "SH flight flushes once 166 wrapper cached"
    assert len(to_cam) == 0, "CKE flight must pend (no 140 wrapper yet)"
    my_sh = to_phone[0]

    # 3. phone CKE+CCS+Fin
    started = [True]
    cke_flight = drive_client(phone, unwrap(my_sh), started)
    assert len(cke_flight) == FLIGHT_SIZES["cke_flight"]
    to_cam, to_phone = eng.on_phone_packet(ph_send(cke_flight))
    assert len(to_cam) == 1, "CKE flight flushes once 140 wrapper cached"
    assert to_phone == [], "NST flight must pend (no 274 wrapper yet)"
    my_cke = to_cam[0]

    # 4. camera NST+CCS+Fin
    nst_flight = drive_server(camera, unwrap(my_cke))
    assert len(nst_flight) == FLIGHT_SIZES["nst_flight"]
    to_cam, to_phone = eng.on_cam_packet(cam_send(nst_flight))
    assert len(to_phone) == 1, "NST flight flushes once 274 wrapper cached"
    my_nst = to_phone[0]

    # 5. phone consumes NST flight -> done
    out = drive_client(phone, unwrap(my_nst), started)
    assert out == b"" and phone.handshake_done
    assert eng.server_leg.handshake_done and eng.client_leg.handshake_done
    assert eng.failed is None

    # 6. appdata phone -> camera through the splice
    rec = phone.encrypt_record(RT_APPDATA, b"start-live")
    to_cam, to_phone = eng.on_phone_packet(ph_send(rec))
    assert len(to_cam) == 1
    r = parse_records(unwrap(to_cam[0]))[0]
    assert camera.decrypt_record(*r) == b"start-live"

    # 7. appdata camera -> phone through the splice
    rec = camera.encrypt_record(RT_APPDATA, b"\x00" * 600 + b"FRAME")
    to_cam, to_phone = eng.on_cam_packet(cam_send(rec))
    assert len(to_phone) == 1
    r = parse_records(unwrap(to_phone[0]))[0]
    assert phone.decrypt_record(*r) == b"\x00" * 600 + b"FRAME"

    # 8. retransmission: phone resends its CKE flight verbatim; the
    #    engine resends its cached NST flight unchanged
    to_cam, to_phone = eng.on_phone_packet(ph_send(cke_flight))
    assert len(to_phone) == 1, "retransmit must trigger a resend"
    assert to_phone[0] == my_nst, "NST flight must be resent verbatim"
    if to_phone[0] == my_nst:
        pass    # plain resend of our last flight
    else:
        # first retransmit adaptively retries the alternate NST-in-hash
        # formula (same 274B flight, re-encrypted Fin, same wrapper)
        alt = eng.server_leg.last_flight
        assert len(alt) == FLIGHT_SIZES["nst_flight"]
        assert to_phone[0][WRAPPER_HDR:-WRAPPER_TRL] == alt
        assert to_phone[0][:WRAPPER_HDR] == my_nst[:WRAPPER_HDR]
        # second retransmit resends the current last flight verbatim
        to_cam, to_phone = eng.on_phone_packet(ph_send(cke_flight))
        assert to_phone == [to_phone[0]] or len(to_phone) == 1
        assert to_phone[0][WRAPPER_HDR:-WRAPPER_TRL] == alt

    # 9. wrapper bookkeeping: nothing stuck pending; steady-state sizes
    #    consumed 1:1 (only the retransmitted 140 wrappers remain pooled)
    assert not eng.pending["to_cam"] and not eng.pending["to_phone"]
    for size in (257, 166, 274, 39, 634):
        q = eng.to_cam.pool.get(size) or eng.to_phone.pool.get(size)
        assert not q, f"size {size} left in pool"
    print("ok engine loopback: pending flushes, wrapper reuse, appdata, "
          "retransmit handling")


def test_tick_retransmit():
    tpl = Templates.embedded()
    eng = SpliceEngine(ENR, tpl)
    phone = DTLSLeg("client", eng.psk, tpl)
    to_cam, _ = eng.on_phone_packet(wrap(phone.client_hello(), 1, 0))
    assert len(to_cam) == 1
    out = eng.tick(now=time.time() + 0.1)
    assert out == ([], []), "too early to retransmit"
    out = eng.tick(now=time.time() + 5.0)
    assert out == (to_cam, []), "quiet link must retransmit last to_cam flight"
    print("ok tick retransmission")


def test_synthesize_fallback():
    tpl = Templates.embedded()
    eng = SpliceEngine(ENR, tpl)
    # no wrappers cached at all
    w = eng.to_cam.synthesize(b"abcdef")
    assert w[:2] == b"\x51\xcc"
    assert struct.unpack("<H", w[6:8])[0] == 6 + 36
    assert len(w) == 28 + 6 + 20
    print("ok synthesize fallback")


def _pick_scheme(leg, name):
    for s in leg.schemes:
        if s.name == name:
            return s
    raise AssertionError(f"scheme {name} not in candidates")


def test_engine_discovers_nonrfc():
    """Both endpoints run a deviating stack (non-reference construction +
    non-RFC AAD). The engine's server leg must discover it from the
    phone's Fin, propagate it to the camera leg before the CKE flight
    leaves, and the splice must complete with appdata both ways."""
    import json as _json
    import tempfile
    tpl = Templates.embedded()
    dev_name = "ems/h4/cr_sr/interleaved"   # NOT the RFC reference
    dev_aad = "aad_no_es"
    jr = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
    jr.close()
    eng = SpliceEngine(ENR, tpl, journal=jr.name)
    phone = DTLSLeg("client", eng.psk, tpl)
    camera = DTLSLeg("server", eng.psk, tpl)
    seq = {"ph": 0, "cam": 0}

    def ph_send(payload):
        seq["ph"] += 1
        return wrap(payload, seq["ph"], 0x0000)

    def cam_send(payload):
        seq["cam"] += 1
        return wrap(payload, seq["cam"], 0xFFFF)

    # 1. phone CH -> my CH
    to_cam, to_phone = eng.on_phone_packet(ph_send(phone.client_hello()))
    assert len(to_cam) == 1 and eng.to_phone.pool.get(166) is None
    my_ch = to_cam[0]

    # 2. camera SH flight -> my CKE flight pends (built RFC so far)
    cam_flight = drive_server(camera, unwrap(my_ch))
    to_cam, to_phone = eng.on_cam_packet(cam_send(cam_flight))
    assert len(to_phone) == 1 and len(to_cam) == 0
    my_sh = to_phone[0]
    rfc_flight = eng.client_leg.last_flight

    # 3. phone's CKE flight under the DEVIATING construction
    started = [True]
    cke_flight = drive_client(phone, unwrap(my_sh), started)
    phone.scheme = _pick_scheme(phone, dev_name)
    phone.aad_variant = dev_aad
    cke_flight = phone.client_rebuild_flight()
    to_cam, to_phone = eng.on_phone_packet(ph_send(cke_flight))
    assert eng.failed is None, eng.failed
    # discovery happened on the server leg
    assert eng.server_leg.scheme is not None
    assert eng.server_leg.scheme.name == dev_name
    assert eng.server_leg.aad_variant == dev_aad
    # propagated to the camera leg, CKE flight rebuilt BEFORE flushing
    assert eng.client_leg.scheme is not None
    assert eng.client_leg.scheme.name == dev_name
    assert eng.client_leg.aad_variant == dev_aad
    assert len(to_cam) == 1, "corrected CKE flight must flush"
    my_cke = to_cam[0]
    assert unwrap(my_cke) != rfc_flight, "CKE flight must be rebuilt"
    assert len(unwrap(my_cke)) == FLIGHT_SIZES["cke_flight"]

    # 4. camera accepts the corrected CKE flight; its own decrypt cascade
    #    discovers the same construction from my rebuilt Fin
    nst_flight = drive_server(camera, unwrap(my_cke))
    assert len(nst_flight) == FLIGHT_SIZES["nst_flight"]
    assert camera.scheme is not None and camera.scheme.name == dev_name
    assert camera.aad_variant == dev_aad
    to_cam, to_phone = eng.on_cam_packet(cam_send(nst_flight))
    assert eng.failed is None, eng.failed
    assert len(to_phone) == 1, "NST flight must flush"
    my_nst = to_phone[0]

    # 5. phone consumes the NST flight -> both sides done
    out = drive_client(phone, unwrap(my_nst), started)
    assert out == b"" and phone.handshake_done
    assert eng.server_leg.handshake_done and eng.client_leg.handshake_done

    # 6. appdata crossing both ways under the adopted construction
    rec = phone.encrypt_record(RT_APPDATA, b"start-live")
    to_cam, _ = eng.on_phone_packet(ph_send(rec))
    r = parse_records(unwrap(to_cam[0]))[0]
    assert camera.decrypt_record(*r) == b"start-live"
    rec = camera.encrypt_record(RT_APPDATA, b"\x00" * 300 + b"F")
    _, to_phone = eng.on_cam_packet(cam_send(rec))
    r = parse_records(unwrap(to_phone[0]))[0]
    assert phone.decrypt_record(*r) == b"\x00" * 300 + b"F"

    # 7. journal has the full key material and the discovery
    events = [_json.loads(l) for l in open(jr.name)]
    kinds = [e.get("ev") for e in events]
    assert "engine_init" in kinds and "derive" in kinds
    assert "discover" in kinds
    d = next(e for e in events if e.get("ev") == "discover")
    assert d["scheme"] == dev_name and d["aad"] == dev_aad
    der = next(e for e in events if e.get("ev") == "derive")
    assert len(der["shared"]) == 64 and len(der["schemes"]) >= 14
    import os as _os
    _os.unlink(jr.name)
    print("ok engine discovers non-RFC construction from the phone's Fin "
          "and propagates it to the camera leg")


def test_engine_cam_retry():
    """Camera retransmits its SH flight (rejected our CKE): first retry
    rebuilds under the current scheme, second flips the Fin label; sizes
    stay byte-identical and no duplicate pending entries appear."""
    tpl = Templates.embedded()
    eng = SpliceEngine(ENR, tpl)
    phone = DTLSLeg("client", eng.psk, tpl)
    camera = DTLSLeg("server", eng.psk, tpl)
    seq = {"ph": 0, "cam": 0}

    def ph_send(payload):
        seq["ph"] += 1
        return wrap(payload, seq["ph"], 0x0000)

    def cam_send(payload):
        seq["cam"] += 1
        return wrap(payload, seq["cam"], 0xFFFF)

    to_cam, _ = eng.on_phone_packet(ph_send(phone.client_hello()))
    my_ch = to_cam[0]
    cam_flight = drive_server(camera, unwrap(my_ch))
    to_cam, to_phone = eng.on_cam_packet(cam_send(cam_flight))
    my_sh = to_phone[0]
    started = [True]
    cke_flight = drive_client(phone, unwrap(my_sh), started)

    # camera SH retransmission #1: rebuild (same construction here)
    to_cam, _ = eng.on_cam_packet(cam_send(cam_flight))
    assert len(to_cam) == 0, "no 140 wrapper yet; retry must pend, not emit"
    pend = [p for p, _, _ in eng.pending["to_cam"]]
    assert pend == [eng.client_leg.last_flight]
    assert len(pend[0]) == FLIGHT_SIZES["cke_flight"]

    # camera SH retransmission #2: label flip, still one pending entry
    to_cam, _ = eng.on_cam_packet(cam_send(cam_flight))
    assert len(to_cam) == 0
    pend = [p for p, _, _ in eng.pending["to_cam"]]
    assert len(pend) == 1 and len(pend[0]) == FLIGHT_SIZES["cke_flight"]
    assert eng.client_leg._fin_label_alt is True

    # phone CKE now arrives: RFC discovery, pending replaced, flushed once
    to_cam, _ = eng.on_phone_packet(ph_send(cke_flight))
    assert eng.failed is None, eng.failed
    assert len(to_cam) == 1
    assert len(unwrap(to_cam[0])) == FLIGHT_SIZES["cke_flight"]
    my_cke = to_cam[0]
    # the flushed flight uses the flipped-back default label after the
    # phone's Fin decrypted under the reference scheme
    nst_flight = drive_server(camera, unwrap(my_cke))
    assert len(nst_flight) == FLIGHT_SIZES["nst_flight"]
    to_cam, to_phone = eng.on_cam_packet(cam_send(nst_flight))
    assert eng.failed is None and eng.client_leg.handshake_done
    assert len(to_phone) == 1
    out = drive_client(phone, unwrap(to_phone[0]), started)
    assert out == b"" and phone.handshake_done
    print("ok engine camera-retry: rebuild + label flip, no duplicate "
          "pending entries")


if __name__ == "__main__":
    test_psk()
    test_templates()
    test_flight_sizes()
    test_ch_template_fidelity()
    test_leg_loopback()
    test_engine_loopback()
    test_tick_retransmit()
    test_synthesize_fallback()
    test_engine_discovers_nonrfc()
    test_engine_cam_retry()
    print("ALL TESTS PASSED")


def test_session_key_ignores_the_per_path_ticket():
    """Live 2026-11-04: the phone's ClientHello came as 0x1402 with ticket
    3e02 via a STUN relay; the camera's flights were 0x1502 with ticket
    ef89 on the data relay. Same session id, same session."""
    from wyze_splice.dtls import session_key
    sid = bytes.fromhex("513361dc1b4ebf55")
    via_stun = bytes(14) + bytes.fromhex("3e02") + sid + bytes(30)
    via_data = bytes(14) + bytes.fromhex("ef89") + sid + bytes(30)
    other = bytes(14) + bytes.fromhex("ef89") + bytes(8) + bytes(30)
    assert session_key(via_stun) == session_key(via_data)
    assert session_key(other) != session_key(via_data)
