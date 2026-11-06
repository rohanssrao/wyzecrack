#!/usr/bin/env python3
"""Offline tests for dtls.py: PSK derivation, template fidelity, and a
client/server handshake loopback."""
import pytest

from wyzecrack.dtls import (  # noqa: E402
    BadRecord, DTLSLeg, HS_CH, HS_CKE, RT_APPDATA, RT_CCS, RT_HANDSHAKE,
    Templates, derive_psk, parse_hs, parse_records,
)

ENR = "gekMdn0XjZoWF/mD"
PSK_HEX = ("cad9cb845808bd1baa377ceda71a843e30269d5b2aaacae6c975913266500000")


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


def test_ch_template_fidelity():
    tpl = Templates.embedded()
    psk = derive_psk(ENR)
    c = DTLSLeg("client", psk, tpl)
    ch_payload = c.client_hello()
    my_ch = parse_hs(parse_records(ch_payload)[0][4])[0][2][12:]
    assert my_ch[:2] == tpl.ch[:2]
    assert my_ch[34:] == tpl.ch[34:], "CH tail (suites/ext) must be template"
    assert my_ch[2:34] == c.random


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
    assert s.handshake_done and nst
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
    # a tampered record doesn't authenticate
    rt, ver, ep, sq, body = parse_records(b_)[0]
    with pytest.raises(BadRecord):
        c.decrypt_record(rt, ver, ep, sq, bytes(len(body)))
