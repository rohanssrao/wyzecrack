"""dtls.py: PSK derivation, the ClientHello template, and a whole handshake
against the fake camera's server side."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from fakecam import ENR, ServerLeg  # noqa: E402

from wyzecrack.dtls import (CLIENT_HELLO, HS_CH, HS_CKE, RT_APPDATA,  # noqa: E402
                            RT_CCS, RT_HANDSHAKE, BadRecord, DTLSClient,
                            derive_psk, parse_hs, parse_records)

# SHA256 of ENR has its first NUL at byte 30: cut there, then zero-padded
PSK_HEX = "cad9cb845808bd1baa377ceda71a843e30269d5b2aaacae6c975913266500000"


def test_psk():
    assert derive_psk(ENR).hex() == PSK_HEX


def test_client_hello_follows_the_template():
    c = DTLSClient(derive_psk(ENR))
    ch = parse_hs(parse_records(c.client_hello())[0][4])[0][2][12:]
    assert ch[:2] == CLIENT_HELLO[:2] and ch[34:] == CLIENT_HELLO[34:]
    assert ch[2:34] == c.random


def _to_server(s, flight):
    """Feed a client flight to the server leg; its answer."""
    out = b""
    for rtype, ver, epoch, seq, body in parse_records(flight):
        if rtype == RT_HANDSHAKE and epoch == 0:
            for msg in parse_hs(body):
                if msg[0] == HS_CH:
                    out = s.on_client_hello(msg)
                elif msg[0] == HS_CKE:
                    s.on_cke(msg)
        elif epoch == 1:
            out = s.on_fin(s.decrypt_record(rtype, ver, epoch, seq, body)) or out
    return out


def _to_client(c, flight):
    for rtype, ver, epoch, seq, body in parse_records(flight):
        if rtype == RT_HANDSHAKE and epoch == 0:
            c.on_server_flight(parse_hs(body))
        elif rtype == RT_CCS:
            c.on_ccs()
        elif epoch == 1:
            c.on_fin(c.decrypt_record(rtype, ver, epoch, seq, body))


def test_handshake_with_the_fake_camera():
    c, s = DTLSClient(derive_psk(ENR)), ServerLeg(derive_psk(ENR))
    server_flight = _to_server(s, c.client_hello())
    cke = c.on_server_flight([m for r in parse_records(server_flight)
                              for m in parse_hs(r[4])])
    _to_client(c, _to_server(s, cke))
    assert s.handshake_done and c.handshake_done

    r = parse_records(c.encrypt_record(RT_APPDATA, b"from the client"))[0]
    assert s.decrypt_record(*r) == b"from the client"
    rt, ver, ep, sq, body = parse_records(s.encrypt_record(RT_APPDATA, b"hi"))[0]
    assert c.decrypt_record(rt, ver, ep, sq, body) == b"hi"
    with pytest.raises(BadRecord):                 # tampered
        c.decrypt_record(rt, ver, ep, sq, bytes(len(body)))


def test_a_wrong_psk_fails_the_handshake():
    c, s = DTLSClient(derive_psk(ENR)), ServerLeg(derive_psk("another key"))
    server_flight = _to_server(s, c.client_hello())
    cke = c.on_server_flight([m for r in parse_records(server_flight)
                              for m in parse_hs(r[4])])
    with pytest.raises(BadRecord):
        _to_server(s, cke)
