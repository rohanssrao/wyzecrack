"""Cloud interception: ENR and event parsing, and the eMudhra-signed leaf."""
import socket
import ssl
import tempfile
import threading

from cryptography.hazmat.primitives import serialization

from wyze_splice import cloud as enr


def test_find_enr_unescapes_and_finds_mac():
    body = (b'POST /device/system/set_device_info HTTP/1.1\r\n\r\n'
            b'{"mac":"d03f27a1b2c3","enr":"gekMdn0XjZoWF\\/mD","x":1}')
    assert enr.find_enr(body) == ("gekMdn0XjZoWF/mD", "D03F27A1B2C3")
    assert enr.find_enr(b'{"mac":"D03F27A1B2C3"}') is None


def test_leaf_validates_against_the_emudhra_intermediate():
    """A client that trusts the compromised intermediate accepts the leaf
    for the requested name, with the chain we serve."""
    certfile, keyfile = enr.mint_leaf("api.wyzecam.com", tempfile.mkdtemp())
    _key, icert, _cross = enr.emudhra_chain()
    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.load_cert_chain(certfile, keyfile)
    cli_ctx = ssl.create_default_context(
        cadata=icert.public_bytes(serialization.Encoding.PEM).decode())
    # the intermediate is the trust anchor here, as in a stale device store
    cli_ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    a, b = socket.socketpair()
    err = []

    def serve():
        try:
            with srv_ctx.wrap_socket(a, server_side=True) as s:
                s.sendall(s.recv(5))
        except Exception as e:  # noqa: BLE001
            err.append(e)
    t = threading.Thread(target=serve)
    t.start()
    with cli_ctx.wrap_socket(b, server_hostname="api.wyzecam.com") as c:
        c.sendall(b"hello")
        assert c.recv(5) == b"hello"
    t.join(5)
    assert not err


def test_request_tap_splits_pipelined_requests_and_names_events():
    got = []
    tap = enr.RequestTap(lambda m, p, h, b: got.append((m, p, b)))
    put = (b"/D03F27A1B2C3/2026-01-01/D03F27A1B2C3011767225600_1767225600894_1_2_0/"
           b"0123456789abcdef0123456789abcdef_1.mp4?Policy=x&Signature=y")
    clip = b"\x00\x00\x00\x18ftypmp42" + bytes(100)
    stream = (b"POST /device/alarm/upload_alarm HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}"
              + b"PUT " + put + b" HTTP/1.1\r\nHost: cpl-t-sightsafe.wyzecam.com\r\n"
              + b"Content-Length: %d\r\n\r\n" % len(clip) + clip)
    for i in range(0, len(stream), 7):        # arbitrary TLS record splits
        tap.feed(stream[i:i + 7])
    assert [g[0] for g in got] == ["POST", "PUT"]
    assert got[1][2] == clip
    folder, fname = enr.event_name(got[1][1])
    assert folder.endswith("_1767225600") and fname == "clip.mp4"
    assert enr.event_name(b"/device/alarm/upload_alarm") is None
