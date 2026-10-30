"""ENR harvest: request parsing and the eMudhra-signed leaf."""
import socket
import ssl
import tempfile
import threading

from cryptography.hazmat.primitives import serialization

from wyze_splice import enr


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
