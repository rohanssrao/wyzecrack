"""Cloud interception: ENR and event parsing, and the eMudhra-signed leaf."""
import json
import socket
import ssl
import tempfile
import threading

import pytest
from cryptography.hazmat.primitives import serialization

from wyzecrack import cloud as enr


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


def _client_hello(sni):
    import ssl
    ctx = ssl.create_default_context()
    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inb, outb, server_hostname=sni)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outb.read()


def test_client_hello_sni():
    hello = _client_hello("cpl-t-sightsafe.wyzecam.com")
    assert enr.client_hello_sni(hello) == "cpl-t-sightsafe.wyzecam.com"
    assert enr.client_hello_sni(hello[:40]) is None            # partial
    assert enr.client_hello_sni(b"GET / HTTP/1.1\r\n") is None  # not TLS
    assert enr.intercepts("api.wyzecam.com")
    assert not enr.intercepts("sinker-t-usw2.s3.us-west-2.amazonaws.com")
    assert enr.intercepts("c-t-usw2.s3.us-west-2.amazonaws.com")    # v2 alarms
    assert not enr.intercepts("wyze-iot.s3.us-west-2.amazonaws.com")
    assert not enr.intercepts("")


def test_long_sni_still_gets_a_leaf():
    name = "a" * 70 + ".wyzecam.com"
    certfile, _ = enr.mint_leaf(name, tempfile.mkdtemp())
    assert open(certfile).read().startswith("-----BEGIN CERTIFICATE-----")


def test_bad_enr_escape_is_ignored():
    assert enr.find_enr(b'{"enr":"ab\\xcd"}') is None


def test_device_info_reads_both_request_shapes():
    alarm = (b'{"alarm_ts":1,"mac":"D03F27A1B2C3","enr":"gekMdn0XjZoWF\\/mD",'
             b'"product_model":"WYZE_CAKP2JFUS","hardware_ver":"0.0.0.0",'
             b'"firmware_ver":"4.36.17.21"}')
    metrics = (b'{"request_id":"x","device_id":"D03F27A1B2C3",'
               b'"device_enr":"gekMdn0XjZoWF/mD","device_model":"WYZE_CAKP2JFUS",'
               b'"firmware_version":"4.36.17.21","hardware_version":"0.0.0.0"}')
    want = {"enr": "gekMdn0XjZoWF/mD", "mac": "D03F27A1B2C3",
            "model": "WYZE_CAKP2JFUS", "fw": "4.36.17.21", "hw": "0.0.0.0"}
    assert enr.device_info(alarm) == want
    assert enr.device_info(metrics) == want


class _Reply:
    def __init__(self, body):
        self.body = body

    def read(self, *a):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_fetch_uid_asks_as_the_camera(monkeypatch):
    import json
    import urllib.request
    sent = {}

    def fake(req, timeout, context):
        sent["url"], sent["body"] = req.full_url, json.loads(req.data)
        return _Reply(b'{"code":"1","msg":"SUCCESS","data":{"p2p_id":'
                      b'"ABCDEFGHJKLMNPQR111A","p2p_id_type":3}}')

    monkeypatch.setattr(urllib.request, "urlopen", fake)
    uid = enr.fetch_uid("d0:3f:27:a1:b2:c3", "gekMdn0XjZoWF/mD",
                        "WYZE_CAKP2JFUS", "4.36.17.21")
    assert uid == "ABCDEFGHJKLMNPQR111A"
    assert sent["url"].endswith("/device/system/get_p2pid")
    b = sent["body"]
    assert (b["mac"], b["enr"], b["p2p_id_type"]) == (
        "D03F27A1B2C3", "gekMdn0XjZoWF/mD", 3)
    assert b["sv"] == enr.SV_GET_P2PID and b["sc"] == enr.SC


def test_fetch_uid_refusal_is_a_cloud_error(monkeypatch):
    import urllib.request
    import pytest
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Reply(
        b'{"code":"1000","msg":"service is error","data":null}'))
    with pytest.raises(enr.CloudError):
        enr.fetch_uid("D03F27A1B2C3", "x", "WYZE_CAKP2JFUS", "4.36.17.21")


def test_event_name_for_a_v2_upload():
    # a Wyze Cam v2 (4.9.9.3006) PUT to its S3 bucket, 2026-11-05
    path = (b"/2CAA8ED4E5F6/2026-01-01/2CAA8ED4E5F6021767225800_1767225800810_2_2_0/"
            b"fedcba9876543210fedcba9876543210_-1.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256")
    folder, fname = enr.event_name(path)
    assert fname == "clip.mp4" and folder.endswith("_1767225800")


def test_a_clip_without_snapshot_gets_a_still_and_its_length(tmp_path):
    av = pytest.importorskip("av")
    from fractions import Fraction
    mp4 = tmp_path / "src.mp4"
    with av.open(str(mp4), "w") as out:
        s = out.add_stream("libx264", rate=10)
        s.width, s.height, s.pix_fmt = 320, 240, "yuv420p"
        s.time_base = Fraction(1, 10)
        for i in range(30):
            f = av.VideoFrame(320, 240, "yuv420p")
            for plane in f.planes:
                plane.update(bytes([i * 8]) * plane.buffer_size)
            f.pts = i
            for pkt in s.encode(f):
                out.mux(pkt)
        for pkt in s.encode(None):
            out.mux(pkt)
    tap = enr.CloudTap(None, "192.168.1.23", events_dir=tmp_path / "events")
    path = (b"/2CAA8ED4E5F6/2026-01-01/2CAA8ED4E5F6021767225800_1767225800810_2_2_0/"
            b"fedcba9876543210fedcba9876543210_-1.mp4?X-Amz-Algorithm=x")
    tap._on_request("PUT", path, {}, mp4.read_bytes())
    d = next((tmp_path / "events").iterdir())
    assert (d / "clip.mp4").exists() and (d / "snapshot.jpg").stat().st_size > 0
    assert json.loads((d / "meta.json").read_text())["seconds"] == pytest.approx(3.0, abs=0.2)
