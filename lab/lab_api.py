"""Fake Wyze cloud for the harvest/event scenario.

  server: TLS on 203.0.113.3:443 with a self-signed cert; answers every
          request with a small JSON body and records each request's SNI
          to $OUT/api-sni.txt
  client: the camera's calls, trusting the eMudhra intermediate the way
          the real camera's stale store does: POSTs {"mac", "enr"} to
          api.wyzecam.com, then PUTs a motion clip to
          cpl-t-sightsafe.wyzecam.com (saved to $OUT/sent-clip.mp4)
"""
import datetime as dt
import hashlib
import json
import os
import socket
import ssl
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from wyze_splice.cloud import emudhra_chain  # noqa: E402

ADDR = ("203.0.113.3", 443)
ENR = "gekMdn0XjZoWF/mD"
OUT = os.environ.get("OUT", "/tmp/wslab-out")
CLIP_PATH = ("/D03F27A1B2C3/2026-01-01/D03F27A1B2C3011767225700_1767225700381_1_2_0/"
             "00112233445566778899aabbccddeeff_1.mp4?Policy=x&Signature=y")


def server(seconds):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.wyzecam.com")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - dt.timedelta(hours=1))
            .not_valid_after(now + dt.timedelta(days=1)).sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp()
    open(f"{d}/c.pem", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(f"{d}/k.pem", "wb").write(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f"{d}/c.pem", f"{d}/k.pem")

    def note_sni(_sock, name, _ctx):
        with open(f"{OUT}/api-sni.txt", "a") as f:
            f.write(f"{name}\n")
    ctx.sni_callback = note_sni
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(ADDR)
    s.listen(4)
    s.settimeout(seconds)
    try:
        while True:
            c, _ = s.accept()
            with ctx.wrap_socket(c, server_side=True) as t:
                t.settimeout(5)
                buf = t.recv(65536)
                head, _, rest = buf.partition(b"\r\n\r\n")
                n = int(dict(l.split(b": ", 1) for l in head.split(b"\r\n")[1:]
                             if b": " in l).get(b"Content-Length", b"0"))
                while len(rest) < n:
                    rest += t.recv(65536)
                body = b'{"code":"1","msg":"SUCCESS"}'
                t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s"
                          % (len(body), body))
    except (socket.timeout, OSError):
        pass


def client():
    from cryptography.hazmat.primitives import serialization
    _k, icert, _x = emudhra_chain()
    ctx = ssl.create_default_context(
        cadata=icert.public_bytes(serialization.Encoding.PEM).decode())
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    body = json.dumps({"mac": "D03F27A1B2C3", "enr": ENR}).encode()
    post = (b"POST /device/system/set_device_info HTTP/1.1\r\n"
            b"Host: api.wyzecam.com\r\nContent-Type: application/json\r\n"
            b"Content-Length: %d\r\n\r\n%s" % (len(body), body))
    clip = b"\x00\x00\x00\x18ftypmp42" + os.urandom(300_000)
    open(f"{OUT}/sent-clip.mp4", "wb").write(clip)
    put = (b"PUT %s HTTP/1.1\r\nHost: cpl-t-sightsafe.wyzecam.com\r\n"
           b"Content-Type:application/octet-stream\r\nContent-Length: %d\r\n\r\n"
           % (CLIP_PATH.encode(), len(clip))) + clip
    replies = []
    try:
        for host, req in (("api.wyzecam.com", post),
                          ("cpl-t-sightsafe.wyzecam.com", put)):
            with ctx.wrap_socket(socket.create_connection(ADDR, timeout=10),
                                 server_hostname=host) as t:
                t.sendall(req)
                replies.append(t.recv(4096).decode()[-30:])
        print(json.dumps({"ok": True, "replies": replies,
                          "clip_sha": hashlib.sha256(clip).hexdigest()}))
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": repr(e)}))


if __name__ == "__main__":
    server(float(sys.argv[2])) if sys.argv[1] == "server" else client()
