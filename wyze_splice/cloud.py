"""Reading the camera's own HTTPS: its ENR and its motion-event uploads.

The camera's TLS client still trusts the eMudhra "EM OV TLS CA - G3C"
intermediate, whose private key is public (the October 2026 eMudhra
incident: a P-384 key with d=4). Once we route the camera, its tcp/443 is
redirected to a local TLS relay that presents a leaf for the requested
name signed under that intermediate and forwards everything to the real
server, so the camera's cloud calls keep working. Two things are read off
the camera's requests:

- the ENR, the per-camera secret the DTLS PSK is derived from, in the JSON
  body of its POSTs to api.wyzecam.com (at boot, on motion alarms, and
  every few hours);
- motion events: for each alarm the camera PUTs a snapshot (jpg) and a
  12 s clip (mp4, H.264 + A-law audio) to cpl-t-sightsafe.wyzecam.com via
  pre-signed URLs, with no encryption beyond TLS.
"""
import datetime as dt
import ipaddress
import json
import os
import re
import select
import shutil
import socket
import ssl
import struct
import tempfile
import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .netutil import ipt

# Compromised "EM OV TLS CA - G3C" intermediate (key first) and its
# cross-certificates via "emSign Root TLS CA - G3" and Comodo "AAA
# Certificate Services"; the same material mitmproxy ships for --emudhra.
# Public knowledge -- only use it against devices you are authorized to test.
EMUDHRA_CHAIN_PEM = b"""

-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAShZANiAAQTglHNUqyS
mMHIqtl3Mh3rl+cJvQtMoKylXcitUdz8nRWJoVl+OlEg4e/WMcY+GDXKyuKYaaYu
FjHoooGBq1ZhbcRdkYq8CfOrDmPPeSqk3O1zh743u6VpVJ8cArJw7Wc=
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDaDCCAu6gAwIBAgIPKWkmwiejoVJjkrGUgqUEMAoGCCqGSM49BAMDMFYxCzAJ
BgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVk
MSAwHgYDVQQDDBdlbVNpZ24gUm9vdCBUTFMgQ0EgLSBHMzAeFw0yNTA0MzAxNTM3
NDFaFw00MDA0MjgxODMwMDBaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVk
aHJhIEluYzEbMBkGA1UEAwwSRU0gT1YgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZ
fjpRIOHv1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+
N7ulaVSfHAKycO1no4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L
WUIgkFQwHQYDVR0OBBYEFDTq6gzryQra+dDF4u2beMmHnhtsMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCow
KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB
BAGDjiEBAm4wCAYGZ4EMAQICMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AtYy5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw
b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNT1ZUTFNDQUczQy5wN2MwNwYDVR0f
BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j
cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E
AwMDaAAwZQIxAMSZt2xsPeumRdeSMSQ3CbzIZeQ/q7GDCWfeE1Pq+mhgA6gRM44c
NVF3xJ+wsxJk+wIwFJbaDMokD8Ei6eNOiA8yUMYvfzQyngmrhZQMdPCK1SewrR79
4rSb9vGqxZzelQth
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDdDCCAvmgAwIBAgIQAJYaPvsTWVdu0EAFtGhKWzAKBggqhkjOPQQDAzBrMQsw
CQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhy
YSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290
IENBIC0gRzMwHhcNMjQwNzExMTU0MzM2WhcNMzkwNzA5MTgzMDAwWjBWMQswCQYD
VQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEg
MB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwdjAQBgcqhkjOPQIBBgUr
gQQAIgNiAARfD9w/q1cWxL6D9bMGH6CQ4u+gAV6GN9s+PwQx9Bl4hC+0iU8QOk8m
WO/RwXQy10DCSxT8vSIJClHKp+Ao4qJKdYeV0SwZ7LMQziyLfxIUOY6Grja/sQFw
LKYf8EdDXAyjggF1MIIBcTAfBgNVHSMEGDAWgBR8XQKEE9TMipuBzhccLikenEhj
QjAdBgNVHQ4EFgQU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIB
FhxodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tMHgGCCsGAQUFBwEBBGwwajAi
BggrBgEFBQcwAYYWaHR0cDovL29jc3AuZW1zaWduLmNvbTBEBggrBgEFBQcwAoY4
aHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbS9jZXJ0cy9lbVNpZ25FQ0NSb290
Q0FHMy5jcnQwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5lbXNpZ24uY29t
P1Jvb3RDQUczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIB
ATAKBggqhkjOPQQDAwNpADBmAjEAt9CIpRGp46QHQYDUBnLKw+vvK0/h9vmilEAg
TroUl/anH4x2rXHqiCtBTBfgKDegAjEA8WpG1LTZdAIL0FSYqxXeREaeTSxEofM0
1jJH3jGvCXC79LU9UPJ2o3TU+UIj2gMV
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDzzCCAregAwIBAgIRAI1aSBGTnvRH13ERzdmEmukwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVkaHJhIElu
YzEbMBkGA1UEAwwSRU0gT1YgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0CAQYFK4EE
ACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZfjpRIOHv
1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+N7ulaVSf
HAKycO1no4IBNTCCATEwHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQw
HQYDVR0OBBYEFDTq6gzryQra+dDF4u2beMmHnhtsMA4GA1UdDwEB/wQEAwIBBjAS
BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAxBgNVHSAEKjAoMAgGBmeBDAECAjANBgsrBgEEAYOOIQEAATANBgsrBgEEAYOO
IQECbjBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9B
QUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYIKwYB
BQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQsFAAOC
AQEAHlbhZpjhkPEAQVhPHRtBDaHqiisVD20pQ1TUeSx3l62Qe7NQ0b7vWQy7DN0i
KOu7BGpP5EnIjvXbz9FhpfPJ4FhKEt3tQ51rqXz2oD8vRaryvExWPobDUz3j7HN6
OzBsVMIe3PD7AAkpky0x8zMSi/ep5R9OMzybmNptbtppyuB5ytgq+h7lQdRIP+CQ
TaJX3qTgfMqzntYre5GljmEB5hU2/rSn8zoSU2APkJidlZFpghtgbD4I2VRHZvCw
FFr/SrFM9pwrgbJNZ1MtyTSVgI5NlNb0aMfLR+/r6jJt3ROeY2yh2QQ2dx+Yqgdb
uL5ChFWOQU+ErSDnUq7yr+pjBQ==
-----END CERTIFICATE-----
"""


SO_ORIGINAL_DST = 80
INTERCEPT_PORT = 18443
DEBUG = bool(os.environ.get("WYZE_SPLICE_DEBUG"))
# PUT /<MAC>/<date>/<alarm id>_<alarm ms>_<n>_<file type>_<n>/<uuid>_1.<ext>
EVENT_PATH_RE = re.compile(rb"^/[0-9A-F]{12}/[0-9-]+/([0-9A-F]+)_(\d{13})_\d+_(\d)_\d+/"
                           rb"[0-9a-f]+_\d+\.(jpg|mp4)")
MAX_BODY = 64 << 20
ENR_RE = re.compile(rb'"enr"\s*:\s*"((?:[^"\\]|\\.)+)"')
MAC_RE = re.compile(rb'"mac"\s*:\s*"([0-9A-Fa-f]{12})"')


def emudhra_chain():
    """(issuer key, issuer cert, [cross-certs])"""
    key = serialization.load_pem_private_key(EMUDHRA_CHAIN_PEM, password=None)
    certs = x509.load_pem_x509_certificates(EMUDHRA_CHAIN_PEM)
    return key, certs[0], certs[1:]


def mint_leaf(host, workdir):
    """Write a leaf for `host` under the eMudhra intermediate; returns
    (certfile with chain, keyfile)."""
    ikey, icert, cross = emudhra_chain()
    # RSA-2048 is what the camera was seen accepting
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    try:
        san = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        san = x509.DNSName(host)
    cert = (x509.CertificateBuilder()
            # a CN is limited to 64 characters; the SAN is what clients check
            .subject_name(x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, host)]
                if len(host) <= 64 else []))
            .issuer_name(icert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(hours=1))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            # strict validators reject leaves under this CA without SKI/AKI
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ikey.public_key()), critical=False)
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .sign(ikey, hashes.SHA384()))
    safe = re.sub(r"[^A-Za-z0-9.-]", "_", host)[:80]
    certfile, keyfile = Path(workdir) / f"{safe}.crt", Path(workdir) / f"{safe}.key"
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    certfile.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM)
                                  for c in (cert, icert, *cross)))
    return str(certfile), str(keyfile)


def find_enr(buf):
    """(enr, mac or None) from an HTTP request buffer, or None."""
    m = ENR_RE.search(buf)
    if not m:
        return None
    try:
        enr = json.loads(b'"' + m.group(1) + b'"')
    except ValueError:
        return None
    mac = MAC_RE.search(buf)
    return enr, mac.group(1).decode().upper() if mac else None


# Only Wyze's own names are terminated; everything else the camera sends
# to tcp/443 (firmware and model downloads from S3, anything pinned,
# non-TLS) is relayed as raw TCP, untouched.
INTERCEPT_SUFFIX = ".wyzecam.com"


def intercepts(sni):
    return bool(sni) and sni.lower().endswith(INTERCEPT_SUFFIX)


def client_hello_sni(data):
    """SNI from the start of a TLS stream: a str, "" if the ClientHello
    has none, or None if the bytes are not (yet) a whole ClientHello."""
    if len(data) < 5 or data[0] != 0x16:
        return None
    rec_len = struct.unpack("!H", data[3:5])[0]
    body = data[5:5 + rec_len]
    if len(body) < rec_len or len(body) < 42 or body[0] != 1:
        return None
    try:
        i = 4 + 2 + 32                         # hs header, version, random
        i += 1 + body[i]                       # session id
        i += 2 + struct.unpack("!H", body[i:i + 2])[0]   # cipher suites
        i += 1 + body[i]                       # compression
        end = i + 2 + struct.unpack("!H", body[i:i + 2])[0]
        i += 2
        while i + 4 <= end:
            etype, elen = struct.unpack("!HH", body[i:i + 4])
            if etype == 0:                     # server_name
                n = struct.unpack("!H", body[i + 7:i + 9])[0]
                return body[i + 9:i + 9 + n].decode("ascii", "replace")
            i += 4 + elen
    except (IndexError, struct.error):
        return None
    return ""


def original_dst(sock):
    raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port = struct.unpack(">H", raw[2:4])[0]
    return socket.inet_ntoa(raw[4:8]), port


class RequestTap:
    """Incremental parser for one connection's client->server bytes: calls
    on_request(method, path, headers, body) per complete HTTP/1.1 request
    with a Content-Length body. Anything else (chunked bodies, MQTT, ...)
    makes it give up on the connection; the relay is unaffected."""

    def __init__(self, on_request):
        self.on_request = on_request
        self.buf = bytearray()
        self.dead = False

    def feed(self, data):
        if self.dead:
            return
        self.buf += data
        while True:
            end = self.buf.find(b"\r\n\r\n")
            if end < 0:
                if len(self.buf) > 65536:
                    self.dead = True
                return
            head = bytes(self.buf[:end]).split(b"\r\n")
            parts = head[0].split(b" ")
            if len(parts) != 3 or not parts[2].startswith(b"HTTP/"):
                self.dead = True
                return
            headers = {}
            for line in head[1:]:
                k, _, v = line.partition(b":")
                headers[k.strip().lower()] = v.strip()
            if b"chunked" in headers.get(b"transfer-encoding", b""):
                self.dead = True
                return
            try:
                n = int(headers.get(b"content-length", b"0"))
            except ValueError:
                self.dead = True
                return
            if n > MAX_BODY:
                self.dead = True
                return
            if len(self.buf) < end + 4 + n:
                return
            body = bytes(self.buf[end + 4:end + 4 + n])
            del self.buf[:end + 4 + n]
            self.on_request(parts[0].decode("latin-1"), bytes(parts[1]),
                            headers, body)


def event_name(path):
    """(event folder name, file name) for a motion-event upload path, or
    None. Folder: local alarm time + alarm id; files snapshot.jpg/clip.mp4."""
    m = EVENT_PATH_RE.match(path)
    if not m:
        return None
    alarm_id, ms, _ftype, ext = (x.decode() for x in m.groups())
    when = time.strftime("%Y%m%d-%H%M%S", time.localtime(int(ms) / 1000))
    return f"{when}_{alarm_id[-10:]}", "clip.mp4" if ext == "mp4" else "snapshot.jpg"


class CloudTap:
    """Transparent interceptor for the camera's tcp/443.

    Connections whose SNI is a *.wyzecam.com name are terminated with an
    eMudhra-chained leaf and relayed to the real server under the same
    SNI; all others are relayed as raw TCP. `enr_found` is set when an
    ENR is seen; with events_dir set, motion-event uploads are saved
    there as <time>_<id>/clip.mp4 and snapshot.jpg.

    listen() binds (do it before going on-path), start() installs the
    redirect, stop() removes it."""

    def __init__(self, changes, cam_ip, port=INTERCEPT_PORT, events_dir=None,
                 on_event=None):
        self.changes = changes
        self.cam_ip, self.port = cam_ip, port
        self.events_dir = Path(events_dir) if events_dir else None
        self.on_event = on_event
        self.enr_found = threading.Event()
        self.enr = self.mac = None
        self.events = []
        self.stats = {"connections": 0, "intercepted": 0, "passed": 0,
                      "tls_failed": 0}
        self.hosts = {}
        self._work = tempfile.mkdtemp(prefix="wyze-splice-certs-")
        self._ctx_lock = threading.Lock()
        self._tokens = []
        self._srv = None

    def _ctx_for(self, host):
        with self._ctx_lock:
            ctx = self.hosts.get(host)
            if ctx is None:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(*mint_leaf(host, self._work))
                self.hosts[host] = ctx
            return ctx

    def listen(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", self.port))
        except OSError as e:
            srv.close()
            raise SystemExit(f"TCP port {self.port} is busy ({e.strerror})")
        srv.listen(32)
        self._srv = srv
        threading.Thread(target=self._accept, daemon=True).start()

    def start(self):
        if self._srv is None:
            self.listen()
        for table, chain, spec in (
                ("nat", "PREROUTING", ["-s", self.cam_ip, "-p", "tcp",
                                       "--dport", "443", "-j", "REDIRECT",
                                       "--to-ports", str(self.port)]),
                ("filter", "INPUT", ["-s", self.cam_ip, "-p", "tcp",
                                     "--dport", str(self.port), "-j",
                                     "ACCEPT"])):
            self._tokens.append(self.changes.add(
                "ipt", args=["-t", table, "-D", chain, *spec]))
            ipt("-t", table, "-I", chain, "1", *spec)

    def stop(self):
        """Remove the redirect (new connections go straight to the cloud)
        and stop listening; relays in flight finish on their own."""
        self.changes.undo(self._tokens)
        self._tokens = []
        if self._srv:
            try:
                self._srv.shutdown(socket.SHUT_RDWR)   # wakes accept()
            except OSError:
                pass
            self._srv.close()
            self._srv = None
        shutil.rmtree(self._work, ignore_errors=True)

    def _accept(self):
        while True:
            srv = self._srv
            if srv is None:
                return
            try:
                c, peer = srv.accept()
            except OSError:
                return
            if peer[0] != self.cam_ip:
                c.close()          # only the camera's redirected traffic
                continue
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _peek_hello(self, c):
        """Wait (briefly) for the client's first bytes; returns the SNI
        decision of client_hello_sni, or None for non-TLS/no data."""
        deadline = time.monotonic() + 10
        data = b""
        while time.monotonic() < deadline:
            c.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                data = c.recv(16384, socket.MSG_PEEK)
            except socket.timeout:
                return None
            if not data:
                return None
            sni = client_hello_sni(data)
            if sni is not None or data[0] != 0x16 or len(data) >= 16384:
                return sni
            time.sleep(0.05)
        return None

    def _handle(self, c):
        up = None
        self.stats["connections"] += 1
        try:
            dst = original_dst(c)
            if dst[1] == self.port or is_local(dst[0]):
                return             # never relay into ourselves
            sni = self._peek_hello(c)
            if DEBUG:
                print(f"[d] camera -> {dst[0]}:{dst[1]} sni={sni!r} "
                      f"{'intercept' if intercepts(sni) else 'pass'}")
            if not intercepts(sni):
                self.stats["passed"] += 1
                up = socket.create_connection(dst, timeout=15)
                _pump(c, up, None)
                return
            c.settimeout(15)
            try:
                tc = self._ctx_for(sni).wrap_socket(c, server_side=True)
            except (ssl.SSLError, OSError):
                # the camera refused our certificate
                self.stats["tls_failed"] += 1
                return
            self.stats["intercepted"] += 1
            cctx = ssl.create_default_context()
            cctx.check_hostname = False
            cctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection(dst, timeout=15)
            up = cctx.wrap_socket(raw, server_hostname=sni)
            _pump(tc, up, RequestTap(self._on_request))
        except (OSError, ssl.SSLError, ValueError) as e:
            if DEBUG:
                import traceback
                traceback.print_exc()
            self.stats["errors"] = self.stats.get("errors", 0) + 1
        finally:
            for s in (c, up):
                try:
                    s and s.close()
                except OSError:
                    pass

    def _on_request(self, method, path, headers, body):
        if not self.enr_found.is_set():
            hit = find_enr(body)
            if hit:
                self.enr, self.mac = hit
                self.enr_found.set()
        if method == "PUT" and self.events_dir is not None and body:
            name = event_name(path)
            if name:
                d = self.events_dir / name[0]
                d.mkdir(parents=True, exist_ok=True)
                (d / name[1]).write_bytes(body)
                self.events.append(d / name[1])
                if self.on_event:
                    self.on_event(d / name[1])


# per-operation timeout and idle cutoff for relayed connections: generous,
# so slow uploads and quiet keep-alive connections are never cut short
IO_TIMEOUT = 60
IDLE_TIMEOUT = 900


def _pump(a, b, tap):
    """Relay a<->b until either side closes (a is the camera's side),
    feeding a->b bytes to the tap. Reads never block (a readable TLS
    socket may hold only a partial record, or a post-handshake message
    such as a TLS 1.3 session ticket that carries no data); writes block
    for up to IO_TIMEOUT. Tap errors disable the tap, never the
    connection."""
    tls = hasattr(a, "pending")
    while True:
        ready = [s for s in (a, b) if tls and s.pending()]
        if not ready:
            ready, _, _ = select.select([a, b], [], [], IDLE_TIMEOUT)
            if not ready:
                return
        for s in ready:
            s.settimeout(0)
            try:
                data = s.recv(65536)
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError,
                    BlockingIOError, socket.timeout):
                continue
            if not data:
                return
            dst = b if s is a else a
            dst.settimeout(IO_TIMEOUT)
            dst.sendall(data)
            if s is a and tap and not tap.dead:
                try:
                    tap.feed(data)
                except Exception as e:  # noqa: BLE001
                    tap.dead = True
                    print(f"[!] stopped reading a camera connection ({e!r})")


def is_local(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((ip, 0))
        s.close()
        return True
    except OSError:
        return False
