"""Find Wyze cameras on the local network by MAC vendor prefix."""
import ipaddress
import socket
import threading
import time

from . import rawnet
from .changes import run

# IEEE assignments to Wyze Labs Inc: five MA-L (24-bit) OUIs and one MA-M
# (28-bit) block
WYZE_OUI24 = {"2c:aa:8e", "7c:78:b2", "80:48:2c", "d0:3f:27", "f0:c8:8b"}
WYZE_OUI28 = {"a4:da:22:2"}
MAX_SWEEP = 1024


def is_wyze(mac):
    mac = mac.lower()
    return mac[:8] in WYZE_OUI24 or mac[:10] in WYZE_OUI28


def iface_network(iface):
    """(our address, network) of iface's first IPv4 address, or None."""
    out = run(["ip", "-4", "-o", "addr", "show", "dev", iface]).stdout
    for line in out.splitlines():
        parts = line.split()
        if "inet" in parts:
            ifc = ipaddress.ip_interface(parts[parts.index("inet") + 1])
            return str(ifc.ip), ifc.network
    return None


def neighbors(iface):
    """{ip: mac} from the kernel's neighbor table."""
    found = {}
    out = run(["ip", "-4", "neigh", "show", "dev", iface]).stdout
    for line in out.splitlines():
        parts = line.split()
        if "lladdr" in parts:
            found[parts[0]] = parts[parts.index("lladdr") + 1].lower()
    return found


def sweep(iface, seconds=3.0, rounds=3, extra=()):
    """ARP every address on iface's subnet (up to MAX_SWEEP of them,
    nearest first) and return {ip: mac} of everything that answered or
    was already known."""
    me = iface_network(iface)
    if not me:
        return {}
    my_ip, net = me
    hosts = [str(h) for h in net.hosts() if str(h) != my_ip]
    if len(hosts) > MAX_SWEEP:
        mine = int(ipaddress.ip_address(my_ip))
        hosts.sort(key=lambda h: abs(int(ipaddress.ip_address(h)) - mine))
        hosts = hosts[:MAX_SWEEP]
    found = neighbors(iface)
    stop = threading.Event()

    def on_arp(p):
        if p.op == 2 and p.tpa == my_ip:
            found[p.spa] = p.sha.hex(":")
    listener = threading.Thread(
        target=rawnet.sniff, daemon=True,
        args=(iface, rawnet.arp_filter(), rawnet.parse_arp, on_arp, stop.is_set))
    listener.start()
    time.sleep(0.2)
    src_mac = rawnet.mac_bytes(rawnet.iface_mac(iface))
    # Wi-Fi cameras in power save can sleep through one request: ask every
    # address a few times, known ones (extra) first
    order = list(dict.fromkeys([*extra, *hosts]))
    with rawnet.open_raw(iface) as s:
        for _ in range(rounds):
            for h in order:
                if h in found and h not in extra:
                    continue
                try:
                    s.send(rawnet.arp_request(src_mac, my_ip, h))
                except OSError:
                    break
                time.sleep(0.002)
            time.sleep(0.8)
    # and let the kernel resolve everyone too: a datagram to each address
    # makes it ARP with its own retries, and answers land in the neighbor
    # table (some Wi-Fi cameras only answer those)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
        u.setblocking(False)
        for h in order:
            try:
                u.sendto(b"", (h, 9))          # discard port
            except OSError:
                pass
    time.sleep(seconds)
    found.update(neighbors(iface))
    stop.set()
    listener.join(1)
    return found


def find_cameras(iface, known=()):
    """[(ip, mac)] of Wyze devices on iface's LAN, sorted by address.
    known: addresses to ask first (cameras seen before)."""
    found = sweep(iface, extra=[ip for ip in known if ip])
    # a camera can answer late or only to the kernel; take the neighbor
    # table's word too
    found.update(neighbors(iface))
    return sorted(((ip, mac) for ip, mac in found.items() if is_wyze(mac)),
                  key=lambda x: socket.inet_aton(x[0]))


# DHCP hostnames are "<product model>-<MAC>"; the router's DNS answers
# reverse lookups with them
MODELS = {
    "WYZE_CAKP2JFUS": "Wyze Cam v3",
    "HL_CAM3P": "Wyze Cam v3 Pro",
    "HL_CAM4": "Wyze Cam v4",
    "WYZEC1-JZ": "Wyze Cam v2",
    "WYZEC1": "Wyze Cam v1",
    "WYZECP1_JEF": "Wyze Cam Pan",
    "HL_PAN2": "Wyze Cam Pan v2",
    "HL_PAN3": "Wyze Cam Pan v3",
    "HL_CFL2": "Wyze Cam Floodlight v2",
    "WVOD1": "Wyze Cam Outdoor",
    "HL_WCO2": "Wyze Cam Outdoor v2",
    "WYZEDB3": "Wyze Video Doorbell",
}
# models wyze-splice has been tested against
TESTED = {"WYZE_CAKP2JFUS"}


def reverse_name(ip, server, timeout=1.5):
    """PTR lookup of ip at a DNS server (the router), or None."""
    import random
    import struct
    name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    qid = random.randint(0, 0xFFFF)
    q = (struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
         + b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
         + b"\0" + struct.pack("!HH", 12, 1))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (server, 53))
        r = s.recv(512)
    except OSError:
        return None
    finally:
        s.close()
    if len(r) < 12 or struct.unpack("!H", r[:2])[0] != qid:
        return None
    if not struct.unpack("!H", r[6:8])[0]:
        return None
    i = len(q) + 12          # answer: name pointer, type, class, ttl, rdlength
    labels = []
    while i < len(r) and r[i] and not r[i] & 0xC0:
        labels.append(r[i + 1:i + 1 + r[i]].decode("ascii", "replace"))
        i += 1 + r[i]
    return ".".join(labels) or None


def describe(ip, mac, gateway):
    """{"model", "model_id", "hostname", "tested"} for a Wyze device."""
    host = reverse_name(ip, gateway) if gateway else None
    model_id = None
    if host:
        base = host.split(".")[0]
        tail = mac.replace(":", "").upper()
        if base.upper().endswith("-" + tail):
            base = base[: -len(tail) - 1]
        model_id = base
    return {"hostname": host, "model_id": model_id,
            "model": MODELS.get(model_id or "", model_id or "Wyze device"),
            "tested": model_id in TESTED}
