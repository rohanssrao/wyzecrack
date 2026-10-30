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


def sweep(iface, seconds=3.0):
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
    with rawnet.open_raw(iface) as s:
        for h in hosts:
            try:
                s.send(rawnet.arp_request(src_mac, my_ip, h))
            except OSError:
                break
            time.sleep(0.002)
    time.sleep(seconds)
    stop.set()
    listener.join(1)
    return found


def find_cameras(iface):
    """[(ip, mac)] of Wyze devices on iface's LAN, sorted by address."""
    return sorted(((ip, mac) for ip, mac in sweep(iface).items() if is_wyze(mac)),
                  key=lambda x: socket.inet_aton(x[0]))
