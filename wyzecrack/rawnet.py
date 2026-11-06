"""Raw Ethernet I/O on Linux without libpcap: AF_PACKET sockets with
classic BPF filters attached by SO_ATTACH_FILTER, plus the little ARP and
IPv4/UDP framing this tool needs."""
import ctypes
import socket
import struct
import time
from collections import namedtuple

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
SO_ATTACH_FILTER = 26

# classic BPF opcodes (linux/filter.h)
LD_W_ABS, LD_H_ABS, LD_B_ABS = 0x20, 0x28, 0x30
JEQ_K = 0x15
RET_K = 0x06
ACCEPT, DROP = 0x40000, 0

UdpPacket = namedtuple("UdpPacket", "src dst sport dport payload")
ArpPacket = namedtuple("ArpPacket", "op sha spa tha tpa")


def _ip(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def udp_filter(hosts, dsts=()):
    """BPF for IPv4 UDP frames whose source or destination is in `hosts`,
    or whose destination is in `dsts`."""
    # (code, jt, jf, k); jumps are relative to the next instruction
    tests = [(26, h) for h in hosts] + [(30, h) for h in (*hosts, *dsts)]
    assert len(tests) < 100, "jump offsets are 8-bit"
    prog = [(LD_H_ABS, 0, 0, 12),
            (JEQ_K, 0, 0, ETH_P_IP),        # jf patched to DROP below
            (LD_B_ABS, 0, 0, 23),
            (JEQ_K, 0, 0, socket.IPPROTO_UDP)]
    for off, addr in tests:
        prog += [(LD_W_ABS, 0, 0, off), (JEQ_K, 0, 0, _ip(addr))]
    prog += [(RET_K, 0, 0, DROP), (RET_K, 0, 0, ACCEPT)]
    drop, accept = len(prog) - 2, len(prog) - 1
    out = []
    for i, (code, jt, jf, k) in enumerate(prog):
        if code == JEQ_K:
            if i in (1, 3):                     # wrong type/proto: drop
                jt, jf = 0, drop - i - 1
            else:                               # address match: accept
                jt, jf = accept - i - 1, 0
        out.append((code, jt, jf, k))
    return out


def arp_filter():
    return [(LD_H_ABS, 0, 0, 12), (JEQ_K, 0, 1, ETH_P_ARP),
            (RET_K, 0, 0, ACCEPT), (RET_K, 0, 0, DROP)]


def attach_filter(sock, prog):
    insns = b"".join(struct.pack("HBBI", *i) for i in prog)
    buf = ctypes.create_string_buffer(insns)
    # struct sock_fprog { unsigned short len; struct sock_filter *filter; }
    fprog = struct.pack("@HP", len(prog), ctypes.addressof(buf))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)


def open_raw(iface, prog=None):
    """AF_PACKET socket on iface. With a filter it is created with
    protocol 0 (receives nothing), filtered, then bound for all
    protocols, so no unfiltered frame is ever queued."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    try:
        if prog is not None:
            attach_filter(s, prog)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
            s.bind((iface, ETH_P_ALL))
        else:
            s.bind((iface, 0))           # send-only
    except OSError:
        s.close()
        raise
    return s


def parse_udp(frame):
    """Ethernet frame -> UdpPacket, or None if it is not IPv4 UDP."""
    if len(frame) < 42 or frame[12:14] != b"\x08\x00":
        return None
    ihl = (frame[14] & 0x0F) * 4
    if ihl < 20 or frame[23] != socket.IPPROTO_UDP or len(frame) < 14 + ihl + 8:
        return None
    if struct.unpack("!H", frame[20:22])[0] & 0x3FFF:
        return None                     # a fragment: no complete UDP header
    total = struct.unpack("!H", frame[16:18])[0]
    u = 14 + ihl
    sport, dport, ulen = struct.unpack("!HHH", frame[u:u + 6])
    end = min(len(frame), 14 + total, u + ulen)
    return UdpPacket(socket.inet_ntoa(frame[26:30]), socket.inet_ntoa(frame[30:34]),
                     sport, dport, bytes(frame[u + 8:end]))


def parse_arp(frame):
    if len(frame) < 42 or frame[12:14] != b"\x08\x06":
        return None
    op = struct.unpack("!H", frame[20:22])[0]
    return ArpPacket(op, frame[22:28], socket.inet_ntoa(frame[28:32]),
                     frame[32:38], socket.inet_ntoa(frame[38:42]))


def mac_bytes(mac):
    return bytes.fromhex(mac.replace(":", ""))


def arp_reply(src_mac, dst_mac, spa, sha, tpa, tha):
    """Ethernet frame carrying an ARP reply: "spa is at sha", sent to
    dst_mac (MACs as bytes)."""
    return (dst_mac + src_mac + struct.pack("!H", ETH_P_ARP)
            + struct.pack("!HHBBH", 1, ETH_P_IP, 6, 4, 2)
            + sha + socket.inet_aton(spa) + tha + socket.inet_aton(tpa))


def arp_request(src_mac, src_ip, target_ip):
    """Broadcast "who has target_ip" from src_mac/src_ip (MACs as bytes)."""
    return (b"\xff" * 6 + src_mac + struct.pack("!H", ETH_P_ARP)
            + struct.pack("!HHBBH", 1, ETH_P_IP, 6, 4, 1)
            + src_mac + socket.inet_aton(src_ip) + b"\x00" * 6
            + socket.inet_aton(target_ip))


def iface_mac(iface):
    with open(f"/sys/class/net/{iface}/address") as f:
        return f.read().strip()


def sniff(iface, prog, parse, on_packet, stop, timeout=None):
    """Feed every parsed frame matching `prog` to on_packet until
    stop() is true or `timeout` seconds pass. Frames this host sends
    (including the forwarded copies of what it receives) are skipped.
    Raises OSError if the interface goes away (callers retry)."""
    deadline = time.monotonic() + timeout if timeout else None
    s = open_raw(iface, prog)
    s.settimeout(0.5)
    try:
        while not stop() and (deadline is None or time.monotonic() < deadline):
            try:
                frame, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            if addr[2] == PACKET_OUTGOING:
                continue
            pkt = parse(frame)
            if pkt is not None:
                on_packet(pkt)
    finally:
        s.close()
