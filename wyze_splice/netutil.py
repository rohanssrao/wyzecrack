"""Small Linux networking helpers: iptables/ip wrappers, route lookups,
and conntrack over netlink (pyroute2)."""
import errno
import socket

from .changes import run


def ipt(*a):
    return run(["iptables", *a])


def ip_cmd(*a):
    return run(["ip", *a])


def ipt_restore(blob):
    return run(["iptables-restore", "--noflush"], input=blob)


def route_get(dst):
    return run(["ip", "-4", "route", "get", dst]).stdout


def local_ip_for(dst):
    """Our source address toward dst (for an on-link camera: our address
    on the camera's LAN)."""
    out = route_get(dst)
    if "src " not in out:
        raise OSError(f"no route to {dst}")
    return out.split("src ")[1].split()[0]


def iface_for(dst):
    out = route_get(dst)
    if "dev " not in out:
        # e.g. the link is down across a suspend/resume; callers retry
        raise OSError(f"no route to {dst}")
    return out.split("dev ")[1].split()[0]


def on_link(dst):
    """True if dst is reached directly, not through a gateway."""
    out = route_get(dst)
    return bool(out) and " via " not in out.split("\n")[0]


def default_gateway(iface):
    """The default route's next hop on iface, or None."""
    out = run(["ip", "-4", "route", "show", "default", "dev", iface]).stdout
    for line in out.splitlines():
        parts = line.split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    return None


def is_local_address(ip):
    out = run(["ip", "-4", "route", "get", ip]).stdout
    return out.startswith("local ")


_CT = [None]


def ensure_conntrack():
    """Open the netlink conntrack socket at startup: the latch-time NAT
    handoff needs it, and failing then would be too late."""
    from pyroute2 import Conntrack
    try:
        ct = Conntrack()
        ct.count()
    except Exception as e:  # noqa: BLE001
        raise SystemExit(f"conntrack netlink unavailable ({e}); is the "
                         f"nf_conntrack_netlink module loaded?")
    _CT[0] = ct
    return ct


def conntrack_delete(src, sport, dst, dport, proto=socket.IPPROTO_UDP):
    """Delete the conntrack entry whose original direction is
    src:sport -> dst:dport. Best-effort: a missing entry is normal, and a
    failure here must never skip the splice's rule cleanup."""
    from pyroute2.netlink.exceptions import NetlinkError
    from pyroute2.netlink.nfnetlink.nfctsocket import NFCTAttrTuple
    ct = _CT[0]
    if ct is None:
        return False
    try:
        ct.entry("del", tuple_orig=NFCTAttrTuple(
            saddr=src, daddr=dst, proto=proto, sport=int(sport),
            dport=int(dport)))
        return True
    except NetlinkError as e:
        if e.code != errno.ENOENT:
            print(f"[!] conntrack delete failed: {e}")
        return False
    except Exception as e:  # noqa: BLE001
        print(f"[!] conntrack delete failed: {e}")
        return False
