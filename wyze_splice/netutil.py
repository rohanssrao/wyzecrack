"""Small Linux networking helpers: iptables/ip wrappers, route lookups,
and conntrack over netlink (pyroute2)."""
import errno
import socket
import subprocess


def ipt(*a):
    return subprocess.run(["iptables", *a], capture_output=True, text=True)


def ip_cmd(*a):
    return subprocess.run(["ip", *a], capture_output=True, text=True)


def ipt_restore(blob):
    return subprocess.run(["iptables-restore", "--noflush"], input=blob,
                          capture_output=True, text=True)


def route_get(dst):
    return subprocess.run(["ip", "-4", "route", "get", dst],
                          capture_output=True, text=True).stdout


def local_ip_for(dst):
    return route_get(dst).split("src ")[1].split()[0]


def iface_for(dst):
    out = route_get(dst)
    if "dev " not in out:
        # e.g. the link is down across a suspend/resume; callers retry
        raise OSError(f"no route to {dst}")
    return out.split("dev ")[1].split()[0]


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
