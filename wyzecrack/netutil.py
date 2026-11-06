"""Small Linux networking helpers: iptables, route lookups."""
from .changes import run


def ipt(*a):
    # -w: wait for the xtables lock instead of failing when Docker,
    # firewalld or fail2ban hold it
    return run(["iptables", "-w", *a])


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
