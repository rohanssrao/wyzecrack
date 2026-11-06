"""Small Linux networking helpers: iptables, route lookups."""
import ipaddress

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
    return route_get(ip).startswith("local ")


def internet_iface():
    """The interface of this host's internet route."""
    try:
        return iface_for("8.8.8.8")
    except OSError:
        raise SystemExit("this host has no internet route; is its network up?")


def camera_iface(target, on_path=False):
    """The interface the camera at `target` is on, after checking that it
    is another host's IPv4 address on this host's LAN (unless this host
    already carries its traffic: on_path) and on the interface of this
    host's internet route. Raises SystemExit with the reason."""
    try:
        ipaddress.IPv4Address(target)
    except ValueError:
        raise SystemExit(f"--target must be an IPv4 address, not {target!r}")
    if is_local_address(target):
        raise SystemExit(f"{target} is this host's own address")
    if not on_path and not on_link(target):
        raise SystemExit(f"{target} is not on a LAN this host is attached to")
    iface, inet = iface_for(target), internet_iface()
    if iface != inet:
        raise SystemExit(f"the camera is on {iface} but this host's internet "
                         f"route is on {inet} (a VPN?); the camera's traffic "
                         f"must leave through the interface it arrives on")
    return iface
