"""Small Linux networking helpers: iptables/ip wrappers, route lookups,
conntrack, and making scapy find libpcap on NixOS."""
import os
import subprocess


def ensure_libpcap():
    """Make scapy's BPF filters work where libpcap exists but is not in the
    ldconfig cache that ctypes.util.find_library consults (NixOS: libpcap
    lives in a store path uv/pip Pythons never see). Must run before scapy
    is imported: scapy caches find_library's failure at import."""
    import ctypes
    import ctypes.util
    import glob

    if ctypes.util.find_library("pcap"):
        return
    for pat in ("/run/current-system/sw/lib/libpcap.so*",
                "/usr/lib/libpcap.so*", "/usr/lib/*/libpcap.so*",
                "/usr/local/lib/libpcap.so*",
                "/nix/store/*-libpcap*/lib/libpcap.so*"):
        for path in sorted(glob.glob(pat)):
            try:
                ctypes.CDLL(path)
            except OSError:
                continue
            orig = ctypes.util.find_library
            ctypes.util.find_library = (
                lambda name, _p=path, _o=orig: _p if name == "pcap" else _o(name))
            return


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


_CONNTRACK = [None]


def find_conntrack():
    """conntrack as a command list, or None. NixOS keeps it in a store
    path that changes across generations, so search rather than hardcode."""
    import glob
    import shutil
    c = shutil.which("conntrack")
    if c:
        return [c]
    for p in ("/run/current-system/sw/bin/conntrack",):
        if os.path.exists(p):
            return [p]
    hits = sorted(glob.glob("/nix/store/*-conntrack-tools-*/bin/conntrack"))
    if hits:
        return [hits[-1]]
    if shutil.which("nix"):
        return ["nix", "shell", "nixpkgs#conntrack-tools", "--command",
                "conntrack"]
    return None


def ensure_conntrack():
    """Resolve conntrack once at startup (the latch-time NAT-entry handoff
    needs it, and a `nix shell` fallback would cost seconds inside the
    handshake window)."""
    c = find_conntrack()
    if c and c[0] != "nix":
        _CONNTRACK[0] = c
        return c
    r = subprocess.run(["nix", "build", "--no-link", "--print-out-paths",
                        "nixpkgs#conntrack-tools"], capture_output=True,
                       text=True)
    path = r.stdout.strip().splitlines()[-1] if r.returncode == 0 else ""
    if path and os.path.exists(f"{path}/bin/conntrack"):
        _CONNTRACK[0] = [f"{path}/bin/conntrack"]
        return _CONNTRACK[0]
    raise SystemExit("on-path mode needs conntrack (conntrack-tools)")


def conntrack_delete(*args):
    """Best-effort conntrack -D; never raises (a failure here must not skip
    the splice's rule cleanup)."""
    if _CONNTRACK[0] is None:
        _CONNTRACK[0] = find_conntrack() or []
    if not _CONNTRACK[0]:
        return None
    try:
        return subprocess.run([*_CONNTRACK[0], "-D", *args],
                              capture_output=True, text=True)
    except OSError as e:
        print(f"[!] conntrack failed: {e}")
        return None
