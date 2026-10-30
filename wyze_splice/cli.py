"""wyze-splice: decrypt a Wyze Cam v3 live view while the app keeps playing.

  sudo wyze-splice run                 splice the next live view, save events
  sudo wyze-splice events              only save motion-event clips
  sudo wyze-splice find                list Wyze devices on this LAN
  sudo wyze-splice check               pre-flight checks, camera untouched
  sudo wyze-splice cleanup             undo what a crashed run left behind
  wyze-splice extract <capture>/av.bin rebuild the video from a capture

run and events find the camera by themselves when the LAN has one Wyze
device, and ask which one when it has several; --target <camera ip> skips
the search.
"""
import argparse
import atexit
import ipaddress
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

STATE_DIR = Path(os.environ.get("WYZE_SPLICE_STATE", "/var/lib/wyze-splice"))


class _QuietStream:
    """stdout/stderr that survive a vanished terminal: after a hangup every
    write would raise EIO, and teardown must still run to the end."""

    def __init__(self, stream):
        self._s = stream

    def write(self, data):
        try:
            return self._s.write(data)
        except OSError:
            return len(data)

    def flush(self):
        try:
            self._s.flush()
        except OSError:
            pass

    def __getattr__(self, name):
        return getattr(self._s, name)


def _interrupt(signum, frame):
    raise KeyboardInterrupt


def _install_signals():
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _interrupt)
    # a parent shell may have started us with SIGINT ignored
    signal.signal(signal.SIGINT, signal.default_int_handler)


def _inhibit_sleep():
    """A suspended host black-holes the camera while it is the camera's
    gateway; hold a sleep inhibitor for the run."""
    exe = shutil.which("systemd-inhibit")
    if not exe:
        return
    # the lock is held by `tail --pid`, which ends with this process even
    # when it is killed outright
    p = subprocess.Popen([exe, "--what=sleep:idle:handle-lid-switch",
                          "--who=wyze-splice", "--why=camera gateway",
                          "tail", f"--pid={os.getpid()}", "-f", "/dev/null"],
                         start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    atexit.register(p.terminate)


# -- ENR cache (keyed by camera MAC) ------------------------------------
def _mac_key(mac):
    return mac.replace(":", "").upper()


def _cache():
    try:
        d = json.loads((STATE_DIR / "enr.json").read_text())
    except (OSError, ValueError):
        return {}
    # early versions keyed entries by camera IP, with the MAC inside
    return {(_mac_key(v["mac"]) if v.get("mac") else k): v
            for k, v in d.items()}


def _cached_enr(mac):
    e = _cache().get(_mac_key(mac)) if mac else None
    return e["enr"] if e else None


def _cache_enr(mac, enr):
    d = _cache()
    if d.get(_mac_key(mac), {}).get("enr") == enr:
        return
    d[_mac_key(mac)] = {"enr": enr, "seen": int(time.time())}
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = STATE_DIR / "enr.json.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(d, indent=1) + "\n")
    os.replace(tmp, STATE_DIR / "enr.json")


# -- picking and checking the target -------------------------------------
def _pick_target(a):
    from .discover import find_cameras
    from .netutil import iface_for
    if a.target:
        return a.target
    iface = _internet_iface()
    print(f"[*] looking for Wyze devices on {iface}...")
    cams = find_cameras(iface)
    if len(cams) == 1:
        print(f"[+] found {cams[0][0]} ({cams[0][1]})")
        return cams[0][0]
    if not cams:
        sys.exit(f"no Wyze device answered on {iface}'s LAN; is the camera "
                 f"on this network? Pass --target <camera ip> to skip the search")
    known = {_mac_key(m) for m in _cache()}
    print(f"[*] {len(cams)} Wyze devices on this LAN (plugs and bulbs share "
          f"the vendor prefix):")
    for i, (ip, mac) in enumerate(cams, 1):
        note = "  (ENR cached)" if _mac_key(mac) in known else ""
        print(f"    {i}) {ip}  {mac}{note}")
    if not sys.stdin.isatty():
        sys.exit("pick one with --target <camera ip>")
    while True:
        try:
            pick = input("which one is the camera? number or IP: ").strip()
        except EOFError:
            sys.exit("pick one with --target <camera ip>")
        if pick.isdigit() and 1 <= int(pick) <= len(cams):
            return cams[int(pick) - 1][0]
        if pick in {ip for ip, _ in cams}:
            return pick


def _internet_iface():
    from .netutil import iface_for
    try:
        return iface_for("8.8.8.8")
    except OSError:
        sys.exit("this host has no internet route; is its network up?")


def _check_target(target, on_path):
    """Validate the target; returns (iface, our address on its LAN)."""
    from .netutil import iface_for, is_local_address, local_ip_for, on_link
    try:
        ipaddress.IPv4Address(target)
    except ValueError:
        sys.exit(f"--target must be an IPv4 address, not {target!r}")
    if is_local_address(target):
        sys.exit(f"{target} is this host's own address")
    if not on_path and not on_link(target):
        sys.exit(f"{target} is not on a LAN this host is attached to")
    iface = iface_for(target)
    if _internet_iface() != iface:
        sys.exit(f"the camera is on {iface} but this host's internet route "
                 f"is on {_internet_iface()} (a VPN?); the camera's "
                 f"traffic must leave through the interface it arrives on")
    return iface, local_ip_for(target)


# -- the armed session ----------------------------------------------------
class Armed:
    """Context manager for everything that changes the host: the journal
    lock, on-path routing, the HTTPS interceptor and the splicer. Leaving
    it (normally, by exception, Ctrl-C, SIGTERM or SIGHUP) undoes it all."""

    def __init__(self, a, out, splice, dry=False):
        self.a, self.out, self.want_splice, self.dry = a, out, splice, dry
        self.iface = self.gateway = None
        self.onpath = self.tap = self.splicer = None
        self.cam_mac = None
        self.changes = None

    def __enter__(self):
        from .changes import Changes
        _need_root_linux()
        self.changes = Changes()
        self.changes.acquire()
        atexit.register(self._teardown)
        try:
            self._enter()
        except BaseException:
            self._teardown()
            raise
        return self

    def _enter(self):
        from .cloud import CloudTap
        from .netutil import ensure_conntrack
        from .onpath import OnPath, neighbor_mac
        from .splice import Splicer
        a = self.a
        target = _pick_target(a)
        a.target = target
        iface, us = _check_target(target, a.on_path)
        self.cam_mac = neighbor_mac(target)
        if not self.cam_mac:
            sys.exit(f"{target} does not answer on {iface}; is the camera on?")
        self.iface = iface
        if self.want_splice:
            ensure_conntrack()
        if not self.dry:
            self.out.mkdir(parents=True, exist_ok=True)
        # bind and check everything before touching the camera's route
        if self.want_splice:
            self.splicer = Splicer(self.changes, target, us, self.out,
                                   pass_through=a.pass_through,
                                   journal=a.journal)
            self.splicer.setup()
        if getattr(a, "events_dir", None) is not None or self._need_harvest():
            self.tap = CloudTap(self.changes, target,
                                events_dir=getattr(a, "events_dir", None),
                                on_event=lambda p: print(f"[+] motion event: {p}"))
            self.tap.listen()
        self.onpath = OnPath(self.changes, target, iface,
                             poison=not a.on_path)
        self.gateway = self.onpath.gateway
        if self.dry:
            return
        _inhibit_sleep()
        self.onpath.start()
        if self.tap:
            self.tap.start()

    def _need_harvest(self):
        return (self.want_splice and not self.enr()
                and not getattr(self.a, "pass_through", False))

    def enr(self):
        a = self.a
        if getattr(a, "enr", None):
            return a.enr
        if getattr(a, "reharvest", False):
            return None
        return _cached_enr(self.cam_mac)

    def wait_enr(self, timeout):
        tap = self.tap
        print("[*] waiting for the camera's ENR. It sends it at boot, on "
              "motion alarms (walk past the camera), and every few hours")
        start = time.monotonic()
        last, warned = None, False
        while not tap.enr_found.wait(5):
            st = dict(tap.stats)
            if st != last and time.monotonic() - start > 30:
                print(f"    camera HTTPS so far: {st['intercepted']} read, "
                      f"{st['passed']} passed through, {st['tls_failed']} "
                      f"refused our certificate")
                last = st
            if st["tls_failed"] >= 3 and not st["intercepted"] and not warned:
                print("[!] the camera keeps refusing the eMudhra certificate: "
                      "this firmware may no longer trust that CA. Pass --enr "
                      "if you have the ENR some other way")
                warned = True
            if timeout and time.monotonic() - start > timeout:
                return None
        if tap.mac and _mac_key(tap.mac) != _mac_key(self.cam_mac):
            print(f"[!] the ENR came from MAC {tap.mac}, but {self.a.target} "
                  f"is {self.cam_mac}")
        print("[+] ENR harvested from the camera's own HTTPS")
        _cache_enr(self.cam_mac, tap.enr)
        return tap.enr

    def __exit__(self, *exc):
        self._teardown()
        return False

    def _teardown(self):
        from .changes import signals_held
        if self.changes is None:
            return
        with signals_held():
            for part in (self.tap, self.splicer, self.onpath):
                if part is None:
                    continue
                try:
                    part.stop() if part is self.tap else part.close()
                except Exception as e:  # noqa: BLE001
                    print(f"[!] teardown step failed: {e!r}")
            self.changes.undo_all()
            self.changes.release()
            if self.tap and self.tap.enr_found.is_set() and self.cam_mac:
                _cache_enr(self.cam_mac, self.tap.enr)
            self.changes = None


def _give_to_user(path, since):
    """Under sudo, hand back the files this run created."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid:
        return
    for root, dirs, files in os.walk(path):
        for n in [root, *(os.path.join(root, f) for f in dirs + files)]:
            st = os.lstat(n)
            if st.st_uid == 0 and st.st_mtime >= since - 1:
                os.chown(n, int(uid), int(gid))


def _default_out(prefix=""):
    return Path(f"captures/{prefix}{time.strftime('%Y%m%d-%H%M%S')}")


def _new_root(path):
    """The topmost directory of `path` that does not exist yet (what this
    run will create), or path itself if it exists."""
    path = Path(path).absolute()
    root = path
    while not root.parent.exists():
        root = root.parent
    return root if not path.exists() else path


# -- commands ---------------------------------------------------------------
def cmd_run(a):
    started = time.time()
    out = Path(a.out) if a.out else _default_out()
    root = _new_root(out)
    a.events_dir = None if a.no_events else out / "events"
    spliced, armed, no_enr = 0, Armed(a, out, splice=True), False
    try:
        with armed:
            enr = armed.enr()
            if enr and not a.enr:
                print("[*] using the cached ENR for this camera")
            if not enr and not a.pass_through:
                enr = armed.wait_enr(a.harvest_timeout)
                no_enr = not enr
                if enr and a.no_events:
                    armed.tap.stop()
            if not no_enr:
                spliced = armed.splicer.run(
                    enr, sessions=None if a.keep_going else 1)
    except KeyboardInterrupt:
        print()
    events = armed.tap.events if armed.tap else []
    av = out / "av.bin"
    if spliced and av.exists() and not a.no_video and not a.pass_through:
        _export(av, out)
    if out.exists():
        _give_to_user(root, started)
        print(f"[+] {spliced} live session(s) spliced, {len(events)} event "
              f"file(s) saved; output in {out}/")
    if no_enr:
        print("[!] no ENR seen; pass --enr, or try again later")
    return 0 if spliced else 1


def cmd_events(a):
    started = time.time()
    out = Path(a.out) if a.out else _default_out("events-")
    root = _new_root(out)
    a.events_dir = out
    armed = Armed(a, out, splice=False)
    try:
        with armed:
            print(f"[*] saving {a.target}'s motion events to {out}/ "
                  f"(Ctrl-C to stop)")
            while True:
                clips = sum(1 for p in armed.tap.events if p.name == "clip.mp4")
                if a.count and clips >= a.count:
                    time.sleep(3)          # let the matching snapshot land
                    break
                time.sleep(1)
    except KeyboardInterrupt:
        print()
    events = armed.tap.events if armed.tap else []
    if out.exists():
        _give_to_user(root, started)
        print(f"[+] {len(events)} event file(s) in {out}/")
    return 0


def cmd_check(a):
    """Every pre-flight check of `run`, without touching the camera."""
    from .netutil import ipt
    a.pass_through = a.journal = False
    a.events_dir = None
    armed = Armed(a, Path("."), splice=True, dry=True)
    with armed:
        print(f"[+] camera {a.target} ({armed.cam_mac}) on {armed.iface}, "
              f"gateway {armed.gateway}")
        print("[+] TPROXY, conntrack netlink, UDP 47821 and TCP 18443: ok")
        print("[+] ENR: " + ("cached" if armed.enr() else
                             "not cached yet; the first run harvests it"))
        policy = ipt("-S", "FORWARD").stdout.splitlines()[:1]
        if policy and policy[0].endswith("DROP"):
            print("[*] iptables FORWARD policy is DROP; run adds accept "
                  "rules for the camera")
        if shutil.which("nft"):
            nft = subprocess.run(["nft", "list", "ruleset"], capture_output=True,
                                 text=True).stdout
            if "hook forward" in nft and "policy drop" in nft:
                print("[!] an nftables chain drops forwarded traffic; iptables "
                      "rules may not override it, and the camera would lose "
                      "its connection")
    print("[+] ready: `run` would work from here")
    return 0


def cmd_find(a):
    from .discover import find_cameras
    _need_root_linux()
    iface = a.iface or _internet_iface()
    cams = find_cameras(iface)
    if not cams:
        print(f"no Wyze devices answered on {iface}")
        return 1
    known = {_mac_key(m) for m in _cache()}
    for ip, mac in cams:
        print(f"{ip}  {mac}{'  (ENR cached)' if _mac_key(mac) in known else ''}")
    return 0


def cmd_cleanup(a):
    from .changes import RUN_DIR, Changes, load
    _need_root_linux()
    if not load(RUN_DIR / "changes.json"):
        print("nothing to undo")
        return 0
    c = Changes()
    c.acquire()          # replays the journal
    c.release()
    print("[+] done")
    return 0


def _export(av, outdir):
    from .media import export
    try:
        r = export(str(av), str(outdir))
    except Exception as e:  # noqa: BLE001
        print(f"[!] video export failed: {e!r}")
        return False
    if not r["frames"]:
        print("[!] no decodable video in av.bin")
        return False
    for m in r["mp4s"]:
        size = f"{m['size'][0]}x{m['size'][1]}" if m["size"] else "?"
        print(f"[+] video: {m['path']} ({size}, {m['seconds']:.1f}s)")
    if r.get("frame"):
        print(f"[+] still: {r['frame']}")
    for err in r.get("errors", []):
        print(f"[!] {err}")
    if r["dropped"]:
        print(f"    {r['dropped']} frame(s) left out: incomplete, or after an "
              f"incomplete I-frame (the camera keeps streaming briefly "
              f"after the viewer leaves, without completing I-frames)")
    return True


def cmd_extract(a):
    av = Path(a.av_bin)
    if av.is_dir():
        av = av / "av.bin"
    if not av.exists():
        sys.exit(f"{av} not found")
    return 0 if _export(av, Path(a.outdir) if a.outdir else av.parent) else 1


def _target_args(p):
    p.add_argument("--target", help="camera IPv4 address (default: find the "
                                    "one Wyze device on this LAN)")
    p.add_argument("--on-path", action="store_true",
                   help="this host already carries the camera's traffic on "
                        "the camera's LAN interface (e.g. the lab): skip ARP "
                        "poisoning")
    p.add_argument("--out", help="output directory (default captures/<time>)")


def _need_root_linux():
    if not sys.platform.startswith("linux"):
        sys.exit("this command runs on Linux (it needs AF_PACKET, iptables "
                 "and TPROXY); only `extract` works elsewhere")
    if os.geteuid() != 0:
        sys.exit("this command needs root (ARP, iptables, raw and "
                 "transparent sockets): run it with sudo")


def main(argv=None):
    sys.stdout = _QuietStream(sys.stdout)
    sys.stderr = _QuietStream(sys.stderr)
    _install_signals()
    ap = argparse.ArgumentParser(prog="wyze-splice", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="get on-path, splice the next live view, "
                                   "write the video")
    _target_args(r)
    r.add_argument("--enr", help="camera ENR (default: harvest it from the "
                                 "camera, then reuse the cached one)")
    r.add_argument("--reharvest", action="store_true",
                   help="ignore the cached ENR and read it from the camera again")
    r.add_argument("--harvest-timeout", type=int, default=0, metavar="SECONDS",
                   help="give up waiting for the ENR (default: wait)")
    r.add_argument("--keep-going", action="store_true",
                   help="splice every live view until Ctrl-C, not just the first")
    r.add_argument("--no-events", action="store_true",
                   help="don't save motion events uploaded during the run")
    r.add_argument("--no-video", action="store_true",
                   help="skip the MP4 export at the end")
    r.add_argument("--pass-through", action="store_true",
                   help="divert but forward verbatim, no decryption (A/B control)")
    r.add_argument("--journal", action="store_true",
                   help="also write journal.jsonl with all key material")
    r.set_defaults(fn=cmd_run)

    ev = sub.add_parser("events", help="get on-path and save motion-event "
                                       "clips and snapshots until Ctrl-C")
    _target_args(ev)
    ev.add_argument("--count", type=int, default=0,
                    help="stop after this many clips (default: until Ctrl-C)")
    ev.set_defaults(fn=cmd_events)

    ck = sub.add_parser("check", help="run every pre-flight check without "
                                      "touching the camera")
    ck.add_argument("--target", help="camera IPv4 address (default: find it)")
    ck.add_argument("--on-path", action="store_true", help=argparse.SUPPRESS)
    ck.add_argument("--enr", help=argparse.SUPPRESS)
    ck.add_argument("--reharvest", action="store_true", help=argparse.SUPPRESS)
    ck.set_defaults(fn=cmd_check)

    f = sub.add_parser("find", help="list Wyze devices on this LAN")
    f.add_argument("--iface", help="interface to search (default: the one "
                                   "with the internet route)")
    f.set_defaults(fn=cmd_find)

    c = sub.add_parser("cleanup", help="undo network changes left by a run "
                                       "that was killed")
    c.set_defaults(fn=cmd_cleanup)

    e = sub.add_parser("extract", help="rebuild video.mp4 + frame.jpg "
                                       "from a capture")
    e.add_argument("av_bin", help="a capture directory or its av.bin")
    e.add_argument("outdir", nargs="?")
    e.set_defaults(fn=cmd_extract)

    a = ap.parse_args(argv)
    try:
        return a.fn(a)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
