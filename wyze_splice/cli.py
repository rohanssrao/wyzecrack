"""wyze-splice: decrypt a Wyze Cam v3 live view while the app keeps playing.

  sudo wyze-splice run                 splice the next live view, save events
  sudo wyze-splice events              only save motion-event clips
  sudo wyze-splice find                list Wyze devices on this LAN
  sudo wyze-splice cleanup             undo what a crashed run left behind
  wyze-splice extract <capture>/av.bin rebuild the video from a capture

run and events find the camera by itself when the LAN has exactly one
Wyze device; otherwise pass --target <camera ip>.
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
    p = subprocess.Popen([exe, "--what=sleep:idle:handle-lid-switch",
                          "--who=wyze-splice", "--why=camera gateway",
                          "sleep", "infinity"], start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    atexit.register(p.terminate)


# -- ENR cache (keyed by camera MAC) ------------------------------------
def _mac_key(mac):
    return mac.replace(":", "").upper()


def _cache():
    try:
        return json.loads((STATE_DIR / "enr.json").read_text())
    except (OSError, ValueError):
        return {}


def _cached_enr(mac):
    e = _cache().get(_mac_key(mac)) if mac else None
    return e["enr"] if e else None


def _cache_enr(mac, enr):
    d = _cache()
    if d.get(_mac_key(mac), {}).get("enr") == enr:
        return
    d[_mac_key(mac)] = {"enr": enr, "seen": int(time.time())}
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = STATE_DIR / "enr.json"
    path.write_text(json.dumps(d, indent=1) + "\n")
    os.chmod(path, 0o600)


# -- picking and checking the target -------------------------------------
def _pick_target(a):
    from .discover import find_cameras
    from .netutil import iface_for
    if a.target:
        return a.target
    iface = iface_for("8.8.8.8")
    print(f"[*] looking for Wyze devices on {iface}...")
    cams = find_cameras(iface)
    if len(cams) == 1:
        print(f"[+] found {cams[0][0]} ({cams[0][1]})")
        return cams[0][0]
    if not cams:
        sys.exit(f"no Wyze device answered on {iface}'s LAN; is the camera "
                 f"on this network? Pass --target <camera ip> to skip the search")
    print("[!] more than one Wyze device on this LAN:")
    for ip, mac in cams:
        print(f"      {ip}  {mac}")
    sys.exit("pick one with --target <camera ip>")


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
    if iface_for("8.8.8.8") != iface:
        sys.exit(f"the camera is on {iface} but this host's internet route "
                 f"is on {iface_for('8.8.8.8')} (a VPN?); the camera's "
                 f"traffic must leave through the interface it arrives on")
    return iface, local_ip_for(target)


# -- the armed session ----------------------------------------------------
class Armed:
    """Context manager for everything that changes the host: the journal
    lock, on-path routing, the HTTPS interceptor and the splicer. Leaving
    it (normally, by exception, Ctrl-C, SIGTERM or SIGHUP) undoes it all."""

    def __init__(self, a, out, splice):
        self.a, self.out, self.want_splice = a, out, splice
        self.onpath = self.tap = self.splicer = None
        self.cam_mac = None
        self.changes = None

    def __enter__(self):
        from .changes import Changes
        if os.geteuid() != 0:
            sys.exit("needs root (ARP, iptables, raw and transparent sockets)")
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
        ensure_conntrack()
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
        _inhibit_sleep()
        self.onpath = OnPath(self.changes, target, iface,
                             poison=not a.on_path)
        self.onpath.start()
        if self.tap:
            self.tap.start()

    def _need_harvest(self):
        return self.want_splice and not self.enr()

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


# -- commands ---------------------------------------------------------------
def cmd_run(a):
    started = time.time()
    out = Path(a.out) if a.out else _default_out()
    a.events_dir = None if a.no_events else out / "events"
    spliced, armed = 0, Armed(a, out, splice=True)
    try:
        with armed:
            enr = armed.enr()
            if enr and not a.enr:
                print("[*] using the cached ENR for this camera")
            if not enr:
                enr = armed.wait_enr(a.harvest_timeout)
                if not enr:
                    sys.exit("no ENR seen; pass --enr, or try again later")
                if a.no_events:
                    armed.tap.stop()
            spliced = armed.splicer.run(enr, sessions=None if a.keep_going else 1)
    except KeyboardInterrupt:
        print()
    events = armed.tap.events if armed.tap else []
    av = out / "av.bin"
    if spliced and av.exists() and not a.no_video and not a.pass_through:
        _export(av, out)
    if out.exists():
        _give_to_user(out, started)
    print(f"[+] {spliced} live session(s) spliced, {len(events)} event "
          f"file(s) saved; output in {out}/")
    return 0 if spliced else 1


def cmd_events(a):
    started = time.time()
    out = Path(a.out) if a.out else _default_out("events-")
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
        _give_to_user(out, started)
    print(f"[+] {len(events)} event file(s) in {out}/")
    return 0


def cmd_find(a):
    from .discover import find_cameras
    from .netutil import iface_for
    if os.geteuid() != 0:
        sys.exit("needs root (raw ARP)")
    iface = a.iface or iface_for("8.8.8.8")
    cams = find_cameras(iface)
    if not cams:
        print(f"no Wyze devices answered on {iface}")
        return 1
    for ip, mac in cams:
        print(f"{ip}  {mac}")
    return 0


def cmd_cleanup(a):
    from .changes import RUN_DIR, Changes, load
    if os.geteuid() != 0:
        sys.exit("needs root")
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
                   help="this host already routes the camera (its gateway, "
                        "or the lab): skip ARP poisoning")
    p.add_argument("--out", help="output directory (default captures/<time>)")


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
