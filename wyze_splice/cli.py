"""wyze-splice: watch a Wyze Cam v3 from the local network.

  wyze-splice                          open the app (pick a camera, watch it)
  sudo wyze-splice watch               record the live view straight from the camera
  sudo wyze-splice key                 get and save the camera's ENR and UID
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
import threading
import subprocess
import sys
import time
from pathlib import Path

STATE_DIR = Path(os.environ.get("WYZE_SPLICE_STATE", "/var/lib/wyze-splice"))
# Models on which the ENR nudge (nudge.py: resetting the camera's MQTT
# connection until it reports in) has been tried live and the camera
# stayed online. The v2 got it only after a test with someone there to
# power-cycle it (an internet outage had once left one offline for over an
# hour): the v2, 4.9.9.3006, key after one reset, 2026-11-05.
NUDGE_MODELS = {"WYZE_CAKP2JFUS", "WYZEC1-JZ"}
# firmware to quote to Wyze when the camera's own report didn't say
DEFAULT_FW = "4.36.17.21"


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


def _inhibit_sleep(why):
    """Keep the host awake until _release_inhibitor(returned value): a
    suspended host black-holes the camera while it is the camera's gateway,
    and ends a live view. Returns None without systemd-inhibit."""
    exe = shutil.which("systemd-inhibit")
    if not exe:
        return None
    # `tail --pid` also ends the lock when this process is killed outright
    p = subprocess.Popen([exe, "--what=sleep:idle:handle-lid-switch",
                          "--who=wyze-splice", f"--why={why}",
                          "tail", f"--pid={os.getpid()}", "-f", "/dev/null"],
                         start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    atexit.register(_release_inhibitor, p)
    return p


def _release_inhibitor(p):
    if p is not None and p.poll() is None:
        p.terminate()
        try:
            p.wait(2)
        except subprocess.TimeoutExpired:
            p.kill()


# -- camera key cache (keyed by camera MAC) -------------------------------
# enr.json: {MAC: {"enr", "seen", and once known "uid", "model", "fw", "hw"}}
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


def _cached(mac):
    return (_cache().get(_mac_key(mac)) or {}) if mac else {}


def _cached_enr(mac):
    return _cached(mac).get("enr")


def _cached_uid(mac):
    return _cached(mac).get("uid")


def _remember_framing(mac, d):
    """After a session opened: which framing the camera speaks, so the next
    session only sends that one's discovery."""
    if d.framing and _cached(mac).get("framing") != d.framing:
        _cache_enr(mac, _cached_enr(mac), framing=d.framing)


def _forget_key(mac):
    """Drop a camera's ENR, for a camera that was set up again in the Wyze
    app; the next session reads it again."""
    d = _cache()
    entry = d.get(_mac_key(mac))
    if not entry:
        return
    # the UID is the camera's for life; the ENR (and so the AuthKey that
    # signs every packet) changes when it is set up again
    for k in ("enr", "framing"):
        entry.pop(k, None)
    tmp = STATE_DIR / "enr.json.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(d, indent=1) + "\n")
    os.replace(tmp, STATE_DIR / "enr.json")


def _cache_enr(mac, enr, **fields):
    """Remember the camera's ENR, plus uid/model/fw/hw when given. A new
    ENR keeps the UID: the UID is the camera's for life, the ENR changes
    when it is set up again."""
    d = _cache()
    old = d.get(_mac_key(mac), {})
    new = {**old, **{k: v for k, v in fields.items() if v}, "enr": enr}
    if old == new or (old.get("enr") == enr and not fields and old):
        return
    new["seen"] = int(time.time())
    d[_mac_key(mac)] = new
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = STATE_DIR / "enr.json.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(d, indent=1) + "\n")
    os.replace(tmp, STATE_DIR / "enr.json")


def _relays(mac):
    """The STUN relays this camera used the last time all of them came
    through this host."""
    try:
        d = json.loads((STATE_DIR / "relays.json").read_text())
    except (OSError, ValueError):
        return []
    return d.get(_mac_key(mac), [])


def _save_relays(mac, seen):
    if sorted(seen) == sorted(_relays(mac)):
        return
    try:
        d = json.loads((STATE_DIR / "relays.json").read_text())
    except (OSError, ValueError):
        d = {}
    d[_mac_key(mac)] = sorted(seen)
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = STATE_DIR / "relays.json.tmp"
    tmp.write_text(json.dumps(d, indent=1) + "\n")
    os.replace(tmp, STATE_DIR / "relays.json")


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

    def __init__(self, a, out, splice, dry=False, harvest=False, changes=None):
        self.a, self.out, self.want_splice, self.dry = a, out, splice, dry
        self.want_harvest = harvest
        # a scope of a longer-lived journal (the page's), or None to take
        # the single-instance lock and a journal of its own
        self.scope = changes
        self.iface = self.gateway = None
        self.onpath = self.tap = self.splicer = None
        self.cam_mac = None
        self.changes = None
        self._sleep_lock = None
        self._down = threading.Lock()
        # front-end hooks
        self.stop = None                 # threading.Event: abandon waits
        self.on_motion = lambda p: print(f"[+] motion event: {p}")

    def __enter__(self):
        from .changes import Changes
        _need_root_linux()
        self.changes = self.scope or Changes()
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
        from . import events
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
            w = self.splicer.watcher
            w.expected_relays = set(_relays(self.cam_mac))
            w.on_relays = lambda seen: _save_relays(self.cam_mac, seen)
            self.splicer.setup()
        if getattr(a, "events_dir", None) is not None or self._need_harvest():
            self.tap = CloudTap(self.changes, target,
                                events_dir=getattr(a, "events_dir", None),
                                on_event=self.on_motion)
            self.tap.listen()
        self.onpath = OnPath(self.changes, target, iface,
                             poison=not a.on_path)
        self.gateway = self.onpath.gateway
        if self.dry:
            return
        self._sleep_lock = _inhibit_sleep("camera gateway")
        events.emit("onpath", state="arming")
        self.onpath.start()
        if self.tap:
            self.tap.start()
        events.emit("onpath", state="on")

    def _need_harvest(self):
        if self.want_harvest:
            return True
        return (self.want_splice and not self.enr()
                and not getattr(self.a, "pass_through", False))

    def enr(self):
        a = self.a
        if getattr(a, "enr", None):
            return a.enr
        if getattr(a, "reharvest", False):
            return None
        return _cached_enr(self.cam_mac)

    def wait_enr(self, timeout, nudge=True):
        """Wait for the camera to send its ENR. With nudge, on models in
        NUDGE_MODELS, make it send one now (nudge.py)."""
        from .nudge import MqttNudge
        n = None
        if nudge and self.model() in NUDGE_MODELS:
            n = MqttNudge(self.changes, self.a.target, self.iface)
            n.start()
        try:
            return self._wait_enr(timeout, n)
        finally:
            if n:
                n.stop.set()
                n.thread.join(3)

    def model(self):
        from .discover import describe
        return (_cached(self.cam_mac).get("model")
                or describe(self.a.target, self.cam_mac, self.gateway).get("model_id"))

    def _wait_enr(self, timeout, n):
        from . import events
        tap = self.tap
        if n:
            print("[*] getting the camera's ENR: its connection to Wyze is reset "
                  "a few times, which makes it report in (about a minute)")
        else:
            print("[*] waiting for the camera's ENR. It sends it at boot, on "
                  "motion alarms, and in a report every 20 minutes or so")
        events.emit("enr", state="nudging" if n else "waiting",
                    stats=dict(tap.stats))
        start = time.monotonic()
        last, printed, warned, told = None, None, False, False
        while not tap.enr_found.wait(1):
            if self.stop and self.stop.is_set():
                return None
            st = dict(tap.stats, resets=n.resets if n else 0)
            if st != last:
                events.emit("enr", state="nudging" if n and not n.failed
                            else "waiting", stats=st)
                last = st
            if n and n.failed and not told:
                print(f"[!] {n.failed}; waiting for the camera to report in "
                      f"on its own")
                told = True
            if st != printed and time.monotonic() - start > 30:
                print(f"    camera HTTPS so far: {st['intercepted']} read, "
                      f"{st['passed']} passed through, {st['tls_failed']} "
                      f"refused our certificate")
                printed = st
            if st["tls_failed"] >= 3 and not st["intercepted"] and not warned:
                print("[!] the camera keeps refusing the eMudhra certificate: "
                      "this firmware may no longer trust that CA. Pass --enr "
                      "if you have the ENR some other way")
                events.emit("enr", state="refused", stats=st)
                warned = True
            if timeout and time.monotonic() - start > timeout:
                return None
        if tap.mac and _mac_key(tap.mac) != _mac_key(self.cam_mac):
            print(f"[!] the ENR came from MAC {tap.mac}, but {self.a.target} "
                  f"is {self.cam_mac}")
        print(f"[+] ENR harvested from the camera's own HTTPS after "
              f"{time.monotonic() - start:.0f} s"
              + (f" and {n.resets} connection reset(s)" if n else ""))
        _cache_enr(self.cam_mac, tap.enr, **tap.device)
        events.emit("enr", state="harvested")
        return tap.enr

    def __exit__(self, *exc):
        self._teardown()
        return False

    def _teardown(self):
        from .changes import signals_held
        # atexit and the owner's `with` can both get here, from different
        # threads: one does the work, the other waits for it
        with self._down:
            if self.changes is None:
                return
            with signals_held():
                self._undo_everything()

    def _undo_everything(self):
        for part in (self.tap, self.splicer, self.onpath):
            if part is None:
                continue
            try:
                part.stop() if part is self.tap else part.close()
            except Exception as e:  # noqa: BLE001
                print(f"[!] teardown step failed: {e!r}")
        self.changes.undo_all()
        self.changes.release()
        _release_inhibitor(self._sleep_lock)
        self._sleep_lock = None
        if self.tap and self.tap.enr_found.is_set() and self.cam_mac:
            _cache_enr(self.cam_mac, self.tap.enr, **self.tap.device)
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
                enr = armed.wait_enr(a.harvest_timeout, nudge=not a.no_nudge)
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


def obtain_key(armed, a, nudge=True):
    """(enr, uid) for the armed camera: from the cache, else the ENR from
    the camera's HTTPS and the UID from Wyze. Returns (enr, None) when
    Wyze won't give the UID, and (None, None) without an ENR."""
    from . import events
    from .cloud import CloudError
    mac = armed.cam_mac
    enr = armed.enr()
    if enr:
        events.emit("enr", state="harvested", cached=True)
    else:
        enr = armed.wait_enr(getattr(a, "harvest_timeout", 0), nudge=nudge)
    if not enr:
        return None, None
    uid = None if getattr(a, "reharvest", False) else _cached_uid(mac)
    if uid:
        events.emit("uid", state="done", cached=True)
        return enr, uid
    events.emit("uid", state="active")
    try:
        uid = uid_from_wyze(a.target, mac, enr, armed.gateway)
    except CloudError as e:
        print(f"[!] {e}")
        events.emit("uid", state="problem", detail=str(e))
        return enr, None
    events.emit("uid", state="done")
    return enr, uid


def uid_from_wyze(target, mac, enr, gateway=None):
    """Ask Wyze for the camera's UID with its ENR (see cloud.fetch_uid) and
    cache it. Raises cloud.CloudError."""
    from .cloud import fetch_uid
    from .discover import describe
    from .netutil import default_gateway, iface_for
    known = _cached(mac)
    model = known.get("model")
    if not model:
        gw = gateway or default_gateway(iface_for(target))
        model = describe(target, mac, gw).get("model_id") or "WYZE_CAKP2JFUS"
    print("[*] asking Wyze for the camera's P2P UID, as the camera")
    uid = fetch_uid(mac, enr, model, known.get("fw") or DEFAULT_FW,
                    known.get("hw") or "0.0.0.0")
    print(f"[+] UID {uid}")
    _cache_enr(mac, enr, uid=uid)
    return uid


def _direct_key(a):
    """(target, mac, enr, uid), getting on-path once to learn what isn't
    cached yet."""
    from .cloud import CloudError
    from .onpath import neighbor_mac
    target = _pick_target(a)
    a.target = target
    mac = neighbor_mac(target)
    if not mac:
        sys.exit(f"{target} does not answer; is the camera on?")
    enr = getattr(a, "enr", None) or (None if a.reharvest else _cached_enr(mac))
    uid = None if a.reharvest else _cached_uid(mac)
    if enr and not uid:
        try:
            uid = uid_from_wyze(target, mac, enr)
        except CloudError as e:
            sys.exit(f"{e}; `wyze-splice run` still works, by catching a "
                     f"live view the app opens")
    if enr and uid:
        return target, mac, enr, uid
    print("[*] first time with this camera: reading its key (ENR) off its "
          "own HTTPS, then its UID from Wyze")
    armed = Armed(a, Path("."), splice=False, harvest=True)
    a.events_dir = None
    with armed:
        enr, uid = obtain_key(armed, a, nudge=not a.no_nudge)
    if not enr:
        sys.exit("no ENR seen; trigger a motion alarm and try again, or "
                 "pass --enr")
    if not uid:
        sys.exit("Wyze didn't hand out the camera's UID; `wyze-splice run` "
                 "still works, by catching a live view the app opens")
    return target, mac, enr, uid


def cmd_key(a):
    target, mac, enr, uid = _direct_key(a)
    print(f"[+] {target} ({mac}): ENR and UID saved in {STATE_DIR}/enr.json")
    return 0


def cmd_watch(a):
    """The live view straight from the camera, recorded until Ctrl-C (or
    --seconds)."""
    from .changes import Changes, signals_held
    from .direct import CameraGone, Direct, open_firewall, open_first
    from .netutil import local_ip_for
    started = time.time()
    target, mac, enr, uid = _direct_key(a)
    out = Path(a.out) if a.out else _default_out("watch-")
    root = _new_root(out)
    out.mkdir(parents=True, exist_ok=True)
    changes = Changes()
    changes.acquire()
    framing = _cached(mac).get("framing")

    def make(stop):
        s = Direct(target, uid, enr, mac, local_ip=local_ip_for(target),
                   stop=stop, framing=framing)
        open_firewall(changes, target, s.port)
        return s

    d, ok = None, False
    sleep_lock = _inhibit_sleep("recording a live view")
    try:
        t0 = time.monotonic()
        d = open_first(make, av_log=str(out / "av.bin"))
        _remember_framing(mac, d)
        print(f"[+] live from {target} after {time.monotonic() - t0:.1f} s"
              + (f" ({d.tries} sessions tried)" if d.tries > 1 else "")
              + f"; recording to {out}/ (Ctrl-C to stop)")
        ok = True
        end = time.monotonic() + a.seconds if a.seconds else None
        tick = time.monotonic() + 5
        while end is None or time.monotonic() < end:
            d.pump(0.5)
            if os.environ.get("WYZE_SPLICE_DEBUG") and time.monotonic() >= tick:
                print(f"[d] {time.strftime('%T')} rx {d.stats['rx']} "
                      f"ignored {d.stats.get('ignored', 0)} tx {d.stats['tx']}")
                tick += 5
    except KeyboardInterrupt:
        print()
    except (CameraGone, ValueError) as e:
        print(f"[!] {e}")
    finally:
        if d:
            if os.environ.get("WYZE_SPLICE_DEBUG"):
                print(f"[d] session ({d.framing} framing): {d.stats}")
            d.close()
        with signals_held():
            changes.undo_all()
        changes.release()
        _release_inhibitor(sleep_lock)
    if ok and not a.no_video:
        _export(out / "av.bin", out)
    _give_to_user(root, started)
    return 0 if ok else 1


def cmd_check(a):
    """Every pre-flight check of `run`, without touching the camera."""
    from .netutil import ipt
    a.pass_through = a.journal = False
    a.events_dir = None
    armed = Armed(a, Path("."), splice=True, dry=True)
    with armed:
        print(f"[+] camera {a.target} ({armed.cam_mac}) on {armed.iface}, "
              f"gateway {armed.gateway}")
        print("[+] TPROXY, conntrack netlink and UDP 47821: ok")
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
              f"incomplete I-frame")
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


def _key_args(p):
    p.add_argument("--target", help="camera IPv4 address (default: find the "
                                    "one Wyze device on this LAN)")
    p.add_argument("--enr", help="camera ENR (default: harvest it once, then "
                                 "reuse it)")
    p.add_argument("--reharvest", action="store_true",
                   help="ignore the saved ENR and UID and get them again")
    p.add_argument("--no-nudge", action="store_true",
                   help="don't reset the camera's cloud connection to make it "
                        "report its ENR; wait for it to report on its own")
    p.add_argument("--harvest-timeout", type=int, default=0, metavar="SECONDS",
                   help="give up waiting for the ENR (default: wait)")
    p.add_argument("--on-path", action="store_true", help=argparse.SUPPRESS)


def _sudo_reexec():
    """Re-run this command under sudo (it prompts for the password), so
    users never need to type sudo themselves."""
    if os.geteuid() == 0 or not sys.platform.startswith("linux"):
        return
    exe = shutil.which("sudo")
    if not exe:
        sys.exit("wyze-splice needs root; run it as root")
    print("wyze-splice needs root to reroute the camera's traffic.")
    keep = ",".join(k for k in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
                                "DBUS_SESSION_BUS_ADDRESS", "PYTHONPATH")
                    if k in os.environ)
    argv = [exe] + ([f"--preserve-env={keep}"] if keep else []) + \
        [sys.executable, "-m", "wyze_splice", *sys.argv[1:]]
    os.execv(exe, argv)


def cmd_gui(a):
    _sudo_reexec()
    _need_root_linux()
    from .gui import serve
    return serve(listen=a.listen, port=a.port, out=a.out or "captures",
                 browser=not a.no_browser)


def _need_root_linux():
    if not sys.platform.startswith("linux"):
        sys.exit("this command runs on Linux (it needs AF_PACKET, iptables "
                 "and TPROXY); only `extract` works elsewhere")
    if os.geteuid() != 0:
        sys.exit("this command needs root (ARP, iptables, raw and "
                 "transparent sockets): run it with sudo")


def main(argv=None):
    try:
        sys.stdout.reconfigure(line_buffering=True)   # progress shows at once
    except (AttributeError, ValueError):
        pass
    sys.stdout = _QuietStream(sys.stdout)
    sys.stderr = _QuietStream(sys.stderr)
    _install_signals()
    ap = argparse.ArgumentParser(prog="wyze-splice", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    g = sub.add_parser("gui", help="the app (default): pick a camera, watch along")
    g.add_argument("--listen", default="127.0.0.1",
                   help="address to serve the page on (e.g. a tailnet address "
                        "to watch from another device)")
    g.add_argument("--port", type=int, default=0)
    g.add_argument("--out", help="where recordings go (default ./captures)")
    g.add_argument("--no-browser", action="store_true",
                   help="print the link instead of opening a browser")
    g.set_defaults(fn=cmd_gui)

    r = sub.add_parser("run", help="get on-path, splice the next live view, "
                                   "write the video")
    _target_args(r)
    r.add_argument("--enr", help="camera ENR (default: harvest it from the "
                                 "camera, then reuse the cached one)")
    r.add_argument("--reharvest", action="store_true",
                   help="ignore the cached ENR and read it from the camera again")
    r.add_argument("--harvest-timeout", type=int, default=0, metavar="SECONDS",
                   help="give up waiting for the ENR (default: wait)")
    r.add_argument("--no-nudge", action="store_true",
                   help="don't reset the camera's cloud connection to make it "
                        "report its ENR; wait for it to report on its own")
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

    w = sub.add_parser("watch", help="watch and record the camera directly "
                                     "over the LAN (no phone needed)")
    _key_args(w)
    w.add_argument("--out", help="output directory (default captures/watch-<time>)")
    w.add_argument("--seconds", type=float, default=0,
                   help="stop after this long (default: until Ctrl-C)")
    w.add_argument("--no-video", action="store_true",
                   help="skip the MP4 export at the end")
    w.set_defaults(fn=cmd_watch)

    k = sub.add_parser("key", help="get and save the camera's ENR and UID "
                                   "(once per camera)")
    _key_args(k)
    k.set_defaults(fn=cmd_key)

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
    if a.cmd is None:
        a = ap.parse_args(["gui", *(argv or [])])
    if a.cmd in ("run", "watch", "key", "events", "find", "check", "cleanup"):
        _sudo_reexec()
    try:
        return a.fn(a)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
