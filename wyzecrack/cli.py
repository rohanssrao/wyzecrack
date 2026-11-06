"""wyzecrack: watch and record Wyze cameras from their local network.

  wyzecrack                          open the app (pick a camera, watch it)
  wyzecrack watch                    record the live view straight from the camera
  wyzecrack events                   save the camera's motion clips
  wyzecrack cleanup                  undo what a killed wyzecrack left behind
  wyzecrack extract <recording>      write a recording's video again, if that failed

watch and events find the camera by themselves when the LAN has one Wyze
device, and ask which one when it has several; --target <camera ip> skips
the search.
"""
import argparse
import os
import shutil
import signal
import sys
import threading
import time
from pathlib import Path


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


def _pick_target(a):
    """The camera's address: --target, the one Wyze device on the LAN, or
    the one the user picks."""
    from . import keys
    from .discover import find_cameras
    from .netutil import internet_iface
    if a.target:
        return a.target
    iface = internet_iface()
    print(f"[*] looking for Wyze devices on {iface}...")
    cams = find_cameras(iface)
    if len(cams) == 1:
        print(f"[+] found {cams[0][0]} ({cams[0][1]})")
        return cams[0][0]
    if not cams:
        sys.exit(f"no Wyze device answered on {iface}'s LAN; is the camera "
                 f"on this network? Pass --target <camera ip> to skip the search")
    print(f"[*] {len(cams)} Wyze devices on this LAN (plugs and bulbs share "
          f"the vendor prefix):")
    for i, (ip, mac) in enumerate(cams, 1):
        note = "  (key saved)" if keys.cached(mac).get("enr") else ""
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


def _camera_mac(target):
    from .onpath import neighbor_mac
    mac = neighbor_mac(target)
    if not mac:
        sys.exit(f"{target} does not answer; is the camera on?")
    return mac


def _journal():
    """The run's journal of host changes, holding the single-instance lock
    (and undoing what a crashed run left)."""
    from .changes import Changes
    c = Changes()
    c.acquire()
    return c


def _close(journal):
    from .changes import signals_held
    with signals_held():
        journal.undo_all()
    journal.release()


def give_to_user(path, since):
    """Under sudo, hand back the files this run created."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid:
        return
    for root, dirs, files in os.walk(path):
        for n in [root, *(os.path.join(root, f) for f in dirs + files)]:
            st = os.lstat(n)
            if st.st_uid == 0 and st.st_mtime >= since - 1:
                os.chown(n, int(uid), int(gid))


def _default_out(prefix):
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
def cmd_watch(a):
    """The live view straight from the camera, recorded until Ctrl-C (or
    --seconds). When the camera hangs up it reconnects, as the page does;
    everything goes into one recording."""
    from . import keys
    from .view import watch
    started = time.time()
    target = _pick_target(a)
    mac = _camera_mac(target)
    if a.enr:
        keys.save(mac, enr=a.enr)
    elif a.reharvest:
        keys.forget_enr(mac)
    out = Path(a.out) if a.out else _default_out("watch-")
    root = _new_root(out)
    journal = _journal()
    seen = set()                   # "live", "picture"

    def picture(frame):
        seen.add("picture")

    def status(kind, **info):
        if kind == "live" and "live" not in seen:
            seen.add("live")
            print(f"    recording to {out}/ (Ctrl-C to stop)")
        elif kind == "retry":
            print("[*] the camera hung up; reconnecting" if info["hung_up"]
                  else "[*] trying again")
        elif kind == "gave_up":
            print("[!] the camera doesn't answer. Is it switched on in the "
                  "Wyze app? If it was set up again there, its key changed: "
                  "`wyzecrack watch --reharvest` reads the new one")

    try:
        enr, uid = keys.camera_key(journal, target, mac)
        out.mkdir(parents=True, exist_ok=True)
        watch(journal, target, mac, enr, uid, str(out / "av.bin"),
              threading.Event(), seconds=a.seconds, on_video=picture,
              on_status=status)
    except KeyboardInterrupt:
        print()
    finally:
        _close(journal)
    if (out / "av.bin").exists():
        _export(out / "av.bin", out)
    if out.is_dir() and not any(out.iterdir()):
        out.rmdir()
    if root.exists():
        give_to_user(root, started)
    return 0 if "picture" in seen else 1


def cmd_events(a):
    from .onpath import Reroute
    started = time.time()
    target = _pick_target(a)
    out = Path(a.out) if a.out else _default_out("events-")
    root = _new_root(out)
    journal = _journal()
    saved = []

    def on_motion(path):
        print(f"[+] motion event: {path}")
        saved.append(path)

    r = Reroute(journal, target, on_path=a.on_path, events_dir=out,
                on_motion=on_motion)
    try:
        r.start()
        print(f"[*] saving {target}'s motion events to {out}/ (Ctrl-C to stop)")
        while not (a.count and sum(p.name == "clip.mp4" for p in saved) >= a.count):
            time.sleep(1)
        time.sleep(3)              # let the matching snapshot land
    except KeyboardInterrupt:
        print()
    finally:
        r.stop()
        _close(journal)
    if out.exists():
        give_to_user(root, started)
        print(f"[+] {len(saved)} event file(s) in {out}/")
    return 0


def cmd_cleanup(a):
    from .changes import RUN_DIR, load
    if not load(RUN_DIR / "changes.json"):
        print("nothing to undo")
        return 0
    _journal().release()           # taking it replays the journal
    print("[+] done")
    return 0


def _export(av, outdir):
    """video.mp4 and frame.jpg from av.bin, which then goes; it stays if
    the export failed, for `extract` to try again."""
    from .media import export
    try:
        r = export(str(av), str(outdir))
    except Exception as e:  # noqa: BLE001
        r = {"mp4": None, "error": repr(e)}
    if r["error"]:
        print(f"[!] couldn't write the video ({r['error']}); "
              f"`wyzecrack extract {outdir}` tries again")
        return False
    av.unlink()
    if not r["mp4"]:
        print("[!] the camera sent no whole picture")
        return False
    size = f"{r['size'][0]}x{r['size'][1]}" if r["size"] else "?"
    print(f"[+] video: {r['mp4']} ({size}, {r['seconds']:.1f} s)")
    return True


def cmd_extract(a):
    av = Path(a.av_bin)
    if av.is_dir():
        av = av / "av.bin"
    if not av.exists():
        sys.exit(f"{av} not found")
    return 0 if _export(av, Path(a.outdir) if a.outdir else av.parent) else 1


def cmd_gui(a):
    from .gui import serve
    return serve(listen=a.listen, port=a.port, out=a.out or "captures",
                 browser=not a.no_browser)


def _sudo_reexec():
    """Re-run this command under sudo (it prompts for the password), so
    users never need to type sudo themselves."""
    if os.geteuid() == 0 or not sys.platform.startswith("linux"):
        return
    exe = shutil.which("sudo")
    if not exe:
        sys.exit("wyzecrack needs root; run it as root")
    print("wyzecrack needs root to reroute the camera's traffic.")
    keep = ",".join(k for k in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
                                "DBUS_SESSION_BUS_ADDRESS", "PYTHONPATH")
                    if k in os.environ)
    # -B: root writing __pycache__ into the user's install would leave
    # files the user can't remove (uv tool uninstall/upgrade then fails)
    argv = [exe] + ([f"--preserve-env={keep}"] if keep else []) + \
        [sys.executable, "-B", "-m", "wyzecrack", *sys.argv[1:]]
    os.execv(exe, argv)


def _need_root_linux():
    if not sys.platform.startswith("linux"):
        sys.exit("this command runs on Linux (it needs AF_PACKET and "
                 "iptables); only `extract` works elsewhere")
    if os.geteuid() != 0:
        sys.exit("this command needs root (ARP, iptables and raw sockets): "
                 "run it with sudo")


def main(argv=None):
    try:
        sys.stdout.reconfigure(line_buffering=True)   # progress shows at once
    except (AttributeError, ValueError):
        pass
    sys.stdout = _QuietStream(sys.stdout)
    sys.stderr = _QuietStream(sys.stderr)
    _install_signals()
    ap = argparse.ArgumentParser(prog="wyzecrack", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    target_help = "camera IPv4 address (default: find the one Wyze device on this LAN)"
    g = sub.add_parser("gui", help="the page (default): pick a camera and watch it")
    g.add_argument("--listen", default="127.0.0.1",
                   help="address to serve the page on (e.g. a tailnet address "
                        "to watch from another device)")
    g.add_argument("--port", type=int, default=0)
    g.add_argument("--out", help="where recordings go (default ./captures)")
    g.add_argument("--no-browser", action="store_true",
                   help="print the link instead of opening a browser")
    g.set_defaults(fn=cmd_gui)

    w = sub.add_parser("watch", help="record the live view straight from "
                                     "the camera, until Ctrl-C")
    w.add_argument("--target", help=target_help)
    w.add_argument("--enr", help="the camera's key (ENR), if you have it "
                                 "from elsewhere (default: read it from the "
                                 "camera once)")
    w.add_argument("--reharvest", action="store_true",
                   help="read the camera's key again (after it was set up "
                        "again in the Wyze app)")
    w.add_argument("--out", help="output directory (default captures/watch-<time>)")
    w.add_argument("--seconds", type=float, default=0,
                   help="stop after this long live (default: until Ctrl-C)")
    w.set_defaults(fn=cmd_watch)

    ev = sub.add_parser("events", help="save the camera's motion clips, "
                                       "until Ctrl-C")
    ev.add_argument("--target", help=target_help)
    ev.add_argument("--on-path", action="store_true",
                    help="this host already carries the camera's traffic on "
                         "the camera's LAN interface (e.g. the lab): skip ARP "
                         "poisoning")
    ev.add_argument("--out", help="output directory (default captures/events-<time>)")
    ev.add_argument("--count", type=int, default=0,
                    help="stop after this many clips (default: until Ctrl-C)")
    ev.set_defaults(fn=cmd_events)

    c = sub.add_parser("cleanup", help="undo network changes left by a "
                                       "killed wyzecrack")
    c.set_defaults(fn=cmd_cleanup)

    e = sub.add_parser("extract", help="write a recording's video again, "
                                       "if that failed")
    e.add_argument("av_bin", help="a recording's directory or its av.bin")
    e.add_argument("outdir", nargs="?")
    e.set_defaults(fn=cmd_extract)

    a = ap.parse_args(argv)
    if a.cmd is None:
        a = ap.parse_args(["gui", *(argv or [])])
    if a.cmd != "extract":
        _sudo_reexec()
        _need_root_linux()
    try:
        return a.fn(a)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
