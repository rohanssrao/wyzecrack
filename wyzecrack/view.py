"""A live view of one camera, for the page and `watch`: direct sessions
(direct.py) one after another for as long as it is watched, reconnecting
when the camera hangs up, all recorded into one av.bin."""
import os
import time

from . import keys
from .changes import keep_awake, signals_held
from .direct import CameraGone, Direct, open_firewall, open_first
from .live import LiveAssembler
from .netutil import local_ip_for

# sessions in a row without a picture before the view gives up
RETRIES = 3


def watch(journal, ip, mac, enr, uid, av_log, stop, seconds=None,
          on_video=None, on_audio=None, on_status=None):
    """Watch the camera until `stop` is set, or for `seconds` once it went
    live. Pictures go to on_video(live.Frame), sound to on_audio(t, pcm);
    on_status(kind, **info) hears "connecting", "live" (after, tries),
    "retry" (hung_up: whether the camera had sent a picture) and "gave_up"
    (when the camera doesn't answer)."""
    status = on_status or (lambda kind, **info: None)
    debug = os.environ.get("WYZECRACK_DEBUG")
    end = None
    failures, any_picture = 0, False
    release = keep_awake("showing a live view")
    try:
        while not stop.is_set() and (end is None or time.monotonic() < end):
            status("connecting")
            scope = journal.scope()          # this session's firewall rule
            framing = keys.cached(mac).get("framing")
            pictures = 0

            def make(ev, scope=scope, framing=framing):
                d = Direct(ip, uid, enr, mac, local_ip=local_ip_for(ip),
                           stop=ev, framing=framing)
                open_firewall(scope, ip, d.port)
                return d

            def picture(frame):
                nonlocal pictures
                pictures += 1
                if on_video:
                    on_video(frame)

            live = LiveAssembler(on_video=picture, on_audio=on_audio)
            d, why = None, ""
            try:
                t0 = time.monotonic()
                d = open_first(make, stop=stop, av_log=av_log, on_av=live.feed)
                keys.save(mac, framing=d.framing)
                print(f"[+] live from {ip} after {time.monotonic() - t0:.1f} s"
                      + (f" ({d.tries} sessions tried)" if d.tries > 1 else ""))
                status("live", after=time.monotonic() - t0, tries=d.tries)
                if seconds and end is None:
                    end = time.monotonic() + seconds
                tick = time.monotonic() + 5
                while not stop.is_set() and (end is None or time.monotonic() < end):
                    d.pump(0.3)
                    if debug and time.monotonic() >= tick:
                        print(f"[d] {time.strftime('%T')} rx {d.stats['rx']} "
                              f"ignored {d.stats['ignored']} tx {d.stats['tx']}")
                        tick += 5
            except (CameraGone, ValueError, OSError) as e:
                # ValueError: a DTLS handshake that went wrong; OSError: no
                # route (the host's network is still coming up)
                why = str(e)
                print(f"[!] {e}")
            finally:
                if d:
                    if debug:
                        print(f"[d] session ({d.framing} framing): {d.stats}")
                    d.close()
                with signals_held():
                    scope.undo_all()
            any_picture = any_picture or pictures > 0
            if not why or stop.is_set() or (end and time.monotonic() >= end):
                break                    # stopped, or the seconds are up
            failures = 0 if pictures else failures + 1
            # no answer at all to a first try: switched off, offline, or a
            # new key; trying again won't change that
            if failures >= RETRIES or ("(discovery)" in why and not any_picture):
                status("gave_up")
                break
            status("retry", hung_up=pictures > 0)
            stop.wait(1.5)
    finally:
        release()
