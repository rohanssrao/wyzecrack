"""A camera's key (ENR) and P2P ID (UID), read once and kept in
enr.json in wyzecrack's data directory (files.data_dir), by camera MAC.

The ENR comes off the camera's own HTTPS while the camera is routed
through this host (onpath.Reroute); on the models it was tried on,
nudge.py resets the camera's MQTT connection so that it reports in with it
right away. The UID comes from Wyze's device API, asked with the camera's
MAC and ENR (cloud.fetch_uid).
"""
import json
import time

from .files import data_dir, mac_key, write_json

# firmware to quote to Wyze when the camera's own report didn't say
DEFAULT_FW = "4.36.17.21"


def _load():
    try:
        return json.loads((data_dir() / "enr.json").read_text())
    except (OSError, ValueError):
        return {}


def _store(d):
    write_json(data_dir() / "enr.json", d, mode=0o600)


def cached(mac):
    """What is known of the camera: "enr", "uid", "model", "fw", "hw" and
    "framing" (the packet framing it speaks)."""
    return _load().get(mac_key(mac)) or {}


def save(mac, **fields):
    """Remember these fields for the camera (empty ones are left out)."""
    d = _load()
    old = d.get(mac_key(mac), {})
    new = {**old, **{k: v for k, v in fields.items() if v}}
    if new != old:
        d[mac_key(mac)] = new
        _store(d)


def forget_enr(mac):
    """Drop a camera's ENR, for a camera that was set up again in the Wyze
    app; it is read again next time. The UID stays: it is the camera's for
    life, while the ENR (and so the AuthKey that signs every packet)
    changes with each setup."""
    d = _load()
    entry = d.get(mac_key(mac))
    if entry:
        for k in ("enr", "framing"):
            entry.pop(k, None)
        _store(d)


def camera_key(journal, ip, mac, stop=None, on_step=None, events_dir=None,
               on_motion=None):
    """(enr, uid) for the camera: the saved ones, else its ENR read off its
    HTTPS (routing it through this host meanwhile, journaled in `journal`;
    motion clips it uploads then go to events_dir) and its UID from Wyze.
    None if `stop` was set first. on_step(step, status, detail) follows
    along: steps "enr" and "uid", statuses "active", "done" and "problem".
    Raises SystemExit with the reason it can't."""
    step = on_step or (lambda *a: None)
    enr = cached(mac).get("enr")
    if not enr:
        from .onpath import Reroute
        print("[*] first time with this camera: reading its key (ENR) off its "
              "own HTTPS, then its UID from Wyze")
        with Reroute(journal.scope(), ip, mac, events_dir=events_dir,
                     on_motion=on_motion) as r:
            enr = _wait_enr(r, stop, step)
        if not enr:
            return None
    step("enr", "done")
    uid = cached(mac).get("uid")
    if not uid:
        from .cloud import CloudError
        step("uid", "active")
        try:
            uid = uid_from_wyze(ip, mac, enr)
        except CloudError as e:
            step("uid", "problem")
            raise SystemExit(f"Wyze didn't hand out this camera's ID ({e}). "
                             f"Try again later.")
    step("uid", "done")
    return enr, uid


def _wait_enr(r, stop, step):
    """The rerouted camera's ENR, when it sends it (None if stopped). On
    the models it was tried on, its MQTT connection is reset meanwhile, so
    that it reports in now."""
    from .discover import TESTED_MODELS
    from .nudge import MqttNudge
    if _model(r.ip, r.mac, r.gateway) in TESTED_MODELS:
        nudge = MqttNudge(r.journal, r.ip, r.iface)
    else:
        nudge = None
    if nudge:
        print("[*] getting the camera's ENR: its connection to Wyze is reset "
              "a few times, which makes it report in (about a minute)")
        nudge.start()
    else:
        print("[*] waiting for the camera's ENR. It sends it at boot, on "
              "motion alarms, and in a report every 20 minutes or so")
    tap, start = r.tap, time.monotonic()
    shown = printed = None
    refused = told = False
    try:
        # the first look is at once: the page shows the step right away
        while not tap.enr_found.wait(1 if shown else 0):
            if stop is not None and stop.is_set():
                return None
            st = dict(tap.stats, resets=nudge.resets if nudge else 0)
            if st["tls_failed"] >= 3 and not st["intercepted"] and not refused:
                print("[!] the camera keeps refusing the eMudhra certificate: "
                      "this firmware may no longer trust that CA. Pass --enr "
                      "if you have the ENR some other way")
                refused = True
            if st != shown:
                step("enr", "problem" if refused else "active",
                     {"seen": st["intercepted"], "resets": st["resets"],
                      "nudging": bool(nudge and not nudge.failed)})
                shown = st
            if nudge and nudge.failed and not told:
                print(f"[!] {nudge.failed}; waiting for the camera to report in "
                      f"on its own")
                told = True
            if st != printed and time.monotonic() - start > 30:
                print(f"    camera HTTPS so far: {st['intercepted']} read, "
                      f"{st['passed']} passed through, {st['tls_failed']} "
                      f"refused our certificate")
                printed = st
    finally:
        if nudge:
            nudge.stop.set()
            nudge.thread.join(3)
    print(f"[+] ENR harvested from the camera's own HTTPS after "
          f"{time.monotonic() - start:.0f} s"
          + (f" and {nudge.resets} connection reset(s)" if nudge else ""))
    return tap.enr


def uid_from_wyze(ip, mac, enr):
    """Ask Wyze for the camera's UID with its ENR (see cloud.fetch_uid) and
    save both. Raises cloud.CloudError."""
    from .cloud import fetch_uid
    known = cached(mac)
    model = _model(ip, mac) or "WYZE_CAKP2JFUS"
    print("[*] asking Wyze for the camera's P2P UID, as the camera")
    uid = fetch_uid(mac, enr, model, known.get("fw") or DEFAULT_FW,
                    known.get("hw") or "0.0.0.0")
    print(f"[+] UID {uid}")
    save(mac, enr=enr, uid=uid)
    return uid


def _model(ip, mac, gateway=None):
    """The camera's model ID: as it reported it, else from its DHCP name."""
    from .discover import describe
    from .netutil import default_gateway, iface_for
    return (cached(mac).get("model")
            or describe(ip, mac, gateway or default_gateway(iface_for(ip))).get("model_id"))
