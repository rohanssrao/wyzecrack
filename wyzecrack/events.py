"""A tiny publish/subscribe bus for what the tool is doing, so a front end
(the GUI) can follow along. The terminal output stays as it is."""
import threading
import time

_subs = []
_lock = threading.Lock()


def subscribe(fn):
    with _lock:
        _subs.append(fn)
    return lambda: unsubscribe(fn)


def unsubscribe(fn):
    with _lock:
        if fn in _subs:
            _subs.remove(fn)


def emit(kind, **data):
    """Publish an event: {"kind": ..., "t": unix time, **data}."""
    ev = {"kind": kind, "t": time.time(), **data}
    with _lock:
        subs = list(_subs)
    for fn in subs:
        try:
            fn(ev)
        except Exception:  # noqa: BLE001  (a subscriber must not break the tool)
            pass
    return ev
