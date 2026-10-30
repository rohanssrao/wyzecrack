"""Every change this tool makes to the host, undoable and crash-safe.

Each change (an iptables rule, an ip rule/route, a sysctl, the ARP lie)
is recorded as data in a journal file before it is made, so that:

- teardown undoes exactly what was done, in reverse order, with SIGINT,
  SIGTERM and SIGHUP held off until it finishes (a second Ctrl-C cannot
  cut it short), and with the undo commands in their own session so a
  terminal's Ctrl-C never reaches them;
- after a crash, SIGKILL or power loss, `wyze-splice cleanup` (and the
  next run, before it starts) replays the journal.

One instance at a time: the journal directory is guarded by an flock.
"""
import contextlib
import fcntl
import json
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

RUN_DIR = Path(os.environ.get("WYZE_SPLICE_RUN", "/run/wyze-splice"))
_SIGNALS = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}


def run(argv, **kw):
    """subprocess.run in a new session: a terminal's Ctrl-C reaches only
    this tool, never the iptables/ip command it is waiting on."""
    return subprocess.run(argv, capture_output=True, text=True,
                          start_new_session=True, **kw)


@contextlib.contextmanager
def signals_held():
    """Defer SIGINT/SIGTERM/SIGHUP (main thread only) until the block ends."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    old = signal.pthread_sigmask(signal.SIG_BLOCK, _SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)


def _undo(item):
    kind = item["kind"]
    if kind == "ipt":
        run(["iptables", *item["args"]])
    elif kind == "ip":
        run(["ip", *item["args"]])
    elif kind == "sysctl":
        Path(item["path"]).write_text(item["value"] + "\n")
    elif kind == "arp":
        from . import rawnet
        frame = bytes.fromhex(item["frame"])
        for _ in range(5):
            try:
                with rawnet.open_raw(item["iface"]) as s:
                    s.send(frame)
            except OSError:
                pass
            time.sleep(0.2)


DESCRIBE = {
    "ipt": lambda i: "iptables " + " ".join(i["args"]),
    "ip": lambda i: "ip " + " ".join(i["args"]),
    "sysctl": lambda i: f"{i['path']} = {i['value']}",
    "arp": lambda i: f"restore the camera's ARP entry for its gateway ({i['iface']})",
}


class Changes:
    """The journal. add() records an undo action and returns a token;
    undo(tokens) or undo_all() reverts them, newest first."""

    def __init__(self, run_dir=RUN_DIR):
        self.dir = Path(run_dir)
        self.path = self.dir / "changes.json"
        self.items = []          # [(token, item)]
        self._next = 0
        self._lock = threading.RLock()
        self._lockf = None

    # -- locking ---------------------------------------------------------
    def acquire(self):
        """Take the single-instance lock, replaying any journal a dead
        predecessor left. Raises SystemExit if another instance runs."""
        self.dir.mkdir(parents=True, exist_ok=True)
        f = open(self.dir / "lock", "w")
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            f.close()
            raise SystemExit("another wyze-splice is already running "
                             "(only one can be the camera's router)")
        self._lockf = f
        stale = load(self.path)
        if stale:
            print(f"[*] undoing {len(stale)} change(s) left by a previous "
                  f"run that did not exit cleanly")
            replay(stale)
            self.path.unlink(missing_ok=True)

    def release(self):
        if self._lockf:
            self._lockf.close()
            self._lockf = None

    # -- journal ---------------------------------------------------------
    def _save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps([i for _, i in self.items], indent=1))
        os.replace(tmp, self.path)

    def add(self, kind, **item):
        with self._lock:
            item["kind"] = kind
            token = self._next
            self._next += 1
            self.items.append((token, item))
            self._save()
            return token

    def undo(self, tokens):
        tokens = set(tokens)
        with self._lock, signals_held():
            for tok, item in reversed(list(self.items)):
                if tok not in tokens:
                    continue
                try:
                    _undo(item)
                except Exception as e:  # noqa: BLE001
                    print(f"[!] could not undo {DESCRIBE[item['kind']](item)}: {e}")
                self.items = [(t, i) for t, i in self.items if t != tok]
                self._save()
            if not self.items:
                self.path.unlink(missing_ok=True)

    def undo_all(self):
        self.undo([t for t, _ in self.items])

    # -- helpers for the common changes ----------------------------------
    def sysctl(self, path, value):
        """Set a sysctl, recording its old value."""
        p = Path(path)
        old = p.read_text().strip()
        tok = self.add("sysctl", path=str(p), value=old)
        p.write_text(f"{value}\n")
        return tok

    def remember_sysctl(self, path):
        """Record a sysctl's current value so it is restored, without
        changing it (for values the kernel changes as a side effect)."""
        p = Path(path)
        return self.add("sysctl", path=str(p), value=p.read_text().strip())


def load(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return []


def replay(items):
    with signals_held():
        for item in reversed(items):
            try:
                _undo(item)
                print(f"    undone: {DESCRIBE[item['kind']](item)}")
            except Exception as e:  # noqa: BLE001
                print(f"[!] could not undo {DESCRIBE.get(item.get('kind'), str)(item)}: {e}")
