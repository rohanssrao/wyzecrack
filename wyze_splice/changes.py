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
    """Defer SIGINT/SIGTERM/SIGHUP until the block ends, then deliver them.
    Done with handlers rather than the signal mask: a process-directed
    signal goes to any thread that has it unblocked, and Python then
    raises it in the main thread anyway. Main thread only; elsewhere (and
    when nested) it is a no-op."""
    if (threading.current_thread() is not threading.main_thread()
            or getattr(_held, "on", False)):
        yield
        return
    pending = []
    old = {sig: signal.signal(sig, lambda n, f: pending.append(n))
           for sig in _SIGNALS}
    _held.on = True
    try:
        yield
    finally:
        _held.on = False
        for sig, h in old.items():
            signal.signal(sig, h)
        for sig in dict.fromkeys(pending):
            signal.raise_signal(sig)


_held = threading.local()


# errors that mean the thing to undo is already gone
_GONE = ("does not exist", "Bad rule", "No chain", "No such file",
         "No such process", "Cannot find")


def _undo(item):
    """Undo one change; raises RuntimeError if it could not be undone."""
    kind = item["kind"]
    if kind in ("ipt", "ip"):
        argv = (["iptables", "-w", *item["args"]] if kind == "ipt"
                else ["ip", *item["args"]])
        r = run(argv)
        if r.returncode and not any(g in r.stderr for g in _GONE):
            raise RuntimeError(r.stderr.strip() or f"exit {r.returncode}")
    elif kind == "sysctl":
        p = Path(item["path"])
        if p.exists():            # an interface may be gone by now
            p.write_text(item["value"] + "\n")
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
            left = replay(stale)
            if left:
                self.path.write_text(json.dumps(left, indent=1))
                raise SystemExit("some changes could not be undone (see "
                                 "above); fix that, then run "
                                 "`wyze-splice cleanup` again")
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
        """Undo these changes, newest first. One that cannot be undone
        stays in the journal (for `wyze-splice cleanup`) and is reported."""
        tokens = set(tokens)
        with self._lock, signals_held():
            for tok, item in reversed(list(self.items)):
                if tok not in tokens:
                    continue
                try:
                    _undo(item)
                except Exception as e:  # noqa: BLE001
                    print(f"[!] could not undo {DESCRIBE[item['kind']](item)}: {e}")
                    continue
                self.items = [(t, i) for t, i in self.items if t != tok]
                self._save()
            if not self.items:
                self.path.unlink(missing_ok=True)

    def forget(self, tokens):
        """Drop journal entries without undoing them (for changes that
        turned out not to have been made by us)."""
        with self._lock:
            self.items = [(t, i) for t, i in self.items if t not in set(tokens)]
            self._save()

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
    """Undo journal items newest first; returns those that failed (in
    journal order)."""
    failed = []
    with signals_held():
        for item in reversed(items):
            try:
                _undo(item)
                print(f"    undone: {DESCRIBE[item['kind']](item)}")
            except Exception as e:  # noqa: BLE001
                print(f"[!] could not undo {DESCRIBE.get(item.get('kind'), str)(item)}: {e}")
                failed.insert(0, item)
    return failed
