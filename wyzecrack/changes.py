"""Every change this tool makes to the host, undoable and crash-safe.

Each change (an iptables rule, an ip rule/route, a sysctl, the ARP lie)
is recorded as data in a journal file before it is made, so that:

- teardown undoes exactly what was done, in reverse order, with SIGINT,
  SIGTERM and SIGHUP held off until it finishes (a second Ctrl-C cannot
  cut it short), and with the undo commands in their own session so a
  terminal's Ctrl-C never reaches them;
- after a crash, SIGKILL or power loss, `wyzecrack cleanup` (and the
  next run, before it starts) replays the journal.

One instance at a time: the journal directory is guarded by an flock.
Within that instance, parts that come and go independently (the page's
live views and motion captures, each camera's on-path routing) each take a
scope() of the one journal, and undo only what they did. A sysctl that two
parts set is shared: the first part's saved value is kept, and it is put
back when the last part that needs it is done.
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

RUN_DIR = Path(os.environ.get("WYZECRACK_RUN", "/run/wyzecrack"))
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
    if kind == "ipt":
        r = run(["iptables", "-w", *item["args"]])
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
        self._holders = {}       # sysctl item token -> tokens that need it
        self._alias = {}         # sharing token -> the item token it shares

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
            raise SystemExit("another wyzecrack is already running "
                             "(only one runs at a time)")
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
                                 "`wyzecrack cleanup` again")
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

    def _release(self, tokens):
        """The item tokens these tokens free: a shared sysctl only once its
        last holder lets go."""
        free = set()
        for t in tokens:
            real = self._alias.pop(t, t)
            holders = self._holders.get(real)
            if holders is not None:
                holders.discard(t)
                if holders:
                    continue
                del self._holders[real]
            free.add(real)
        return free

    def undo(self, tokens):
        """Undo these changes, newest first. One that cannot be undone
        stays in the journal (for `wyzecrack cleanup`) and is reported."""
        with self._lock, signals_held():
            tokens = self._release(tokens)
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
            tokens = self._release(tokens)
            self.items = [(t, i) for t, i in self.items if t not in tokens]
            self._save()

    def undo_all(self):
        with self._lock:
            self._holders.clear()
            self._alias.clear()
            self.undo([t for t, _ in self.items])

    def scope(self):
        return Scope(self)

    # -- helpers for the common changes ----------------------------------
    def _share(self, path):
        """A token sharing the journal's entry for this sysctl, or None."""
        for tok, item in self.items:
            if item["kind"] == "sysctl" and item["path"] == str(path):
                self._holders.setdefault(tok, {tok})
                alias = self._next
                self._next += 1
                self._holders[tok].add(alias)
                self._alias[alias] = tok
                return alias
        return None

    def sysctl(self, path, value):
        """Set a sysctl, recording its old value (or sharing the entry of a
        part of this run that set it first)."""
        p = Path(path)
        with self._lock:
            tok = self._share(p)
            if tok is None:
                old = p.read_text().strip()
                tok = self.add("sysctl", path=str(p), value=old)
                self._holders[tok] = {tok}
            p.write_text(f"{value}\n")
            return tok

    def remember_sysctl(self, path):
        """Record a sysctl's current value so it is restored, without
        changing it (for values the kernel changes as a side effect)."""
        p = Path(path)
        with self._lock:
            tok = self._share(p)
            if tok is None:
                tok = self.add("sysctl", path=str(p), value=p.read_text().strip())
                self._holders[tok] = {tok}
            return tok


class Scope:
    """One part of a run in the run's journal (Changes.scope()). It has the
    journal's interface, but undo_all() undoes only this part's changes,
    and acquire()/release() are the owner's business."""

    def __init__(self, parent):
        self.parent = parent
        self.tokens = []
        self._lock = threading.Lock()

    def _keep(self, tok):
        with self._lock:
            self.tokens.append(tok)
        return tok

    def add(self, kind, **item):
        return self._keep(self.parent.add(kind, **item))

    def sysctl(self, path, value):
        return self._keep(self.parent.sysctl(path, value))

    def remember_sysctl(self, path):
        return self._keep(self.parent.remember_sysctl(path))

    def _drop(self, tokens):
        tokens = set(tokens)
        with self._lock:
            self.tokens = [t for t in self.tokens if t not in tokens]

    def undo(self, tokens):
        tokens = list(tokens)
        self.parent.undo(tokens)
        self._drop(tokens)

    def forget(self, tokens):
        tokens = list(tokens)
        self.parent.forget(tokens)
        self._drop(tokens)

    def undo_all(self):
        self.undo(list(self.tokens))

    def acquire(self):
        pass

    def release(self):
        pass


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
