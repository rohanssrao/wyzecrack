"""Saving a camera's motion clips while the page is open.

For every motion alarm the camera uploads a snapshot and a 12 s clip to
Wyze over HTTPS (cloud.py). Copying them means routing the camera through
this host (onpath.py) and reading its HTTPS (cloud.CloudTap) for as long
as the capture runs; live views don't need either. The ENR travels with
the alarm upload too, so a capture also saves the key of a camera that
doesn't have one yet.

Each capture has its own scope of the page's journal, so starting and
stopping one never touches another camera's routing or a live view's
firewall rule.
"""
import threading


class MotionCapture:
    def __init__(self, journal, cam_ip, cam_mac, events_dir, on_event):
        self.journal, self.ip, self.mac = journal, cam_ip, cam_mac
        self.events_dir, self.on_event = events_dir, on_event
        self.scope = self.tap = self.onpath = None
        self._sleep_lock = None
        self._lock = threading.Lock()
        self.error = None

    @property
    def running(self):
        return self.tap is not None

    def start(self):
        """Route the camera through this host and read its uploads. Raises
        SystemExit (with a message) if it can't."""
        from .cli import _inhibit_sleep
        from .cloud import CloudTap
        from .netutil import iface_for
        from .onpath import OnPath
        with self._lock:
            if self.tap is not None:
                return
            self.scope = self.journal.scope()
            try:
                tap = CloudTap(self.scope, self.ip, port=0,
                               events_dir=self.events_dir,
                               on_event=self._event)
                tap.listen()
                self.onpath = OnPath(self.scope, self.ip, iface_for(self.ip),
                                     poison=True)
                # a suspended host black-holes the camera until it notices
                self._sleep_lock = _inhibit_sleep("saving motion clips")
                self.onpath.start()
                tap.start()
                self.tap = tap
            except BaseException:
                self._teardown()
                raise

    def _event(self, path):
        self._save_key()
        self.on_event(path)

    def _save_key(self):
        from .cli import _cache_enr
        tap = self.tap
        if tap and tap.enr_found.is_set() and tap.enr:
            _cache_enr(self.mac, tap.enr, **tap.device)

    def stop(self):
        with self._lock:
            self._save_key()
            self._teardown()

    def _teardown(self):
        from .changes import signals_held
        from .cli import _release_inhibitor
        for part in (self.tap, self.onpath):
            if part is None:
                continue
            try:
                part.stop() if part is self.tap else part.close()
            except Exception as e:  # noqa: BLE001
                print(f"[!] stopping the motion capture: {e!r}")
        if self.scope is not None:
            with signals_held():
                self.scope.undo_all()
        _release_inhibitor(self._sleep_lock)
        self._sleep_lock = None
        self.tap = self.onpath = self.scope = None
