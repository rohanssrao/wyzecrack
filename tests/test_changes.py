"""The host-change journal: ordering, crash replay, single instance."""
import json
import tempfile
import unittest.mock
from pathlib import Path

import pytest

from wyze_splice import changes as ch


def test_undo_is_newest_first_and_journal_tracks_state(tmp_path):
    c = ch.Changes(tmp_path)
    p1, p2 = tmp_path / "a", tmp_path / "b"
    p1.write_text("0\n")
    p2.write_text("x\n")
    c.sysctl(p1, 1)
    c.remember_sysctl(p2)
    p2.write_text("changed\n")              # e.g. a kernel side effect
    c.add("ipt", args=["-t", "nat", "-D", "POSTROUTING", "-j", "X"])
    assert len(json.loads((tmp_path / "changes.json").read_text())) == 3
    with unittest.mock.patch.object(ch, "run") as run:
        c.undo_all()
    run.assert_called_once_with(["iptables", "-t", "nat", "-D", "POSTROUTING", "-j", "X"])
    assert p1.read_text() == "0\n" and p2.read_text() == "x\n"
    assert not (tmp_path / "changes.json").exists()


def test_a_crashed_runs_journal_is_replayed_by_the_next(tmp_path):
    p = tmp_path / "s"
    p.write_text("0\n")
    dead = ch.Changes(tmp_path)
    dead.sysctl(p, 1)                        # then "SIGKILL": no undo
    assert p.read_text() == "1\n"
    nxt = ch.Changes(tmp_path)
    nxt.acquire()
    assert p.read_text() == "0\n"
    assert not (tmp_path / "changes.json").exists()
    nxt.release()


def test_only_one_instance(tmp_path):
    a = ch.Changes(tmp_path)
    a.acquire()
    with pytest.raises(SystemExit):
        ch.Changes(tmp_path).acquire()
    a.release()
    b = ch.Changes(tmp_path)
    b.acquire()
    b.release()
