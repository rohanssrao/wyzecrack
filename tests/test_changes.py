"""The host-change journal: ordering, crash replay, single instance."""
import json
import unittest.mock

import pytest

from wyzecrack import changes as ch


def test_undo_is_newest_first_and_journal_tracks_state(tmp_path):
    c = ch.Changes(tmp_path)
    p1, p2 = tmp_path / "a", tmp_path / "b"
    p1.write_text("0\n")
    p2.write_text("x\n")
    c.sysctl(p1, 1)
    c.sysctl(p2)
    p2.write_text("changed\n")              # e.g. a kernel side effect
    c.add("ipt", args=["-t", "nat", "-D", "POSTROUTING", "-j", "X"])
    assert len(json.loads((tmp_path / "changes.json").read_text())) == 3
    with unittest.mock.patch.object(ch, "run") as run:
        run.return_value.returncode = 0
        c.undo_all()
    run.assert_called_once_with(["iptables", "-w", "-t", "nat", "-D", "POSTROUTING", "-j", "X"])
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


def test_an_undo_that_fails_stays_in_the_journal(tmp_path):
    c = ch.Changes(tmp_path)
    c.add("ipt", args=["-t", "nat", "-D", "POSTROUTING", "-j", "X"])
    c.add("ipt", args=["-t", "nat", "-D", "POSTROUTING", "-j", "Y"])
    def fake(argv, **kw):
        r = unittest.mock.Mock()
        r.returncode = 4 if argv[-1] == "X" else 1
        r.stderr = "xtables lock held" if argv[-1] == "X" else "Bad rule (does a matching rule exist?)"
        return r
    with unittest.mock.patch.object(ch, "run", side_effect=fake):
        c.undo_all()
    # Y was already gone (fine); X really failed and is kept for cleanup
    assert [i["args"][-1] for _, i in c.items] == ["X"]
    assert json.loads((tmp_path / "changes.json").read_text())[0]["args"][-1] == "X"


def test_signals_are_deferred_not_lost():
    import os, signal
    got = []
    old = signal.signal(signal.SIGTERM, lambda n, f: got.append("handled"))
    try:
        with ch.signals_held():
            os.kill(os.getpid(), signal.SIGTERM)
            got.append("block finished")
        assert got == ["block finished", "handled"]
    finally:
        signal.signal(signal.SIGTERM, old)


def test_scopes_undo_only_their_own_changes(tmp_path):
    c = ch.Changes(tmp_path)
    a, b = c.scope(), c.scope()
    with unittest.mock.patch.object(ch, "run") as run:
        run.return_value.returncode = 0
        a.add("ipt", args=["-D", "A"])
        b.add("ipt", args=["-D", "B"])
        a.undo_all()
        run.assert_called_once_with(["iptables", "-w", "-D", "A"])
        assert len(json.loads((tmp_path / "changes.json").read_text())) == 1
        b.undo_all()
    assert not (tmp_path / "changes.json").exists()


def test_a_sysctl_two_scopes_set_is_restored_by_the_last_one(tmp_path):
    c = ch.Changes(tmp_path)
    fwd, side = tmp_path / "ip_forward", tmp_path / "forwarding"
    fwd.write_text("0\n")
    side.write_text("0\n")
    a, b = c.scope(), c.scope()
    a.sysctl(side)
    a.sysctl(fwd, 1)
    side.write_text("1\n")                 # the kernel's side effect
    b.sysctl(side)                # b must not save the 1
    b.sysctl(fwd, 1)
    a.undo_all()                           # b still needs forwarding on
    assert fwd.read_text() == "1\n" and side.read_text() == "1\n"
    b.undo_all()
    assert fwd.read_text() == "0\n" and side.read_text() == "0\n"
    assert not (tmp_path / "changes.json").exists()


def test_the_owners_undo_all_restores_everything(tmp_path):
    c = ch.Changes(tmp_path)
    fwd = tmp_path / "ip_forward"
    fwd.write_text("0\n")
    c.scope().sysctl(fwd, 1)
    c.scope().sysctl(fwd, 1)
    c.undo_all()                           # e.g. the page quitting
    assert fwd.read_text() == "0\n"
