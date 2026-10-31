"""
One small integration test group: real files in pytest's tmp_path, real watchdog.
Timeouts are generous (10 s) so a slow machine does not make tests flaky.
If a test fails on Windows, paste the output; event details may differ there.
"""

import queue
import time
from pathlib import Path

import pytest

from engine.sensor import FileSensor

WAIT_SECONDS = 10.0


def start_sensor(sandbox, ignore_paths=(), dedup_window=0.05):
    sensor = FileSensor([sandbox], ignore_paths=ignore_paths, dedup_window=dedup_window)
    sensor.start()
    time.sleep(0.3)   # small warm-up so the OS watch is surely active before we touch files
    return sensor


def collect_until(event_queue, done, timeout=WAIT_SECONDS):
    """Read events until done(list_of_events) is True or the timeout passes."""
    collected = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            collected.append(event_queue.get(timeout=0.1))
        except queue.Empty:
            continue
        if done(collected):
            break
    return collected


def drain(event_queue):
    items = []
    while True:
        try:
            items.append(event_queue.get_nowait())
        except queue.Empty:
            return items


def has_event(events, event_type, name):
    return any(e.event_type == event_type and Path(e.src_path).name == name for e in events)


def test_create_modify_rename_delete_flow(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    sensor = start_sensor(sandbox)
    try:
        target = sandbox / "doc.txt"

        # create
        target.write_text("hello")
        events = collect_until(sensor.event_queue, lambda evs: has_event(evs, "created", "doc.txt"))
        assert has_event(events, "created", "doc.txt")

        # modify (wait longer than the de-dup window first, and throw away leftovers)
        time.sleep(0.4)
        drain(sensor.event_queue)
        with open(target, "a") as f:
            f.write(" more")
        events = collect_until(sensor.event_queue, lambda evs: has_event(evs, "modified", "doc.txt"))
        assert has_event(events, "modified", "doc.txt")

        # rename with a new extension
        time.sleep(0.4)
        drain(sensor.event_queue)
        renamed = sandbox / "doc.txt.locked"
        target.rename(renamed)
        events = collect_until(sensor.event_queue, lambda evs: any(e.event_type == "moved" for e in evs))
        moved = [e for e in events if e.event_type == "moved"]
        assert moved, "no 'moved' event arrived"
        assert Path(moved[0].src_path).name == "doc.txt"
        assert Path(moved[0].dest_path).name == "doc.txt.locked"
        assert moved[0].extension_changed is True

        # delete
        time.sleep(0.4)
        drain(sensor.event_queue)
        renamed.unlink()
        events = collect_until(sensor.event_queue, lambda evs: has_event(evs, "deleted", "doc.txt.locked"))
        assert has_event(events, "deleted", "doc.txt.locked")
    finally:
        sensor.stop()


def test_ignored_folder_produces_no_events(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    ignored = sandbox / "_ignored"
    ignored.mkdir()
    sensor = start_sensor(sandbox, ignore_paths=[ignored])
    try:
        (ignored / "secret.txt").write_text("x")      # should be invisible
        (sandbox / "visible.txt").write_text("x")     # should be seen
        # Events arrive in order, so once "visible" shows up, "secret" would already have.
        events = collect_until(sensor.event_queue, lambda evs: has_event(evs, "created", "visible.txt"))
        assert has_event(events, "created", "visible.txt")
        time.sleep(0.5)
        events += drain(sensor.event_queue)
        for e in events:
            path = Path(e.src_path)
            assert path.name not in ("secret.txt", "_ignored")
            assert path.parent.name != "_ignored"
        assert sensor.get_stats()["ignored"] >= 1
    finally:
        sensor.stop()


def test_burst_of_created_files_all_arrive(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    sensor = start_sensor(sandbox)
    count = 50
    try:
        for i in range(count):
            (sandbox / ("burst_%d.txt" % i)).write_text("x")

        def all_created(evs):
            names = {Path(e.src_path).name for e in evs if e.event_type == "created"}
            return len(names) >= count

        events = collect_until(sensor.event_queue, all_created)
        names = {Path(e.src_path).name for e in events if e.event_type == "created"}
        assert len(names) == count
    finally:
        sensor.stop()


def test_start_twice_and_stop_twice(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    sensor = FileSensor([sandbox])
    sensor.start()
    try:
        assert sensor.is_running() is True
        with pytest.raises(RuntimeError):
            sensor.start()
    finally:
        finished = sensor.stop()
    assert finished is True
    assert sensor.is_running() is False
    assert sensor.stop() is True    # second stop() is harmless


def test_missing_folder_raises(tmp_path):
    sensor = FileSensor([tmp_path / "does_not_exist"])
    with pytest.raises(FileNotFoundError):
        sensor.start()