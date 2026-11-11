"""Tests for the inspection worker: budget logic with fakes, plus real-thread checks."""

import os
import queue
import time

from engine.inspection_worker import InspectionResult, InspectionWorker
from engine.inspector import FileInspection, Inspector
from engine.sensor import SensorEvent


class FakeClock:
    def __init__(self, start=100.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeInspector:
    """Records what the worker asks for; never touches the disk."""

    def __init__(self, status="ok"):
        self.calls = []
        self.status = status

    def inspect(self, path):
        self.calls.append(("inspect", path))
        return FileInspection(path=path, status=self.status, timestamp=1.0)

    def forget(self, path):
        self.calls.append(("forget", path))

    def move(self, src_path, dest_path):
        self.calls.append(("move", src_path, dest_path))


class ExplodingOnceInspector(FakeInspector):
    def inspect(self, path):
        if not self.calls:
            self.calls.append(("inspect", path))
            raise RuntimeError("boom")
        return super().inspect(path)


def make_event(event_type="modified", path="/sb/a.bin", dest_path=None, is_directory=False):
    return SensorEvent(timestamp=time.monotonic(), event_type=event_type, src_path=path,
                       dest_path=dest_path, is_directory=is_directory, extension_changed=False)


def make_worker(inspector=None, clock=None, **kwargs):
    if inspector is None:
        inspector = FakeInspector()
    if clock is None:
        clock = FakeClock()
    kwargs.setdefault("settle_seconds", 0.0)
    return InspectionWorker(inspector, clock=clock, **kwargs)


def test_submit_ignores_directories_and_other_event_types():
    worker = make_worker()
    assert worker.submit(make_event("modified", "/sb", is_directory=True)) is False
    assert worker.submit(make_event("exploded")) is False
    assert worker.submit(make_event("created")) is True
    assert worker.get_stats()["submitted"] == 1


def test_submit_counts_a_full_queue():
    worker = make_worker(max_pending=1)
    assert worker.submit(make_event("created", "/sb/a.bin")) is True
    assert worker.submit(make_event("created", "/sb/b.bin")) is False
    assert worker.get_stats()["skipped_queue_full"] == 1


def test_handle_event_inspects_a_modified_file():
    inspector = FakeInspector()
    worker = make_worker(inspector)
    event = make_event("modified", "/sb/a.bin")
    worker.handle_event(event)
    result = worker.output_queue.get_nowait()
    assert isinstance(result, InspectionResult)
    assert result.event is event
    assert result.inspection.status == "ok"
    assert inspector.calls == [("inspect", "/sb/a.bin")]
    assert worker.get_stats()["inspected"] == 1


def test_budget_skips_extra_files_in_the_same_tick():
    worker = make_worker(max_files_per_tick=2, tick_seconds=1.0)
    for i in range(5):
        worker.handle_event(make_event("modified", "/sb/f%d.bin" % i))
    stats = worker.get_stats()
    assert stats["inspected"] == 2
    assert stats["skipped_budget"] == 3
    assert worker.output_queue.qsize() == 2


def test_budget_resets_on_the_next_tick():
    clock = FakeClock()
    worker = make_worker(clock=clock, max_files_per_tick=2, tick_seconds=1.0)
    for i in range(3):
        worker.handle_event(make_event("modified", "/sb/a%d.bin" % i))
    clock.advance(1.0)
    for i in range(2):
        worker.handle_event(make_event("modified", "/sb/b%d.bin" % i))
    stats = worker.get_stats()
    assert stats["inspected"] == 4
    assert stats["skipped_budget"] == 1


def test_deleted_event_only_forgets():
    inspector = FakeInspector()
    worker = make_worker(inspector, max_files_per_tick=1)
    worker.handle_event(make_event("deleted", "/sb/a.bin"))
    assert inspector.calls == [("forget", "/sb/a.bin")]
    assert worker.get_stats()["inspected"] == 0
    worker.handle_event(make_event("modified", "/sb/b.bin"))     # budget was not used up
    assert worker.get_stats()["inspected"] == 1


def test_moved_event_moves_the_cache_then_inspects_the_destination():
    inspector = FakeInspector()
    worker = make_worker(inspector)
    worker.handle_event(make_event("moved", "/sb/a.docx", dest_path="/sb/a.docx.locked"))
    assert inspector.calls == [("move", "/sb/a.docx", "/sb/a.docx.locked"),
                               ("inspect", "/sb/a.docx.locked")]


def test_status_counts_are_tracked():
    worker = make_worker(FakeInspector(status="locked"))
    worker.handle_event(make_event("modified"))
    stats = worker.get_stats()
    assert stats["status_locked"] == 1
    assert stats["status_ok"] == 0


def test_full_output_queue_is_counted():
    worker = make_worker(output_queue=queue.Queue(maxsize=1))
    worker.handle_event(make_event("modified", "/sb/a.bin"))
    worker.handle_event(make_event("modified", "/sb/b.bin"))
    assert worker.get_stats()["skipped_output_full"] == 1


# ----- real thread ----------------------------------------------------------
def test_worker_thread_inspects_submitted_files(tmp_path):
    path = tmp_path / "random.bin"
    path.write_bytes(os.urandom(65536))
    worker = InspectionWorker(Inspector(), settle_seconds=0.0)
    worker.start()
    try:
        worker.submit(make_event("created", str(path)))
        result = worker.output_queue.get(timeout=10.0)
    finally:
        finished = worker.stop()
    assert finished is True
    assert result.inspection.status == "ok"
    assert result.inspection.entropy > 7.98


def test_worker_thread_stop_is_clean_and_repeatable():
    worker = InspectionWorker(FakeInspector(), settle_seconds=0.0)
    worker.start()
    try:
        assert worker.is_running() is True
        try:
            worker.start()
            started_twice = True
        except RuntimeError:
            started_twice = False
    finally:
        finished = worker.stop()
    assert started_twice is False
    assert finished is True
    assert worker.is_running() is False
    assert worker.stop() is True


def test_worker_thread_survives_an_inspector_exception():
    worker = InspectionWorker(ExplodingOnceInspector(), settle_seconds=0.0)
    worker.start()
    try:
        worker.submit(make_event("modified", "/sb/first.bin"))     # makes the inspector raise
        worker.submit(make_event("modified", "/sb/second.bin"))    # must still be processed
        result = worker.output_queue.get(timeout=10.0)
        errors = worker.get_stats()["worker_errors"]
    finally:
        worker.stop()
    assert result.inspection.path == "/sb/second.bin"
    assert errors >= 1