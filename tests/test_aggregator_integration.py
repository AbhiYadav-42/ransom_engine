"""
Integration tests: the runner THREAD with plain queues (no filesystem watching).
Short ticks (0.05 s) and generous timeouts (10 s) so they are not flaky.
"""

import csv
import queue
import time

import pytest

from engine.aggregator import Aggregator, AggregatorRunner, csv_header
from engine.features_schema import FEATURE_NAMES, FeatureSchemaError
from engine.sensor import SensorEvent
from engine.inspection_worker import InspectionResult
from engine.inspector import FileInspection

WAIT_SECONDS = 10.0
TICK = 0.05
EPS_1S = FEATURE_NAMES.index("events_per_sec_1s")
ZEROS = [0.0] * len(FEATURE_NAMES)


def real_event(event_type="created", path="/sb/a.txt"):
    # Real clock, because the runner uses time.monotonic() too.
    return SensorEvent(timestamp=time.monotonic(), event_type=event_type, src_path=path,
                       dest_path=None, is_directory=False, extension_changed=False)


def make_runner(input_queue, csv_path=None):
    return AggregatorRunner(Aggregator(windows_style=False), input_queue,
                            tick_seconds=TICK, csv_path=csv_path)


def collect_rows(output_queue, done, timeout=WAIT_SECONDS):
    rows = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            rows.append(output_queue.get(timeout=0.1))
        except queue.Empty:
            continue
        if done(rows):
            break
    return rows


def test_runner_turns_queue_events_into_rows():
    input_queue = queue.Queue()
    runner = make_runner(input_queue)
    runner.start()
    try:
        for i in range(5):
            input_queue.put(real_event("created", "/sb/f%d.txt" % i))
        rows = collect_rows(runner.output_queue,
                            lambda found: any(r.values[EPS_1S] > 0 for r in found))
    finally:
        finished = runner.stop()
    assert any(r.values[EPS_1S] > 0 for r in rows)
    assert finished is True


def test_runner_emits_zero_rows_when_idle():
    runner = make_runner(queue.Queue())
    runner.start()
    try:
        rows = collect_rows(runner.output_queue, lambda found: len(found) >= 3)
    finally:
        runner.stop()
    assert len(rows) >= 3
    assert all(r.to_vector() == ZEROS for r in rows)
    assert all(r.source_key == "global" for r in rows)


def test_runner_stop_is_clean_and_repeatable():
    runner = make_runner(queue.Queue())
    runner.start()
    try:
        assert runner.is_running() is True
        with pytest.raises(RuntimeError):
            runner.start()                      # starting twice is refused
    finally:
        finished = runner.stop()
    assert finished is True
    assert runner.is_running() is False
    assert runner.stop() is True                # second stop() is harmless


def test_runner_writes_csv_rows(tmp_path):
    path = tmp_path / "features.csv"
    runner = make_runner(queue.Queue(), csv_path=path)
    runner.start()
    try:
        collect_rows(runner.output_queue, lambda found: len(found) >= 2)
    finally:
        runner.stop()                            # the thread closes the file when it ends
    with open(path, newline="") as handle:
        lines = list(csv.reader(handle))
    assert lines[0] == csv_header()
    assert len(lines) >= 3                       # header + at least 2 rows


def test_runner_survives_a_bad_event():
    input_queue = queue.Queue()
    runner = make_runner(input_queue)
    runner.start()
    try:
        input_queue.put(object())                # not a SensorEvent: processing raises
        deadline = time.monotonic() + WAIT_SECONDS
        while time.monotonic() < deadline and runner.get_stats()["event_errors"] < 1:
            time.sleep(0.05)
        rows = collect_rows(runner.output_queue, lambda found: len(found) >= 2)
        errors = runner.get_stats()["event_errors"]
    finally:
        runner.stop()
    assert errors >= 1
    assert len(rows) >= 2                        # the thread kept running


def test_runner_refuses_a_csv_with_the_wrong_header(tmp_path):
    path = tmp_path / "old.csv"
    path.write_text("a,b\n")
    runner = make_runner(queue.Queue(), csv_path=path)
    with pytest.raises(FeatureSchemaError):
        runner.start()
    assert runner.is_running() is False



INSPECTED = FEATURE_NAMES.index("files_inspected")


def test_runner_feeds_the_inspection_queue_into_rows():
    input_queue = queue.Queue()
    inspection_queue = queue.Queue()
    runner = AggregatorRunner(Aggregator(windows_style=False), input_queue,
                              tick_seconds=TICK, inspection_queue=inspection_queue)
    runner.start()
    try:
        event = real_event("modified", "/sb/a.bin")
        inspection = FileInspection(path="/sb/a.bin", status="ok", timestamp=time.monotonic(),
                                    bytes_sampled=65536, entropy=7.9, chi_square=255.0,
                                    null_fraction=0.004)
        inspection_queue.put(InspectionResult(event, inspection))
        rows = collect_rows(runner.output_queue,
                            lambda found: any(r.values[INSPECTED] >= 1 for r in found))
    finally:
        finished = runner.stop()
    assert any(r.values[INSPECTED] >= 1 for r in rows)
    assert finished is True


def test_runner_calls_the_event_hook_for_every_event():
    input_queue = queue.Queue()
    seen = []
    runner = AggregatorRunner(Aggregator(windows_style=False), input_queue,
                              tick_seconds=TICK, event_hook=seen.append)
    runner.start()
    try:
        for i in range(3):
            input_queue.put(real_event("created", "/sb/f%d.txt" % i))
        deadline = time.monotonic() + WAIT_SECONDS
        while time.monotonic() < deadline and len(seen) < 3:
            time.sleep(0.05)
    finally:
        runner.stop()
    assert len(seen) == 3