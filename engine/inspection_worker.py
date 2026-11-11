"""
engine/inspection_worker.py -- Stage 4: runs file inspections OFF the other threads.

Why a separate thread: reading files is slow compared with counting events.
It must never run inside the watchdog callback or the aggregator's tick.

LOAD CONTROL (what gets skipped, and where it is counted)
    * pending queue is bounded (max_pending): when full, submit() drops the new
      event             -> stats["skipped_queue_full"]
    * at most max_files_per_tick inspections per tick_seconds; further events in
      that tick are dropped -> stats["skipped_budget"]
    * unreadable files    -> status_locked / status_missing / status_too_small / ...
    Under a burst the EARLIEST files of each tick get inspected; later ones are
    skipped. Each inspection reads at most sample_bytes, so file size never matters.

WHY "SETTLE": Stage 2 drops repeated 'modified' events within 0.25 s of the first.
If we read a file the instant the first event arrives, the writer may not be done
(we would see an empty or half-written file) and the later events are gone. So the
worker waits until the event is settle_seconds old (default 0.3 s) before reading.
"""

import queue
import threading
import time
from dataclasses import dataclass

from engine.inspector import FileInspection

STATUS_NAMES = ("ok", "too_small", "locked", "missing", "not_a_file", "error")
SUBMIT_EVENT_TYPES = ("created", "modified", "moved", "deleted")


@dataclass(frozen=True)
class InspectionResult:
    event: object                 # the SensorEvent that triggered the inspection
    inspection: FileInspection


class InspectionWorker:
    def __init__(self, inspector, output_queue=None, max_pending=1000, max_files_per_tick=50,
                 tick_seconds=1.0, settle_seconds=0.3, clock=time.monotonic):
        if max_files_per_tick < 1 or tick_seconds <= 0 or max_pending < 1:
            raise ValueError("max_files_per_tick, tick_seconds and max_pending must be positive")
        self._inspector = inspector
        self.output_queue = output_queue if output_queue is not None else queue.Queue()
        self._pending = queue.Queue(maxsize=max_pending)
        self._max_files_per_tick = max_files_per_tick
        self._tick = tick_seconds
        self._settle = settle_seconds
        self._clock = clock
        self._interval_start = clock()
        self._used = 0
        self._thread = None
        self._stop_event = threading.Event()
        self.stats = {"submitted": 0, "skipped_queue_full": 0, "skipped_budget": 0,
                      "skipped_output_full": 0, "inspected": 0, "worker_errors": 0}
        self.status_counts = dict((name, 0) for name in STATUS_NAMES)
        self.last_error = None

    # --- called from the aggregator thread: must be fast and must never block ---
    def submit(self, event):
        """Queue an event for inspection. Returns True if accepted."""
        if event.is_directory or event.event_type not in SUBMIT_EVENT_TYPES:
            return False
        try:
            self._pending.put_nowait(event)
        except queue.Full:
            self.stats["skipped_queue_full"] += 1
            return False
        self.stats["submitted"] += 1
        return True

    # --- the actual work for ONE event (public so tests can call it without a thread) ---
    def handle_event(self, event):
        if event.event_type == "deleted":
            self._inspector.forget(event.src_path)       # no file to read; costs no budget
            return

        now = self._clock()
        if now - self._interval_start >= self._tick:     # a new tick: refill the budget
            self._interval_start = now
            self._used = 0

        if event.event_type == "moved":
            self._inspector.move(event.src_path, event.dest_path)   # history follows the file
            path = event.dest_path
        else:
            path = event.src_path

        if self._used >= self._max_files_per_tick:
            self.stats["skipped_budget"] += 1
            return
        self._used += 1

        inspection = self._inspector.inspect(path)
        self.stats["inspected"] += 1
        self.status_counts[inspection.status] = self.status_counts.get(inspection.status, 0) + 1
        try:
            self.output_queue.put_nowait(InspectionResult(event, inspection))
        except queue.Full:
            self.stats["skipped_output_full"] += 1

    # --- thread control ---
    def start(self):
        if self.is_running():
            raise RuntimeError("InspectionWorker is already running")
        self._stop_event.clear()
        self._interval_start = self._clock()
        self._used = 0
        self._thread = threading.Thread(target=self._run, name="inspection-worker", daemon=True)
        self._thread.start()

    def stop(self, timeout=5.0):
        """True if the thread ended cleanly. Waits for an inspection in progress (<= 64 KB read)."""
        thread = self._thread
        if thread is None:
            return True
        self._stop_event.set()
        thread.join(timeout)
        finished = not thread.is_alive()
        if finished:
            self._thread = None
        return finished

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def get_stats(self):
        stats = dict(self.stats)
        for name, count in self.status_counts.items():
            stats["status_" + name] = count
        stats["pending"] = self._pending.qsize()
        return stats

    def _run(self):
        while not self._stop_event.is_set():
            try:
                event = self._pending.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                wait = (event.timestamp + self._settle) - self._clock()
                if wait > 0 and self._stop_event.wait(wait):   # True means stop() was called
                    break
                self.handle_event(event)
            except Exception as error:         # one bad event must not kill the worker
                self.stats["worker_errors"] += 1
                self.last_error = repr(error)