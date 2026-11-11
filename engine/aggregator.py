"""
engine/aggregator.py -- Stage 3 + Stage 4 features: the temporal aggregator.

WHAT THIS FILE DOES
    Reads SensorEvent objects (Stage 2's queue) and FileInspection results
    (Stage 4's worker), remembers the last few seconds of them in sliding
    windows, and every "tick" (default 1 s) produces one FeatureRow: a
    fixed-order list of numbers (the order lives in features_schema.py).

WHAT IT DELIBERATELY DOES NOT DO
    No file reading (the inspection worker does that), no ML, no killing
    processes, no alerts.

TWO LAYERS
    1. Aggregator       pure logic, no threads: process_event(), process_inspection(),
                        compute_features(now). Easy to test with a made-up "now".
    2. AggregatorRunner a thin background thread: get event -> process_event(),
                        drain inspection results, and every tick -> rows -> output
                        queue (+ optional CSV).

HONEST LIMITATIONS
    * It can only count events it receives. Events lost upstream (OS buffer
      overflow, Stage 2 filtering) are invisible here.
    * Windows are capped (max_events_per_second). In a huge burst the OLDEST
      records are evicted, so rates saturate and distinct counts under-count.
    * If the runner falls behind, a row can under-count the newest events.
    * Event timestamps come from Stage 2's time.monotonic(); "now" must come from
      the same clock in the same process.
    * Inspection features cover only files the worker managed to inspect
      (see files_inspected); skipped files are not in them.
    * files_inspected counts INSPECTIONS: a file changed repeatedly can count twice.
"""

import csv
import queue
import threading
import time
from collections import deque, namedtuple
from dataclasses import dataclass
from pathlib import Path

from engine.aggregator_windows import split_for_counting
from engine.features_schema import FEATURE_NAMES, FeatureSchemaError, to_vector

GLOBAL_KEY = "global"
# The feature NAMES contain "1s" / "5s", so these lengths are fixed constants.
# Changing them means new meaning -> new SCHEMA_VERSION -> retrain.
SHORT_WINDOW_SECONDS = 1.0
LONG_WINDOW_SECONDS = 5.0
DEFAULT_TICK_SECONDS = 1.0
DEFAULT_MAX_EVENTS_PER_SECOND = 20000
DEFAULT_MAX_SOURCES = 50
MAX_BLOCK_SECONDS = 0.2    # longest the runner waits on the queue, so stop() reacts quickly

# --- Stage 4 additions. These define what the inspection features MEAN:
# changing a default means new meaning -> new SCHEMA_VERSION -> retrain.
DEFAULT_HIGH_ENTROPY = 7.5      # bits per byte; at or above counts as "high entropy"
DEFAULT_ENTROPY_JUMP = 2.0      # entropy rise (bits) since the last inspection that counts as a jump
CHI_SQUARE_CLIP = 10000.0       # each file's chi-square is capped so one zero-filled file cannot swamp the mean
DEFAULT_MAX_INSPECTIONS = 5000  # memory cap of the inspection window
INSPECTION_BLOCK_SECONDS = 0.05  # runner wake-up interval when an inspection queue is attached
MAX_INSPECTIONS_PER_DRAIN = 1000


# ---------------------------------------------------------------------------
# 1. SlidingWindow
# ---------------------------------------------------------------------------
class SlidingWindow:
    """Keeps (timestamp, item) pairs, oldest on the left of a deque.
    An item stays while  age = now - timestamp  is LESS than window_seconds."""

    def __init__(self, window_seconds, max_items=100000):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if max_items < 1:
            raise ValueError("max_items must be at least 1")
        self.window_seconds = window_seconds
        self.max_items = max_items
        self.dropped_by_cap = 0         # how many OLD items were evicted because we were full
        self._entries = deque()

    def add(self, timestamp, item):
        # Add items in time order, so the oldest is always on the left.
        if len(self._entries) >= self.max_items:
            self._entries.popleft()     # memory safety: evict the oldest, never grow
            self.dropped_by_cap += 1
        self._entries.append((timestamp, item))

    def prune(self, now):
        while self._entries and (now - self._entries[0][0]) >= self.window_seconds:
            self._entries.popleft()

    def count(self):
        return len(self._entries)

    def __iter__(self):
        for _timestamp, item in self._entries:
            yield item


# ---------------------------------------------------------------------------
# 2. Small data holders
# ---------------------------------------------------------------------------
# What we remember about one event (small on purpose).
WindowRecord = namedtuple(
    "WindowRecord",
    ["event_type", "norm_path", "norm_dirs", "extension_changed", "is_directory"])

# What we remember about one successful inspection.
InspectionRecord = namedtuple(
    "InspectionRecord",
    ["entropy", "chi_square", "null_fraction", "is_high", "header_mismatch", "is_jump"])


@dataclass(frozen=True)
class FeatureRow:
    timestamp: float      # the "now" of the tick (time.monotonic() clock)
    source_key: str       # "global" for now; Stage 5 may use a PID-based key
    values: tuple         # floats in exactly FEATURE_NAMES order

    def to_vector(self):
        return list(self.values)

    def to_dict(self):
        return dict(zip(FEATURE_NAMES, self.values))


class _SourceState:
    """The windows that belong to ONE source key."""

    def __init__(self, max_events_per_second, max_inspections):
        self.window_1s = SlidingWindow(
            SHORT_WINDOW_SECONDS, int(max_events_per_second * SHORT_WINDOW_SECONDS))
        self.window_5s = SlidingWindow(
            LONG_WINDOW_SECONDS, int(max_events_per_second * LONG_WINDOW_SECONDS))
        self.window_inspections = SlidingWindow(LONG_WINDOW_SECONDS, max_inspections)


def _event_features(state):
    """The 9 Stage 3 features, from the event windows."""
    count_1s = state.window_1s.count()
    count_5s = state.window_5s.count()
    modified_events = 0
    renames = 0
    extension_changes = 0
    modified_files = set()
    touched_dirs = set()

    for record in state.window_5s:
        if record.event_type == "modified":
            modified_events += 1
            if not record.is_directory:
                modified_files.add(record.norm_path)
        elif record.event_type == "moved" and not record.is_directory:
            renames += 1                 # file moves only (folder moves also spawn child moves)
        if record.extension_changed:
            extension_changes += 1
        for directory in record.norm_dirs:
            touched_dirs.add(directory)

    modify_ratio = (modified_events / count_5s) if count_5s else 0.0
    return {
        "events_per_sec_1s": count_1s / SHORT_WINDOW_SECONDS,
        "events_per_sec_5s": count_5s / LONG_WINDOW_SECONDS,
        "distinct_files_modified": len(modified_files),
        "distinct_dirs_touched": len(touched_dirs),
        "rename_count": renames,
        "extension_change_count": extension_changes,
        "modify_ratio": modify_ratio,
        "canary_touched": 0,       # placeholder, filled by a later stage
        "backup_kill_cmd": 0,      # placeholder, filled by a later stage
    }


def _inspection_features(state):
    """The 8 Stage 4 features, from the inspection window. All 0 when nothing was inspected
    (files_inspected says which case it is)."""
    count = state.window_inspections.count()
    max_entropy = 0.0
    entropy_sum = 0.0
    chi_sum = 0.0
    max_null = 0.0
    high = 0
    mismatches = 0
    jumps = 0
    for record in state.window_inspections:
        max_entropy = max(max_entropy, record.entropy)
        entropy_sum += record.entropy
        chi_sum += record.chi_square
        max_null = max(max_null, record.null_fraction)
        if record.is_high:
            high += 1
        if record.header_mismatch:
            mismatches += 1
        if record.is_jump:
            jumps += 1
    return {
        "files_inspected": count,
        "max_entropy": max_entropy,
        "mean_entropy": (entropy_sum / count) if count else 0.0,
        "fraction_high_entropy": (high / count) if count else 0.0,
        "mean_chi_square": (chi_sum / count) if count else 0.0,
        "max_null_fraction": max_null,
        "header_mismatch_count": mismatches,
        "entropy_jump_count": jumps,
    }


def _features_from_state(state):
    features = _event_features(state)
    features.update(_inspection_features(state))
    return features


# ---------------------------------------------------------------------------
# 3. Aggregator: pure logic, no threads of its own
# ---------------------------------------------------------------------------
class Aggregator:
    def __init__(self, extra_key_func=None, max_events_per_second=DEFAULT_MAX_EVENTS_PER_SECOND,
                 max_sources=DEFAULT_MAX_SOURCES, windows_style=None,
                 high_entropy_threshold=DEFAULT_HIGH_ENTROPY,
                 entropy_jump_threshold=DEFAULT_ENTROPY_JUMP,
                 max_inspections=DEFAULT_MAX_INSPECTIONS):
        # extra_key_func(event) -> str lets you track a second key besides "global"
        # (a folder now, a PID in Stage 5). The aggregator never looks inside the key.
        self._extra_key_func = extra_key_func
        self._max_events_per_second = max_events_per_second
        self._max_sources = max_sources
        self._windows_style = windows_style   # None = this OS's rules; tests force True/False
        self._high_entropy_threshold = high_entropy_threshold
        self._entropy_jump_threshold = entropy_jump_threshold
        self._max_inspections = max_inspections
        self._lock = threading.Lock()
        self._states = {GLOBAL_KEY: self._new_state()}
        self._events_processed = 0
        self._inspections_processed = 0
        self._sources_refused = 0

    def process_event(self, event):
        """Remember one SensorEvent. Cheap: no disk, no printing."""
        record = self._make_record(event)
        keys = self._keys_for(event)
        with self._lock:
            self._events_processed += 1
            for key in keys:
                state = self._state_for(key)
                if state is None:
                    continue
                state.window_1s.add(event.timestamp, record)
                state.window_5s.add(event.timestamp, record)

    def process_inspection(self, event, inspection):
        """Remember one FileInspection (made because of `event`). Only status "ok" counts:
        a locked / missing / too-small file has no measurement."""
        if inspection.status != "ok":
            return
        record = InspectionRecord(
            entropy=inspection.entropy,
            chi_square=min(inspection.chi_square, CHI_SQUARE_CLIP),
            null_fraction=inspection.null_fraction,
            is_high=inspection.entropy >= self._high_entropy_threshold,
            header_mismatch=(inspection.ext_matches_header == 0),
            is_jump=(inspection.had_previous_entropy
                     and inspection.entropy_delta >= self._entropy_jump_threshold))
        keys = self._keys_for(event)
        with self._lock:
            self._inspections_processed += 1
            for key in keys:
                state = self._state_for(key)
                if state is None:
                    continue
                state.window_inspections.add(inspection.timestamp, record)

    def compute_features(self, now, source_key=GLOBAL_KEY):
        """One FeatureRow for one key. Unknown / idle key -> all zeros."""
        with self._lock:
            return self._build_row(now, source_key, self._states.get(source_key))

    def compute_all(self, now):
        """Rows for every key worth reporting: "global" ALWAYS (a heartbeat, zeros
        when idle), other keys only while they still have events or inspections
        in their windows."""
        with self._lock:
            rows = [self._build_row(now, GLOBAL_KEY, self._states[GLOBAL_KEY])]
            for key in sorted(self._states):
                if key == GLOBAL_KEY:
                    continue
                state = self._states[key]
                row = self._build_row(now, key, state)
                if state.window_5s.count() == 0 and state.window_inspections.count() == 0:
                    del self._states[key]          # went quiet: forget it (frees memory)
                else:
                    rows.append(row)
            return rows

    def get_stats(self):
        """Counters. Cap drops cover sources still being tracked."""
        with self._lock:
            return {
                "events_processed": self._events_processed,
                "inspections_processed": self._inspections_processed,
                "cap_drops_1s": sum(s.window_1s.dropped_by_cap for s in self._states.values()),
                "cap_drops_5s": sum(s.window_5s.dropped_by_cap for s in self._states.values()),
                "sources_tracked": len(self._states),
                "sources_refused": self._sources_refused,
            }

    # --- internals (callers already hold the lock where needed) -------------
    def _new_state(self):
        return _SourceState(self._max_events_per_second, self._max_inspections)

    def _keys_for(self, event):
        keys = [GLOBAL_KEY]
        if self._extra_key_func is not None:
            extra_key = self._extra_key_func(event)
            if extra_key and extra_key != GLOBAL_KEY:
                keys.append(extra_key)
        return keys

    def _state_for(self, key):
        """Find or create the state for a key (lock held). None if we track too many keys."""
        state = self._states.get(key)
        if state is None:
            if len(self._states) >= self._max_sources:
                self._sources_refused += 1
                return None
            state = self._new_state()
            self._states[key] = state
        return state

    def _make_record(self, event):
        norm_path, parent = split_for_counting(event.src_path, self._windows_style)
        directories = (parent,)
        if event.dest_path is not None:
            _norm_dest, dest_parent = split_for_counting(event.dest_path, self._windows_style)
            directories = (parent, dest_parent)
        return WindowRecord(event.event_type, norm_path, directories,
                            bool(event.extension_changed), bool(event.is_directory))

    def _build_row(self, now, source_key, state):
        if state is None:
            features = dict((name, 0.0) for name in FEATURE_NAMES)
        else:
            state.window_1s.prune(now)
            state.window_5s.prune(now)
            state.window_inspections.prune(now)
            features = _features_from_state(state)
        values = to_vector(features)    # fixes the column order (and checks it)
        return FeatureRow(timestamp=now, source_key=source_key, values=tuple(values))


# ---------------------------------------------------------------------------
# 4. CSV output (header always comes from FEATURE_NAMES)
# ---------------------------------------------------------------------------
def csv_header():
    return ["timestamp", "source_key"] + list(FEATURE_NAMES)


class FeatureCsvWriter:
    """New/empty file -> write the header from FEATURE_NAMES.
    Existing file -> its first line must equal that header, otherwise we REFUSE
    (appending rows with different columns would corrupt your training data)."""

    def __init__(self, path):
        self.path = Path(path)
        self._file = None
        self._writer = None

    def open(self):
        header = csv_header()
        has_data = self.path.exists() and self.path.stat().st_size > 0
        if has_data:
            with open(self.path, "r", newline="") as existing:
                first_line = next(csv.reader(existing), [])
            if first_line != header:
                raise FeatureSchemaError(
                    "%s has a different header than the current schema. Move or delete "
                    "the old file (or use a new path) before collecting new data." % self.path)
            self._file = open(self.path, "a", newline="")   # newline="" avoids blank lines on Windows
            self._writer = csv.writer(self._file)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(self.path, "w", newline="")
            self._writer = csv.writer(self._file)
            self._writer.writerow(header)
            self._file.flush()

    def write_row(self, row):
        self._writer.writerow([row.timestamp, row.source_key] + list(row.values))
        self._file.flush()       # at most one line per second, so flushing is cheap

    def close(self):
        if self._file is not None:
            self._file.close()
            self._file = None


# ---------------------------------------------------------------------------
# 5. AggregatorRunner: the thin thread wrapper
# ---------------------------------------------------------------------------
class AggregatorRunner:
    def __init__(self, aggregator, input_queue, output_queue=None,
                 tick_seconds=DEFAULT_TICK_SECONDS, csv_path=None, clock=time.monotonic,
                 inspection_queue=None, event_hook=None):
        if tick_seconds <= 0:
            raise ValueError("tick_seconds must be positive")
        self._aggregator = aggregator
        self._input = input_queue
        self.output_queue = output_queue if output_queue is not None else queue.Queue()
        self._tick = tick_seconds
        self._csv_path = csv_path
        self._csv = None
        self._clock = clock
        # Stage 4: results from the inspection worker, and a function called with every event
        # (it must be fast and never block, e.g. InspectionWorker.submit).
        self._inspection_queue = inspection_queue
        self._event_hook = event_hook
        self._thread = None
        self._stop_event = threading.Event()       # thread-safe stop flag
        self.stats = {"rows_emitted": 0, "rows_dropped_output_full": 0,
                      "event_errors": 0, "inspection_errors": 0,
                      "tick_errors": 0, "csv_errors": 0}
        self.last_error = None

    def start(self):
        if self.is_running():
            raise RuntimeError("AggregatorRunner is already running")
        self._stop_event.clear()
        if self._csv_path is not None:
            # Opened HERE (not in the thread) so a header mismatch raises in your face now.
            self._csv = FeatureCsvWriter(self._csv_path)
            self._csv.open()
        self._thread = threading.Thread(target=self._run, name="aggregator", daemon=True)
        self._thread.start()

    def stop(self, timeout=5.0):
        """Ask the thread to finish and wait (join). True if it ended cleanly."""
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
        stats["input_backlog"] = self._input.qsize()    # approximate; grows if we fall behind
        if self._inspection_queue is not None:
            stats["inspection_backlog"] = self._inspection_queue.qsize()
        stats.update(self._aggregator.get_stats())
        return stats

    # --- the thread body ----------------------------------------------------
    def _run(self):
        try:
            next_tick = self._clock() + self._tick
            while not self._stop_event.is_set():
                self._drain_inspections()
                now = self._clock()
                wait = next_tick - now
                if wait > 0:
                    # Wait for an event, but never longer than the next tick or a short
                    # block time (so stop() and inspection results are noticed quickly).
                    block = MAX_BLOCK_SECONDS
                    if self._inspection_queue is not None:
                        block = INSPECTION_BLOCK_SECONDS
                    try:
                        event = self._input.get(timeout=min(wait, block))
                    except queue.Empty:
                        continue
                    self._ingest(event)
                    continue

                # Tick time reached.
                try:
                    self._emit_rows(now)
                except Exception as error:      # keep the thread alive; show it in stats
                    self.stats["tick_errors"] += 1
                    self.last_error = repr(error)
                next_tick += self._tick
                if next_tick <= now:            # we fell behind: skip ahead, no flood of rows
                    next_tick = now + self._tick
        finally:
            if self._csv is not None:
                self._csv.close()
                self._csv = None

    def _ingest(self, event):
        try:
            self._aggregator.process_event(event)
            if self._event_hook is not None:
                self._event_hook(event)
        except Exception as error:              # one bad event must not kill the thread
            self.stats["event_errors"] += 1
            self.last_error = repr(error)

    def _drain_inspections(self):
        if self._inspection_queue is None:
            return
        for _ in range(MAX_INSPECTIONS_PER_DRAIN):
            try:
                result = self._inspection_queue.get_nowait()
            except queue.Empty:
                return
            try:
                self._aggregator.process_inspection(result.event, result.inspection)
            except Exception as error:
                self.stats["inspection_errors"] += 1
                self.last_error = repr(error)

    def _emit_rows(self, now):
        for row in self._aggregator.compute_all(now):
            try:
                self.output_queue.put_nowait(row)
                self.stats["rows_emitted"] += 1
            except queue.Full:                  # only possible with a bounded output queue
                self.stats["rows_dropped_output_full"] += 1
            if self._csv is not None:
                try:
                    self._csv.write_row(row)
                except (OSError, ValueError) as error:    # e.g. file locked / disk full
                    self.stats["csv_errors"] += 1
                    self.last_error = repr(error)