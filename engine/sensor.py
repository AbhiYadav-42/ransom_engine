"""
engine/sensor.py -- Stage 2: the behavioral file sensor.

WHAT THIS FILE DOES
    Watches one or more sandbox folders using the `watchdog` library and turns
    every filesystem event into a small, uniform SensorEvent that is put on a
    queue.Queue. Stage 3 (the aggregator) will read that queue later.

WHAT THIS FILE DELIBERATELY DOES NOT DO
    No counting over time, no entropy, no ML, no killing processes, no alerts.

HONEST LIMITATIONS (also written in the README)
    * NO PROCESS ID. watchdog does not tell us WHICH program touched a file, so
      SensorEvent has no pid field. Process attribution comes later (psutil).
    * EVENTS CAN BE LOST. The OS keeps events in a fixed-size buffer. If we are
      too slow (or a burst is huge) the OS drops events silently. That is why
      the handler callbacks do almost nothing.
    * One real action can produce several events (e.g. create + modify), and
      different OSes / watchdog versions may differ. Do not assume 1 action = 1 event.
"""

import os
import queue
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from engine.sensor_windows import get_sandbox_warnings

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
EVENT_CREATED = "created"
EVENT_MODIFIED = "modified"
EVENT_MOVED = "moved"
EVENT_DELETED = "deleted"
VALID_EVENT_TYPES = (EVENT_CREATED, EVENT_MODIFIED, EVENT_MOVED, EVENT_DELETED)

DEFAULT_DEDUP_WINDOW = 0.25      # seconds
DEFAULT_PRUNE_THRESHOLD = 10000  # forget old de-dup entries when we track more paths than this


# ---------------------------------------------------------------------------
# 1. The event object
# ---------------------------------------------------------------------------
@dataclass(frozen=True)  # frozen = cannot be changed after creation (safe to share between threads)
class SensorEvent:
    timestamp: float                  # time.monotonic() when OUR handler saw the event
    event_type: str                   # "created" | "modified" | "moved" | "deleted"
    src_path: str                     # path as reported by watchdog (use make_pure_path() to compare)
    dest_path: Optional[str] = None   # only for "moved", otherwise None
    is_directory: bool = False
    extension_changed: bool = False   # only meaningful for file "moved" events
    # NOTE: there is intentionally NO pid field. See "HONEST LIMITATIONS" above.


# ---------------------------------------------------------------------------
# 2. Path helpers (pathlib; case-insensitive and backslash-friendly on Windows)
# ---------------------------------------------------------------------------
def make_pure_path(path, windows_style=None):
    """
    Return a "pure" pathlib object used for COMPARING paths.

    PureWindowsPath treats "C:/Sandbox/A.txt" and "c:\\sandbox\\a.TXT" as equal
    (case-insensitive, both slash types). PurePosixPath is case-sensitive.
    windows_style=None means "decide from the OS we are running on".
    The parameter exists so tests can check Windows behaviour on Linux.
    """
    if windows_style is None:
        windows_style = (sys.platform == "win32")
    if windows_style:
        return PureWindowsPath(path)
    return PurePosixPath(path)


def did_extension_change(src_path, dest_path, windows_style=None):
    """True if the LAST suffix differs, ignoring upper/lower case.
    "a.docx" -> "a.docx.locked" is True. "A.TXT" -> "a.txt" is False.
    Only the last suffix counts ("a.tar.gz" has suffix ".gz")."""
    if dest_path is None:
        return False
    old_suffix = make_pure_path(src_path, windows_style).suffix.lower()
    new_suffix = make_pure_path(dest_path, windows_style).suffix.lower()
    return old_suffix != new_suffix


def build_sensor_event(event_type, src_path, dest_path=None, is_directory=False,
                       timestamp=None, windows_style=None):
    """Pure function: plain values in, SensorEvent out (easy to unit test)."""
    if event_type not in VALID_EVENT_TYPES:
        raise ValueError("Unknown event_type: %r" % (event_type,))
    if timestamp is None:
        timestamp = time.monotonic()
    if event_type != EVENT_MOVED:
        dest_path = None  # dest_path only makes sense for moves

    changed = False
    if event_type == EVENT_MOVED and dest_path is not None and not is_directory:
        changed = did_extension_change(src_path, dest_path, windows_style)

    return SensorEvent(
        timestamp=timestamp,
        event_type=event_type,
        src_path=src_path,
        dest_path=dest_path,
        is_directory=is_directory,
        extension_changed=changed,
    )


# ---------------------------------------------------------------------------
# 3. Ignore list (our own quarantine / models / data folders)
# ---------------------------------------------------------------------------
class IgnoreList:
    """A path is ignored if it IS an ignored folder or lives anywhere inside one.
    We compare whole path parts, so "/sb/quarantine_old" is NOT inside "/sb/quarantine"."""

    def __init__(self, paths=(), windows_style=None):
        self._windows_style = windows_style
        self._ignored = [make_pure_path(p, windows_style) for p in paths]

    def matches(self, path):
        if not self._ignored:
            return False
        candidate = make_pure_path(path, self._windows_style)
        for folder in self._ignored:
            if candidate == folder or folder in candidate.parents:
                return True
        return False


# ---------------------------------------------------------------------------
# 4. De-duplication of bursts of "modified" events
# ---------------------------------------------------------------------------
class ModifiedDeduplicator:
    """
    Remembers when we last KEPT a "modified" event for each path.
    should_keep(key, now): False if the same key was kept less than `window`
    seconds ago, otherwise True (and the timer restarts from `now`).
    Dropped events do NOT restart the timer, so a long continuous write still
    yields about one event per window instead of just one forever.
    `now` is passed in, so tests can use a fake clock.
    """

    def __init__(self, window=DEFAULT_DEDUP_WINDOW, prune_threshold=DEFAULT_PRUNE_THRESHOLD):
        self.window = window
        self._prune_threshold = prune_threshold
        self._last_kept = {}              # key -> time we last kept a "modified" for it
        self._lock = threading.Lock()     # cheap insurance in case two threads ever call us

    def should_keep(self, key, now):
        if self.window <= 0:              # window of 0 turns de-duplication off
            return True
        with self._lock:
            last = self._last_kept.get(key)
            if last is not None and (now - last) < self.window:
                return False
            self._last_kept[key] = now
            if len(self._last_kept) > self._prune_threshold:
                self._prune(now)
            return True

    def forget(self, key):
        """Called on delete/move so a recreated file starts fresh."""
        with self._lock:
            self._last_kept.pop(key, None)

    def _prune(self, now):
        # Called with the lock held. Keeps memory from growing with every path ever seen.
        self._last_kept = {k: t for k, t in self._last_kept.items() if (now - t) < self.window}

    def __len__(self):
        return len(self._last_kept)


# ---------------------------------------------------------------------------
# 5. The watchdog handler -- callbacks stay TINY
# ---------------------------------------------------------------------------
class SensorEventHandler(FileSystemEventHandler):
    """
    watchdog calls on_created / on_modified / on_moved / on_deleted from its own
    thread. Each callback only does cheap in-memory work (no disk, no printing,
    no sleeping), then returns. The slow thinking happens in later stages.
    """

    def __init__(self, event_queue, ignore_list=None, deduplicator=None,
                 skip_directory_modified=True, clock=time.monotonic, windows_style=None):
        super().__init__()
        self._queue = event_queue
        self._windows_style = windows_style
        self._ignore = ignore_list if ignore_list is not None else IgnoreList((), windows_style)
        self._dedup = deduplicator if deduplicator is not None else ModifiedDeduplicator()
        self._skip_dir_modified = skip_directory_modified
        self._clock = clock
        # Counters so nothing is dropped silently. Written by watchdog's thread, read by us.
        self.stats = {
            "queued": 0,
            "ignored": 0,
            "directory_modified_skipped": 0,
            "duplicates_dropped": 0,
            "queue_full": 0,
            "errors": 0,
        }
        self.last_error = None

    # The four required callbacks: each is one line.
    def on_created(self, event):
        self._handle(EVENT_CREATED, event)

    def on_modified(self, event):
        self._handle(EVENT_MODIFIED, event)

    def on_moved(self, event):
        self._handle(EVENT_MOVED, event)

    def on_deleted(self, event):
        self._handle(EVENT_DELETED, event)

    # watchdog also has on_opened / on_closed (newer versions, mostly Linux).
    # We do NOT override them, so they are ignored.

    def _handle(self, event_type, event):
        # A crash inside a watchdog callback could stop the whole watcher
        # thread (behaviour may differ by version), so we never let one escape.
        try:
            self._handle_unsafe(event_type, event)
        except Exception as error:  # broad on purpose, see comment above
            self.stats["errors"] += 1
            self.last_error = repr(error)

    def _handle_unsafe(self, event_type, event):
        now = self._clock()
        src_path = os.fsdecode(event.src_path)   # watchdog may give str or bytes
        dest_path = None
        if event_type == EVENT_MOVED:
            dest_path = os.fsdecode(event.dest_path)
        is_directory = bool(event.is_directory)

        # 1) Ignore our own folders. For a move, EITHER side being ignored drops it.
        if self._ignore.matches(src_path) or (dest_path is not None and self._ignore.matches(dest_path)):
            self.stats["ignored"] += 1
            return

        # 2) Per-type handling
        if event_type == EVENT_MODIFIED:
            if is_directory and self._skip_dir_modified:
                self.stats["directory_modified_skipped"] += 1
                return
            key = make_pure_path(src_path, self._windows_style)   # case-insensitive on Windows
            if not self._dedup.should_keep(key, now):
                self.stats["duplicates_dropped"] += 1
                return
        elif event_type in (EVENT_DELETED, EVENT_MOVED):
            self._dedup.forget(make_pure_path(src_path, self._windows_style))

        # 3) Build the event and hand it over. put_nowait never blocks.
        sensor_event = build_sensor_event(
            event_type, src_path, dest_path, is_directory,
            timestamp=now, windows_style=self._windows_style,
        )
        try:
            self._queue.put_nowait(sensor_event)
            self.stats["queued"] += 1
        except queue.Full:
            self.stats["queue_full"] += 1   # only possible with a bounded queue


# ---------------------------------------------------------------------------
# 6. FileSensor: start / stop / watched paths / ignore list
# ---------------------------------------------------------------------------
class FileSensor:
    def __init__(self, watch_paths, event_queue=None, ignore_paths=(),
                 dedup_window=DEFAULT_DEDUP_WINDOW, recursive=True,
                 skip_directory_modified=True):
        if isinstance(watch_paths, (str, Path)):
            watch_paths = [watch_paths]
        # resolve() makes paths absolute, so watchdog's paths and our ignore paths share a prefix.
        self.watch_paths = [Path(p).expanduser().resolve() for p in watch_paths]
        self.ignore_paths = [Path(p).expanduser().resolve() for p in ignore_paths]
        self.event_queue = event_queue if event_queue is not None else queue.Queue()
        self.startup_warnings = []   # filled by start(); Windows hints live in sensor_windows.py
        self._recursive = recursive
        self._observer = None
        self.handler = SensorEventHandler(
            event_queue=self.event_queue,
            ignore_list=IgnoreList(self.ignore_paths),
            deduplicator=ModifiedDeduplicator(window=dedup_window),
            skip_directory_modified=skip_directory_modified,
        )

    def start(self):
        if self.is_running():
            raise RuntimeError("FileSensor is already running")
        for folder in self.watch_paths:
            if not folder.is_dir():
                raise FileNotFoundError("Watched path is not an existing folder: %s" % folder)

        self.startup_warnings = get_sandbox_warnings(self.watch_paths)

        # A watchdog Observer is a thread, and a thread cannot be started twice,
        # so every start() makes a fresh one.
        observer = Observer()   # picks inotify on Linux, ReadDirectoryChangesW on Windows
        for folder in self.watch_paths:
            observer.schedule(self.handler, str(folder), recursive=self._recursive)
        observer.start()
        self._observer = observer

    def stop(self, timeout=5.0):
        """Stop watching and wait (join) for the thread. True if it ended cleanly."""
        observer = self._observer
        if observer is None:
            return True               # nothing running; calling stop() twice is harmless
        self._observer = None
        observer.stop()
        if observer.is_alive():
            observer.join(timeout)
        return not observer.is_alive()

    def is_running(self):
        return self._observer is not None and self._observer.is_alive()

    def get_stats(self):
        return dict(self.handler.stats)