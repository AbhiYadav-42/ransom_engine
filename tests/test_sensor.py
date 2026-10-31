"""Unit tests for Stage 2. No real watching, no desktop needed."""

import dataclasses
import queue

import pytest
from watchdog.events import (
    DirModifiedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
)

from engine.sensor import (
    IgnoreList,
    ModifiedDeduplicator,
    SensorEventHandler,
    build_sensor_event,
    did_extension_change,
    make_pure_path,
)
from engine.sensor_windows import (
    defender_exclusion_command,
    get_sandbox_warnings,
    is_file_locked,
    looks_like_onedrive_path,
)


# ----- helpers --------------------------------------------------------------
class FakeClock:
    """A clock we control by hand, so tests never need time.sleep()."""

    def __init__(self, start=100.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def make_handler(clock=None, ignore=(), window=1.0, skip_dir_modified=True, maxsize=0):
    if clock is None:
        clock = FakeClock()
    q = queue.Queue(maxsize=maxsize)
    handler = SensorEventHandler(
        event_queue=q,
        ignore_list=IgnoreList(ignore, windows_style=False),
        deduplicator=ModifiedDeduplicator(window=window),
        skip_directory_modified=skip_dir_modified,
        clock=clock,
        windows_style=False,   # POSIX rules so results are the same on every OS
    )
    return handler, q, clock


def drain(q):
    items = []
    while True:
        try:
            items.append(q.get_nowait())
        except queue.Empty:
            return items


# ----- event conversion -----------------------------------------------------
def test_build_created_event_fields():
    event = build_sensor_event("created", "/sb/a.txt", timestamp=5.0, windows_style=False)
    assert event.timestamp == 5.0
    assert event.event_type == "created"
    assert event.src_path == "/sb/a.txt"
    assert event.dest_path is None
    assert event.is_directory is False
    assert event.extension_changed is False


def test_build_moved_event_has_dest_path():
    event = build_sensor_event("moved", "/sb/a.txt", "/sb/b.txt", windows_style=False)
    assert event.dest_path == "/sb/b.txt"


def test_dest_path_is_dropped_for_non_move_events():
    event = build_sensor_event("created", "/sb/a.txt", dest_path="/sb/b.txt", windows_style=False)
    assert event.dest_path is None


def test_unknown_event_type_raises():
    with pytest.raises(ValueError):
        build_sensor_event("exploded", "/sb/a.txt")


def test_sensor_event_is_immutable():
    event = build_sensor_event("created", "/sb/a.txt", windows_style=False)
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.src_path = "/somewhere/else"


# ----- extension-change detection ------------------------------------------
def test_extension_changed_when_suffix_differs():
    assert did_extension_change("/sb/a.docx", "/sb/a.docx.locked", windows_style=False) is True
    assert did_extension_change("/sb/notes", "/sb/notes.enc", windows_style=False) is True
    assert did_extension_change("/sb/a.txt", "/sb/a.locked", windows_style=False) is True


def test_extension_not_changed_when_suffix_same_in_any_case():
    assert did_extension_change("/sb/A.TXT", "/sb/b.txt", windows_style=False) is False
    assert did_extension_change("/sb/a.txt", "/sb/other/a.txt", windows_style=False) is False


def test_extension_change_not_computed_for_directories():
    event = build_sensor_event("moved", "/sb/v1.0", "/sb/v2.5x", is_directory=True, windows_style=False)
    assert event.extension_changed is False


def test_extension_compare_windows_style_is_case_insensitive():
    assert did_extension_change("C:\\Data\\Report.DOCX", "C:\\Data\\report.docx", windows_style=True) is False
    assert did_extension_change("C:\\Data\\Report.DOCX", "C:\\Data\\Report.DOCX.locked", windows_style=True) is True


# ----- ignore paths ---------------------------------------------------------
def test_ignore_list_matches_folder_and_children():
    ignore = IgnoreList(["/sb/quarantine"], windows_style=False)
    assert ignore.matches("/sb/quarantine") is True
    assert ignore.matches("/sb/quarantine/x.txt") is True
    assert ignore.matches("/sb/quarantine/deep/er/x.txt") is True
    assert ignore.matches("/sb/other/x.txt") is False


def test_ignore_list_does_not_match_similar_prefix():
    ignore = IgnoreList(["/sb/quarantine"], windows_style=False)
    assert ignore.matches("/sb/quarantine_old/x.txt") is False


def test_ignore_list_windows_style_ignores_case_and_slash_type():
    ignore = IgnoreList(["C:\\Sandbox\\Quarantine"], windows_style=True)
    assert ignore.matches("c:/sandbox/QUARANTINE/a.txt") is True
    assert ignore.matches("C:\\Sandbox\\Other\\a.txt") is False


def test_empty_ignore_list_matches_nothing():
    assert IgnoreList([], windows_style=False).matches("/anything") is False


# ----- de-duplication (fake time passed in by hand) ------------------------
def test_dedup_drops_second_modified_inside_window():
    d = ModifiedDeduplicator(window=1.0)
    assert d.should_keep("a", 0.0) is True
    assert d.should_keep("a", 0.5) is False


def test_dedup_window_is_not_sliding():
    # Dropped events must NOT restart the timer.
    d = ModifiedDeduplicator(window=1.0)
    assert d.should_keep("a", 0.0) is True
    assert d.should_keep("a", 0.9) is False
    assert d.should_keep("a", 1.8) is True   # 1.8 s after the last KEPT event


def test_dedup_paths_are_independent():
    d = ModifiedDeduplicator(window=1.0)
    assert d.should_keep("a", 0.0) is True
    assert d.should_keep("b", 0.1) is True


def test_dedup_forget_lets_next_event_through():
    d = ModifiedDeduplicator(window=1.0)
    d.should_keep("a", 0.0)
    d.forget("a")
    assert d.should_keep("a", 0.1) is True


def test_dedup_window_zero_disables_it():
    d = ModifiedDeduplicator(window=0)
    assert d.should_keep("a", 0.0) is True
    assert d.should_keep("a", 0.0) is True


def test_dedup_prune_removes_old_entries():
    d = ModifiedDeduplicator(window=1.0, prune_threshold=3)
    for name in ["a", "b", "c", "d", "e"]:
        d.should_keep(name, 0.0)
    assert len(d) == 5            # all still inside the window, nothing to prune yet
    d.should_keep("f", 10.0)      # much later: old entries are pruned
    assert len(d) == 1


def test_dedup_key_is_case_insensitive_for_windows_paths():
    d = ModifiedDeduplicator(window=1.0)
    key1 = make_pure_path("C:/Sandbox/A.txt", windows_style=True)
    key2 = make_pure_path("c:\\sandbox\\a.TXT", windows_style=True)
    assert d.should_keep(key1, 0.0) is True
    assert d.should_keep(key2, 0.1) is False


# ----- handler (real watchdog event objects, fake queue/clock) -------------
def test_created_event_goes_on_queue():
    handler, q, _ = make_handler()
    handler.on_created(FileCreatedEvent("/sb/new.txt"))
    events = drain(q)
    assert len(events) == 1
    assert events[0].event_type == "created"
    assert events[0].src_path == "/sb/new.txt"
    assert events[0].dest_path is None
    assert events[0].is_directory is False
    assert handler.stats["queued"] == 1


def test_timestamp_comes_from_the_injected_clock():
    handler, q, _ = make_handler(clock=FakeClock(start=123.5))
    handler.on_created(FileCreatedEvent("/sb/new.txt"))
    assert drain(q)[0].timestamp == 123.5


def test_ignored_paths_never_reach_the_queue():
    handler, q, _ = make_handler(ignore=["/sb/quarantine"])
    handler.on_created(FileCreatedEvent("/sb/quarantine/x.txt"))
    handler.on_moved(FileMovedEvent("/sb/a.txt", "/sb/quarantine/a.txt"))  # moved INTO ignored
    assert drain(q) == []
    assert handler.stats["ignored"] == 2


def test_directory_modified_is_skipped_by_default():
    handler, q, _ = make_handler()
    handler.on_modified(DirModifiedEvent("/sb"))
    assert drain(q) == []
    assert handler.stats["directory_modified_skipped"] == 1


def test_directory_modified_kept_when_switch_is_off():
    handler, q, _ = make_handler(skip_dir_modified=False)
    handler.on_modified(DirModifiedEvent("/sb"))
    events = drain(q)
    assert len(events) == 1
    assert events[0].is_directory is True


def test_repeated_modified_events_are_deduplicated():
    handler, q, clock = make_handler(window=1.0)
    handler.on_modified(FileModifiedEvent("/sb/a.txt"))   # kept
    clock.advance(0.3)
    handler.on_modified(FileModifiedEvent("/sb/a.txt"))   # dropped
    clock.advance(0.3)
    handler.on_modified(FileModifiedEvent("/sb/a.txt"))   # dropped
    clock.advance(1.0)
    handler.on_modified(FileModifiedEvent("/sb/a.txt"))   # kept (window passed)
    assert len(drain(q)) == 2
    assert handler.stats["duplicates_dropped"] == 2


def test_created_is_never_deduplicated():
    handler, q, _ = make_handler(window=1.0)
    for _ in range(3):
        handler.on_created(FileCreatedEvent("/sb/a.txt"))
    assert len(drain(q)) == 3


def test_moved_event_flags_extension_change():
    handler, q, _ = make_handler()
    handler.on_moved(FileMovedEvent("/sb/a.docx", "/sb/a.docx.locked"))
    handler.on_moved(FileMovedEvent("/sb/b.txt", "/sb/c.txt"))
    first, second = drain(q)
    assert first.event_type == "moved"
    assert first.dest_path == "/sb/a.docx.locked"
    assert first.extension_changed is True
    assert second.extension_changed is False


def test_delete_resets_dedup_for_that_path():
    handler, q, clock = make_handler(window=1.0)
    handler.on_modified(FileModifiedEvent("/sb/a.txt"))
    clock.advance(0.1)
    handler.on_deleted(FileDeletedEvent("/sb/a.txt"))
    clock.advance(0.1)
    handler.on_modified(FileModifiedEvent("/sb/a.txt"))   # file re-created: must not be suppressed
    types = [e.event_type for e in drain(q)]
    assert types == ["modified", "deleted", "modified"]


def test_full_queue_is_counted_and_does_not_raise():
    handler, q, _ = make_handler(maxsize=1)
    handler.on_created(FileCreatedEvent("/sb/a.txt"))
    handler.on_created(FileCreatedEvent("/sb/b.txt"))   # queue is full now
    assert handler.stats["queued"] == 1
    assert handler.stats["queue_full"] == 1


def test_handler_never_raises_on_garbage():
    handler, q, _ = make_handler()
    handler.on_created(object())    # has no src_path -> would crash without the safety net
    assert handler.stats["errors"] == 1
    assert handler.last_error is not None
    assert drain(q) == []


def test_bytes_paths_are_converted_to_text():
    handler, q, _ = make_handler()
    handler.on_created(FileCreatedEvent(b"/sb/bytes.txt"))
    assert drain(q)[0].src_path == "/sb/bytes.txt"


# ----- Windows helpers: string logic only, UNTESTED on real Windows --------
def test_onedrive_path_detected():
    assert looks_like_onedrive_path("C:\\Users\\Abhi\\OneDrive\\Desktop\\sandbox", check_environment=False) is True
    assert looks_like_onedrive_path("C:\\Users\\Abhi\\OneDrive - Uni\\sandbox", check_environment=False) is True


def test_non_onedrive_path_not_flagged():
    assert looks_like_onedrive_path("C:\\sandbox", check_environment=False) is False


def test_no_windows_warnings_on_linux():
    assert get_sandbox_warnings(["/sb"], is_windows=False) == []


def test_windows_warnings_mention_onedrive_and_defender():
    warnings_list = get_sandbox_warnings(
        ["C:\\Users\\Abhi\\OneDrive\\sandbox"], is_windows=True, check_environment=False)
    text = " ".join(warnings_list)
    assert "OneDrive" in text
    assert "Defender" in text


def test_defender_command_text():
    command = defender_exclusion_command("C:\\sandbox")
    assert "Add-MpPreference" in command
    assert "C:\\sandbox" in command


def test_is_file_locked_false_for_normal_file(tmp_path):
    f = tmp_path / "plain.txt"
    f.write_text("hello")
    assert is_file_locked(f) is False