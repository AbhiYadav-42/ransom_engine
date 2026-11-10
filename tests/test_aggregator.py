"""Unit tests for Stage 3. No threads, no real time: we hand 'now' to the code."""

import csv

import pytest

from engine.aggregator import (
    GLOBAL_KEY,
    Aggregator,
    FeatureCsvWriter,
    FeatureRow,
    SlidingWindow,
)
from engine.aggregator_windows import describe_monotonic_clock, split_for_counting
from engine.features_schema import FEATURE_NAMES, FeatureSchemaError
from engine.sensor import SensorEvent

ZEROS = [0.0] * len(FEATURE_NAMES)


# ----- helpers --------------------------------------------------------------
def make_event(timestamp, event_type="created", path="/sb/a.txt", dest_path=None,
               is_directory=False, extension_changed=False):
    return SensorEvent(timestamp=timestamp, event_type=event_type, src_path=path,
                       dest_path=dest_path, is_directory=is_directory,
                       extension_changed=extension_changed)


def make_aggregator(**kwargs):
    kwargs.setdefault("windows_style", False)    # POSIX rules: same result on every OS
    return Aggregator(**kwargs)


def feature(row, name):
    return row.to_dict()[name]


def key_by_first_folder(event):
    # "/alpha/a.txt" -> "src:alpha"
    return "src:" + event.src_path.split("/")[1]


# ----- SlidingWindow --------------------------------------------------------
def test_window_add_and_count():
    window = SlidingWindow(window_seconds=5.0, max_items=10)
    assert window.count() == 0
    window.add(1.0, "a")
    window.add(2.0, "b")
    assert window.count() == 2


def test_window_prune_boundary():
    window = SlidingWindow(window_seconds=5.0, max_items=10)
    window.add(0.0, "a")
    window.prune(4.999)
    assert window.count() == 1      # age 4.999 < 5.0: still inside
    window.prune(5.0)
    assert window.count() == 0      # age 5.0: out


def test_window_prune_keeps_newer_items_and_iterates_items_only():
    window = SlidingWindow(window_seconds=5.0, max_items=10)
    window.add(0.0, "old")
    window.add(3.0, "mid")
    window.add(6.0, "new")
    window.prune(6.0)               # ages: 6, 3, 0
    assert list(window) == ["mid", "new"]


def test_window_cap_evicts_oldest_and_counts_drops():
    window = SlidingWindow(window_seconds=5.0, max_items=3)
    for index, name in enumerate(["a", "b", "c", "d", "e"]):
        window.add(float(index), name)
    assert window.count() == 3
    assert list(window) == ["c", "d", "e"]
    assert window.dropped_by_cap == 2


def test_window_rejects_bad_settings():
    with pytest.raises(ValueError):
        SlidingWindow(window_seconds=0, max_items=5)
    with pytest.raises(ValueError):
        SlidingWindow(window_seconds=5.0, max_items=0)


def test_empty_window_is_harmless():
    window = SlidingWindow(window_seconds=5.0, max_items=5)
    window.prune(100.0)
    assert window.count() == 0
    assert list(window) == []


# ----- path helpers ---------------------------------------------------------
def test_windows_style_paths_are_case_insensitive():
    first, first_parent = split_for_counting("C:/Sandbox/A.txt", windows_style=True)
    second, second_parent = split_for_counting("c:\\sandbox\\a.TXT", windows_style=True)
    assert first == second
    assert first_parent == second_parent


def test_posix_style_paths_keep_case_and_tidy_slashes():
    upper, _ = split_for_counting("/sb/A.txt", windows_style=False)
    lower, _ = split_for_counting("/sb/a.txt", windows_style=False)
    messy, _ = split_for_counting("/sb//a.txt", windows_style=False)
    assert upper != lower
    assert messy == lower


def test_split_returns_parent_folder():
    assert split_for_counting("/sb/sub/a.txt", windows_style=False)[1] == "/sb/sub"
    assert split_for_counting("C:\\Sb\\Sub\\a.txt", windows_style=True)[1] == "c:\\sb\\sub"


def test_clock_description_is_text():
    text = describe_monotonic_clock()
    assert isinstance(text, str) and "monotonic" in text


# ----- features, one by one (fake 'now') -----------------------------------
def test_idle_row_is_all_zeros():
    row = make_aggregator().compute_features(10.0)
    assert row.source_key == GLOBAL_KEY
    assert row.timestamp == 10.0
    assert row.to_vector() == ZEROS


def test_events_per_sec_1s():
    agg = make_aggregator()
    agg.process_event(make_event(8.0, path="/sb/old.txt"))       # 2 s old at now=10: outside 1 s
    for i in range(5):
        agg.process_event(make_event(9.5, path="/sb/f%d.txt" % i))
    row = agg.compute_features(10.0)
    assert feature(row, "events_per_sec_1s") == pytest.approx(5.0)


def test_events_per_sec_5s():
    agg = make_aggregator()
    for i in range(4):
        agg.process_event(make_event(4.0, path="/sb/old%d.txt" % i))   # 6 s old: outside 5 s
    for i in range(10):
        agg.process_event(make_event(7.0, path="/sb/f%d.txt" % i))
    row = agg.compute_features(10.0)
    assert feature(row, "events_per_sec_5s") == pytest.approx(2.0)


def test_distinct_files_modified_counts_only_modified_file_events():
    agg = make_aggregator()
    for _ in range(3):
        agg.process_event(make_event(9.0, "modified", "/sb/a.txt"))
    agg.process_event(make_event(9.0, "modified", "/sb/b.txt"))
    agg.process_event(make_event(9.0, "created", "/sb/c.txt"))                       # not modified
    agg.process_event(make_event(9.0, "modified", "/sb", is_directory=True))         # a folder
    row = agg.compute_features(10.0)
    assert feature(row, "distinct_files_modified") == 2


def test_distinct_dirs_touched_includes_move_destination():
    agg = make_aggregator()
    agg.process_event(make_event(9.0, "created", "/sb/a.txt"))
    agg.process_event(make_event(9.0, "created", "/sb/sub/b.txt"))
    agg.process_event(make_event(9.0, "moved", "/sb/c.txt", dest_path="/other/c.txt"))
    row = agg.compute_features(10.0)
    assert feature(row, "distinct_dirs_touched") == 3      # /sb, /sb/sub, /other


def test_rename_count_counts_file_moves_only():
    agg = make_aggregator()
    agg.process_event(make_event(9.0, "moved", "/sb/a.txt", dest_path="/sb/b.txt"))
    agg.process_event(make_event(9.0, "moved", "/sb/c.txt", dest_path="/sb/d.txt"))
    agg.process_event(make_event(9.0, "moved", "/sb/d1", dest_path="/sb/d2", is_directory=True))
    row = agg.compute_features(10.0)
    assert feature(row, "rename_count") == 2


def test_extension_change_count():
    agg = make_aggregator()
    agg.process_event(make_event(9.0, "moved", "/sb/a.txt", "/sb/a.locked", extension_changed=True))
    agg.process_event(make_event(9.0, "moved", "/sb/b.txt", "/sb/b.enc", extension_changed=True))
    agg.process_event(make_event(9.0, "moved", "/sb/c.txt", "/sb/d.txt", extension_changed=False))
    agg.process_event(make_event(9.0, "created", "/sb/e.txt"))
    row = agg.compute_features(10.0)
    assert feature(row, "extension_change_count") == 2


def test_modify_ratio():
    agg = make_aggregator()
    assert feature(agg.compute_features(10.0), "modify_ratio") == 0.0     # no events
    for i in range(3):
        agg.process_event(make_event(9.5, "modified", "/sb/f%d.txt" % i))
    agg.process_event(make_event(9.5, "created", "/sb/new.txt"))
    row = agg.compute_features(10.0)
    assert feature(row, "modify_ratio") == pytest.approx(0.75)


def test_placeholder_features_are_zero():
    agg = make_aggregator()
    agg.process_event(make_event(9.5, "created", "/sb/a.txt"))
    agg.process_event(make_event(9.5, "modified", "/sb/a.txt"))
    row = agg.compute_features(10.0)
    assert feature(row, "canary_touched") == 0.0
    assert feature(row, "backup_kill_cmd") == 0.0


def test_events_age_out_of_the_windows():
    agg = make_aggregator()
    agg.process_event(make_event(0.0, "created", "/sb/a.txt"))
    row = agg.compute_features(0.5)
    assert feature(row, "events_per_sec_1s") == pytest.approx(1.0)
    assert feature(row, "events_per_sec_5s") == pytest.approx(0.2)
    row = agg.compute_features(1.0)                  # age 1.0: out of the 1 s window only
    assert feature(row, "events_per_sec_1s") == 0.0
    assert feature(row, "events_per_sec_5s") == pytest.approx(0.2)
    row = agg.compute_features(5.0)                  # age 5.0: out of both
    assert row.to_vector() == ZEROS


def test_distinct_counting_is_case_insensitive_for_windows_paths():
    agg = Aggregator(windows_style=True)
    agg.process_event(make_event(0.5, "modified", "C:/Sb/A.txt"))
    agg.process_event(make_event(0.5, "modified", "c:\\sb\\a.TXT"))
    row = agg.compute_features(1.0)
    assert feature(row, "distinct_files_modified") == 1
    assert feature(row, "distinct_dirs_touched") == 1


def test_feature_row_vector_and_dict_follow_schema():
    row = make_aggregator().compute_features(1.0)
    assert isinstance(row.values, tuple)
    assert len(row.to_vector()) == len(FEATURE_NAMES)
    assert all(isinstance(v, float) for v in row.to_vector())
    assert list(row.to_dict().keys()) == list(FEATURE_NAMES)


def test_worked_example_from_the_design_notes():
    # 200 files in 3 s: 60 + 70 + 70. Each file = created + modified (2 events).
    agg = make_aggregator()
    files_per_second = {1: 60, 2: 70, 3: 70}
    next_file = 0
    rows = {}
    for second in (1, 2, 3):
        for _ in range(files_per_second[second]):
            path = "/sb/file_%d.txt" % next_file
            next_file += 1
            agg.process_event(make_event(second - 0.5, "created", path))
            agg.process_event(make_event(second - 0.5, "modified", path))
        rows[second] = agg.compute_features(float(second))
    rows[6] = agg.compute_features(6.0)
    rows[8] = agg.compute_features(8.0)

    assert feature(rows[1], "events_per_sec_1s") == pytest.approx(120.0)
    assert feature(rows[1], "events_per_sec_5s") == pytest.approx(24.0)
    assert feature(rows[1], "distinct_files_modified") == 60
    assert feature(rows[1], "modify_ratio") == pytest.approx(0.5)

    assert feature(rows[3], "events_per_sec_1s") == pytest.approx(140.0)
    assert feature(rows[3], "events_per_sec_5s") == pytest.approx(80.0)
    assert feature(rows[3], "distinct_files_modified") == 200
    assert feature(rows[3], "distinct_dirs_touched") == 1

    assert feature(rows[6], "events_per_sec_1s") == 0.0
    assert feature(rows[6], "events_per_sec_5s") == pytest.approx(56.0)
    assert feature(rows[6], "distinct_files_modified") == 140

    assert rows[8].to_vector() == ZEROS


# ----- memory safety, source keys ------------------------------------------
def test_burst_is_bounded_by_the_cap():
    agg = make_aggregator(max_events_per_second=100)     # caps: 100 (1 s), 500 (5 s)
    for i in range(10000):
        agg.process_event(make_event(0.5, "created", "/sb/f%d.txt" % i))
    row = agg.compute_features(1.0)
    stats = agg.get_stats()
    assert stats["events_processed"] == 10000
    assert stats["cap_drops_1s"] == 9900
    assert stats["cap_drops_5s"] == 9500
    assert feature(row, "events_per_sec_1s") == pytest.approx(100.0)    # saturated
    assert feature(row, "events_per_sec_5s") == pytest.approx(100.0)    # saturated


def test_extra_key_gets_its_own_row_and_global_still_counts():
    agg = make_aggregator(extra_key_func=key_by_first_folder)
    agg.process_event(make_event(0.5, "created", "/alpha/a1.txt"))
    agg.process_event(make_event(0.5, "created", "/alpha/a2.txt"))
    agg.process_event(make_event(0.5, "created", "/beta/b1.txt"))
    assert feature(agg.compute_features(1.0), "events_per_sec_5s") == pytest.approx(0.6)
    assert feature(agg.compute_features(1.0, "src:alpha"), "events_per_sec_5s") == pytest.approx(0.4)
    assert feature(agg.compute_features(1.0, "src:beta"), "events_per_sec_5s") == pytest.approx(0.2)
    assert agg.compute_features(1.0, "src:nobody").to_vector() == ZEROS


def test_source_cap_refuses_new_keys_but_global_keeps_working():
    agg = make_aggregator(extra_key_func=key_by_first_folder, max_sources=2)   # global + 1
    agg.process_event(make_event(0.5, "created", "/alpha/a.txt"))
    agg.process_event(make_event(0.5, "created", "/beta/b.txt"))
    agg.process_event(make_event(0.5, "created", "/gamma/c.txt"))
    assert agg.get_stats()["sources_refused"] == 2
    assert feature(agg.compute_features(1.0), "events_per_sec_5s") == pytest.approx(0.6)
    assert agg.compute_features(1.0, "src:beta").to_vector() == ZEROS


def test_compute_all_always_has_global_and_forgets_quiet_sources():
    agg = make_aggregator(extra_key_func=key_by_first_folder)
    agg.process_event(make_event(0.5, "created", "/alpha/a.txt"))
    agg.process_event(make_event(0.5, "created", "/beta/b.txt"))
    rows = agg.compute_all(1.0)
    assert [r.source_key for r in rows] == [GLOBAL_KEY, "src:alpha", "src:beta"]
    rows = agg.compute_all(10.0)                         # everything has aged out
    assert [r.source_key for r in rows] == [GLOBAL_KEY]
    assert rows[0].to_vector() == ZEROS
    assert agg.get_stats()["sources_tracked"] == 1


# ----- CSV ------------------------------------------------------------------
def make_row(timestamp=1.5):
    return FeatureRow(timestamp=timestamp, source_key=GLOBAL_KEY, values=tuple(ZEROS))


def read_csv(path):
    with open(path, newline="") as handle:
        return list(csv.reader(handle))


def test_csv_writer_creates_header_from_schema(tmp_path):
    path = tmp_path / "out" / "features.csv"        # parent folder is created for us
    writer = FeatureCsvWriter(path)
    writer.open()
    writer.write_row(make_row(1.5))
    writer.close()
    lines = read_csv(path)
    assert lines[0] == ["timestamp", "source_key"] + list(FEATURE_NAMES)
    assert lines[1][0] == "1.5"
    assert lines[1][1] == "global"
    assert len(lines) == 2


def test_csv_writer_appends_without_a_second_header(tmp_path):
    path = tmp_path / "features.csv"
    for stamp in (1.0, 2.0):
        writer = FeatureCsvWriter(path)
        writer.open()
        writer.write_row(make_row(stamp))
        writer.close()
    assert len(read_csv(path)) == 3                  # 1 header + 2 rows


def test_csv_writer_refuses_a_mismatched_header(tmp_path):
    path = tmp_path / "features.csv"
    path.write_text("a,b,c\n1,2,3\n")
    with pytest.raises(FeatureSchemaError):
        FeatureCsvWriter(path).open()
    assert path.read_text() == "a,b,c\n1,2,3\n"      # untouched