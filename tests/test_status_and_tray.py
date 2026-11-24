"""Tests for the heartbeat file, the alert gate and the tray's pure logic. No desktop, no pystray."""

import json
from unittest import mock

import pytest

from engine.alert_gate import AlertGate
from engine.status_file import (
    STATUS_NAME, clear_stop_request, read_status, request_stop, stop_requested, write_status)
from ui.tray_app import TrayApp
from ui.tray_logic import (
    acquire_single_instance_lock, compute_state, format_uptime, is_daemon_cmdline, make_icon)


def good_status(**overrides):
    status = {"status": "RUNNING", "uptime_sec": 3725, "eps_1s": 12.5, "alerts_triggered": 2,
              "last_alert": "10:00:01 test", "updated_at": 1000.0}
    status.update(overrides)
    return status


def count_pixels(image, predicate):
    data = image.convert("RGBA").tobytes()
    return sum(1 for i in range(0, len(data), 4)
               if data[i + 3] > 200 and predicate(data[i], data[i + 1], data[i + 2]))


# ----- status file ----------------------------------------------------------
def test_write_then_read_round_trip(tmp_path):
    assert write_status(tmp_path, {"status": "RUNNING", "n": 3}) is True
    assert read_status(tmp_path) == {"status": "RUNNING", "n": 3}


def test_write_leaves_no_temp_file(tmp_path):
    write_status(tmp_path, {"a": 1})
    assert [p.name for p in tmp_path.iterdir()] == [STATUS_NAME]


def test_read_missing_file_returns_none(tmp_path):
    assert read_status(tmp_path) is None
    assert read_status(tmp_path / "no_such_folder") is None


def test_read_corrupt_json_returns_none(tmp_path):
    (tmp_path / STATUS_NAME).write_text("{not json")
    assert read_status(tmp_path) is None


def test_read_non_object_json_returns_none(tmp_path):
    (tmp_path / STATUS_NAME).write_text(json.dumps([1, 2, 3]))
    assert read_status(tmp_path) is None


def test_read_huge_file_returns_none(tmp_path):
    (tmp_path / STATUS_NAME).write_text("x" * 70000)
    assert read_status(tmp_path) is None


def test_write_never_raises_when_replace_fails(tmp_path):
    with mock.patch("engine.status_file.os.replace", side_effect=PermissionError("locked")):
        assert write_status(tmp_path, {"a": 1}, retries=2, retry_delay=0) is False


def test_write_unserialisable_payload_returns_false(tmp_path):
    assert write_status(tmp_path, {"x": object()}) is False


def test_stop_request_helpers(tmp_path):
    assert stop_requested(tmp_path) is False
    assert request_stop(tmp_path) is True
    assert stop_requested(tmp_path) is True
    clear_stop_request(tmp_path)
    assert stop_requested(tmp_path) is False
    clear_stop_request(tmp_path)                    # clearing twice is harmless


# ----- alert gate -----------------------------------------------------------
def test_gate_needs_enough_flagged_ticks():
    gate = AlertGate(window=5, needed=3, cooldown_seconds=60)
    assert gate.update(True, 0) is False
    assert gate.update(True, 1) is False
    assert gate.update(True, 2) is True


def test_gate_cooldown_then_fires_again():
    gate = AlertGate(window=5, needed=3, cooldown_seconds=60)
    for second in range(3):
        gate.update(True, second)                   # fires on the third
    assert gate.update(True, 3) is False            # inside the cooldown
    assert gate.update(True, 62) is True            # cooldown over, still flagged


def test_gate_old_flags_fall_out_of_the_window():
    gate = AlertGate(window=5, needed=3, cooldown_seconds=60)
    gate.update(True, 0)
    gate.update(True, 1)
    for second in range(2, 7):
        gate.update(False, second)
    assert gate.update(True, 100) is False          # only one flagged tick is left in the window


def test_gate_rejects_bad_settings():
    with pytest.raises(ValueError):
        AlertGate(window=3, needed=4)
    with pytest.raises(ValueError):
        AlertGate(window=0, needed=1)


# ----- tray state -----------------------------------------------------------
def test_compute_state_missing_file_is_stopped():
    state = compute_state(None)
    assert state.level == "stopped" and state.running is False


def test_compute_state_running_is_safe():
    state = compute_state(good_status(), now=1001.0)
    assert state.level == "safe" and state.running is True
    assert "1h 02m" in state.status_text
    assert "alerts: 2" in state.status_text


def test_compute_state_alert():
    state = compute_state(good_status(status="ALERT"), now=1001.0)
    assert state.level == "alert" and state.running is True
    assert state.status_text.startswith("ALERT")


def test_compute_state_stopped_status():
    state = compute_state(good_status(status="STOPPED"), now=1001.0)
    assert state.level == "stopped" and state.running is False


def test_compute_state_stale_heartbeat_is_stopped():
    state = compute_state(good_status(), now=1010.0)
    assert state.level == "stopped" and state.running is False
    assert "not responding" in state.status_text


def test_compute_state_survives_garbage_values():
    status = {"status": "RUNNING", "uptime_sec": "abc", "eps_1s": None,
              "alerts_triggered": [], "updated_at": 1000.0}
    state = compute_state(status, now=1000.5)
    assert state.level == "safe"
    assert compute_state({"updated_at": "never"}, now=5.0).level == "stopped"


def test_format_uptime():
    assert format_uptime(0) == "0s"
    assert format_uptime(59) == "59s"
    assert format_uptime(61) == "1m 01s"
    assert format_uptime(3725) == "1h 02m"
    for bad in (None, "x", -5):
        assert format_uptime(bad) == "0s"


# ----- icons ----------------------------------------------------------------
def test_icons_have_the_right_size_and_colors():
    checks = {
        "safe": lambda r, g, b: g > r + 40 and g > b + 40,
        "alert": lambda r, g, b: r > g + 80 and r > b + 80,
        "stopped": lambda r, g, b: abs(r - g) < 12 and abs(g - b) < 12 and 100 < r < 160,
    }
    for level, predicate in checks.items():
        icon = make_icon(level)
        assert icon.size == (64, 64) and icon.mode == "RGBA"
        assert icon.getpixel((0, 0))[3] == 0                       # transparent corner
        assert count_pixels(icon, predicate) > 300


def test_icon_cache_hands_out_independent_copies():
    first = make_icon("safe")
    first.putpixel((32, 32), (1, 2, 3, 255))
    assert make_icon("safe").getpixel((32, 32)) != (1, 2, 3, 255)


# ----- misc -----------------------------------------------------------------
def test_is_daemon_cmdline():
    assert is_daemon_cmdline(["python", "-m", "engine.daemon", "--data-dir", "x"]) is True
    assert is_daemon_cmdline(["python", "other.py"]) is False
    assert is_daemon_cmdline(None) is False


def test_single_instance_lock():
    first = acquire_single_instance_lock(47654)
    assert first is not None
    try:
        assert acquire_single_instance_lock(47654) is None
    finally:
        first.close()
    again = acquire_single_instance_lock(47654)
    assert again is not None
    again.close()


# ----- quit behavior -------------------------------------------------------
def test_quit_stops_engine_and_closes_icon(tmp_path):
    app = TrayApp(pystray=object(), data_dir=tmp_path)

    class FakeController:
        stopped = False

        def stop(self):
            self.stopped = True
            return True, "Engine stopped"

    app._controller = FakeController()

    class FakeIcon:
        stopped = False

        def stop(self):
            self.stopped = True

    icon = FakeIcon()
    app._quit_and_stop(icon)

    assert app._controller.stopped is True
    assert app._stop_event.is_set()
    assert icon.stopped is True