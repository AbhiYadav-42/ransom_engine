import subprocess

import pytest

from engine import alerts


@pytest.fixture(autouse=True)
def clean_state():
    alerts.reset_rate_limiter()
    yield
    alerts.reset_rate_limiter()


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(alerts, "_now", fake)
    return fake


@pytest.fixture
def fake_backend(monkeypatch):
    calls = []

    def backend(title, message, severity):
        calls.append((title, message, severity))
        return alerts.AlertResult(True, "fake ok")

    monkeypatch.setattr(alerts, "_select_backend", lambda platform=None: backend)
    return calls


# ---------------------------------------------------------- validation
def test_invalid_severity_is_rejected(fake_backend):
    result = alerts.send_alert("T", "M", "urgent")
    assert not result.delivered and not result.suppressed
    assert "invalid severity" in result.reason
    assert fake_backend == []


def test_non_string_severity_is_rejected(fake_backend):
    assert not alerts.send_alert("T", "M", None).delivered
    assert fake_backend == []


def test_empty_title_or_message_is_rejected(fake_backend):
    assert not alerts.send_alert("   ", "M", "normal").delivered
    assert not alerts.send_alert("T", "", "normal").delivered
    assert fake_backend == []


def test_severity_is_case_insensitive(fake_backend):
    assert alerts.send_alert("T", "M", " CRITICAL ").delivered
    assert fake_backend[0][2] == "critical"


# ------------------------------------------------------- rate limiting
def test_second_alert_inside_interval_is_suppressed(fake_backend, clock):
    assert alerts.send_alert("T", "M", "normal").delivered
    second = alerts.send_alert("T", "M", "normal")
    assert second.suppressed and not second.delivered
    assert len(fake_backend) == 1


def test_alert_allowed_again_after_interval(fake_backend, clock):
    alerts.send_alert("T", "M", "normal")
    clock.advance(alerts.RATE_LIMIT_SECONDS["normal"] + 0.1)
    assert alerts.send_alert("T", "M", "normal").delivered
    assert len(fake_backend) == 2


def test_normal_alert_does_not_suppress_critical(fake_backend, clock):
    alerts.send_alert("T", "M", "normal")
    assert alerts.send_alert("T", "M", "critical").delivered
    assert alerts.send_alert("T", "M", "critical").suppressed


# -------------------------------------------------- backend selection
def test_backend_selection_per_platform():
    assert alerts._select_backend("linux") is alerts._send_linux
    assert alerts._select_backend("win32") is alerts._send_windows
    assert alerts._select_backend("darwin") is None


def test_unsupported_platform_returns_clear_result(monkeypatch):
    monkeypatch.setattr(alerts, "_select_backend", lambda platform=None: None)
    result = alerts.send_alert("T", "M", "normal")
    assert not result.delivered and "unsupported platform" in result.reason


def test_backend_exception_is_contained(monkeypatch):
    def boom(title, message, severity):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(alerts, "_select_backend", lambda platform=None: boom)
    result = alerts.send_alert("T", "M", "normal")
    assert not result.delivered and "kaboom" in result.reason


# ------------------------------------------------------- Linux backend
def test_missing_notify_send_gives_useful_error(monkeypatch):
    monkeypatch.setattr(alerts.shutil, "which", lambda name: None)
    result = alerts._send_linux("T", "M", "normal")
    assert not result.delivered
    assert "notify-send not found" in result.reason and "libnotify" in result.reason


def test_command_is_a_list_with_double_dash(monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"], seen["kwargs"] = cmd, kwargs
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(alerts.shutil, "which", lambda name: "/usr/bin/notify-send")
    monkeypatch.setattr(alerts.subprocess, "run", fake_run)

    result = alerts._send_linux("-rm -rf", "body", "critical")

    assert result.delivered
    assert seen["cmd"] == [
        "/usr/bin/notify-send", "-u", "critical", "-a", "RansomGuard",
        "--", "-rm -rf", "body",
    ]
    assert not seen["kwargs"].get("shell")
    assert seen["kwargs"]["timeout"] == alerts.SUBPROCESS_TIMEOUT


def test_nonzero_exit_code_is_reported(monkeypatch):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="no bus")

    monkeypatch.setattr(alerts.shutil, "which", lambda name: "/usr/bin/notify-send")
    monkeypatch.setattr(alerts.subprocess, "run", fake_run)

    result = alerts._send_linux("T", "M", "normal")
    assert not result.delivered
    assert "code 1" in result.reason and "no bus" in result.reason


def test_timeout_is_reported_not_raised(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(alerts.shutil, "which", lambda name: "/usr/bin/notify-send")
    monkeypatch.setattr(alerts.subprocess, "run", fake_run)

    result = alerts._send_linux("T", "M", "normal")
    assert not result.delivered and "did not finish" in result.reason


def test_oserror_is_reported_not_raised(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(alerts.shutil, "which", lambda name: "/usr/bin/notify-send")
    monkeypatch.setattr(alerts.subprocess, "run", fake_run)

    result = alerts._send_linux("T", "M", "normal")
    assert not result.delivered and "denied" in result.reason