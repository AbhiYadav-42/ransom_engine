"""Stage 1: desktop alert layer.

The rest of the engine only ever calls send_alert(title, message, severity).
How Linux or Windows actually shows the banner is hidden in this file.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

logger = logging.getLogger("ransomguard.alerts")

APP_NAME = "RansomGuard"
SUBPROCESS_TIMEOUT = 5      # seconds we wait for notify-send
MAX_TITLE_LENGTH = 100
MAX_MESSAGE_LENGTH = 400

VALID_SEVERITIES = ("low", "normal", "critical")

# Rate-limit policy: every severity has its OWN timer, so a "normal" alert can
# never suppress a "critical" one. Values are the minimum seconds between
# accepted alerts of that severity.
RATE_LIMIT_SECONDS = {"low": 30.0, "normal": 10.0, "critical": 2.0}

_now = time.monotonic       # replaced by a fake clock in the tests
_last_sent: dict[str, float] = {}
_limiter_lock = threading.Lock()


@dataclass(frozen=True)
class AlertResult:
    """What happened to one send_alert() call.

    delivered=True means the backend ACCEPTED the request. It is not proof
    that a human actually saw a banner (Focus Assist / do-not-disturb, etc.).
    suppressed=True means the rate limiter blocked it on purpose.
    """
    delivered: bool
    reason: str
    suppressed: bool = False


# ---------------------------------------------------------------- helpers
def _clean_text(value, max_length):
    """Return a trimmed printable string, or None if the input is unusable."""
    if not isinstance(value, str):
        return None
    cleaned = "".join(ch for ch in value if ch.isprintable() or ch == "\n").strip()
    if not cleaned:
        return None
    return cleaned[:max_length]


def _rate_limit_allows(severity):
    """Return (allowed, seconds_to_wait). Records the time when allowed."""
    interval = RATE_LIMIT_SECONDS[severity]
    now = _now()
    with _limiter_lock:
        last = _last_sent.get(severity)
        if last is not None and (now - last) < interval:
            return False, interval - (now - last)
        _last_sent[severity] = now
        return True, 0.0


def reset_rate_limiter():
    """Forget all timers (used by tests and the manual test script)."""
    with _limiter_lock:
        _last_sent.clear()


def _environment_hint():
    names = ("DBUS_SESSION_BUS_ADDRESS", "WAYLAND_DISPLAY")
    return ", ".join(
        f"{name} {'set' if os.environ.get(name) else 'not set'}" for name in names
    )


# --------------------------------------------------------------- backends
def _send_linux(title, message, severity):
    exe = shutil.which("notify-send")
    if exe is None:
        return AlertResult(
            False, "notify-send not found; install it with: sudo pacman -S libnotify"
        )

    # A LIST of arguments (never a shell string). "--" tells notify-send that
    # everything after it is plain text, even if the title starts with "-".
    command = [exe, "-u", severity, "-a", APP_NAME, "--", title, message]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return AlertResult(False, f"notify-send did not finish within {SUBPROCESS_TIMEOUT}s")
    except OSError as exc:
        return AlertResult(False, f"could not start notify-send: {exc}")

    if completed.returncode != 0:
        detail = completed.stderr.strip() or "no error output"
        return AlertResult(
            False,
            f"notify-send exited with code {completed.returncode}: {detail} "
            f"({_environment_hint()})",
        )
    return AlertResult(True, "notify-send accepted the request (banner visibility not verified)")


def _send_windows(title, message, severity):
    # Preferred: winotify (real Windows toast).
    try:
        from winotify import Notification
    except ImportError:
        Notification = None

    if Notification is not None:
        try:
            toast = Notification(
                app_id=APP_NAME,
                title=title,
                msg=message,
                duration="long" if severity == "critical" else "short",
            )
            toast.show()
            return AlertResult(True, "winotify accepted the request (banner visibility not verified)")
        except Exception as exc:  # library errors vary, so contain them all
            return AlertResult(False, f"winotify failed: {exc}")

    # Fallback: plyer.
    try:
        from plyer import notification
    except ImportError:
        return AlertResult(
            False, "no Windows notification library found; run: pip install winotify"
        )
    try:
        notification.notify(title=title, message=message, app_name=APP_NAME, timeout=10)
        return AlertResult(True, "plyer accepted the request (banner visibility not verified)")
    except Exception as exc:
        return AlertResult(False, f"plyer failed: {exc}")


def _select_backend(platform=None):
    """Pick the delivery function for a platform string (testable without a GUI)."""
    platform = platform or sys.platform
    if platform.startswith("linux"):
        return _send_linux
    if platform == "win32":
        return _send_windows
    return None


# ------------------------------------------------------------- public API
def send_alert(title, message, severity="normal"):
    """Show a desktop alert. Never raises for bad input or delivery problems;
    always returns an AlertResult so the caller can log what happened."""
    # 1. Validate input.
    severity_key = severity.strip().lower() if isinstance(severity, str) else None
    if severity_key not in VALID_SEVERITIES:
        reason = f"invalid severity {severity!r}; use one of {VALID_SEVERITIES}"
        logger.warning("alert rejected: %s", reason)
        return AlertResult(False, reason)

    clean_title = _clean_text(title, MAX_TITLE_LENGTH)
    clean_message = _clean_text(message, MAX_MESSAGE_LENGTH)
    if clean_title is None or clean_message is None:
        reason = "title and message must be non-empty text"
        logger.warning("alert rejected: %s", reason)
        return AlertResult(False, reason)

    # 2. Choose the backend BEFORE rate limiting, so an unsupported OS
    #    does not use up a rate-limit slot.
    backend = _select_backend()
    if backend is None:
        reason = f"unsupported platform: {sys.platform}"
        logger.error(reason)
        return AlertResult(False, reason)

    # 3. Rate limit (suppresses the banner only; the caller still owns the event).
    allowed, wait = _rate_limit_allows(severity_key)
    if not allowed:
        reason = f"rate-limited ({severity_key}); next allowed in {wait:.1f}s"
        logger.info(reason)
        return AlertResult(False, reason, suppressed=True)

    # 4. Deliver, and contain any surprise so the engine never crashes here.
    try:
        result = backend(clean_title, clean_message, severity_key)
    except Exception as exc:
        result = AlertResult(False, f"unexpected backend error: {exc}")

    level = logging.INFO if result.delivered else logging.WARNING
    logger.log(level, "alert %r (%s): %s", clean_title, severity_key, result.reason)
    return result