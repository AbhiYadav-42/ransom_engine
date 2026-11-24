"""
ui/tray_logic.py -- everything the tray needs EXCEPT pystray, so it can be tested without a desktop.
Imports only the standard library, Pillow, psutil and engine.status_file (no numpy / scikit-learn).
"""

import os
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import psutil
from PIL import Image, ImageDraw

from engine.status_file import ALERTS_NAME, read_status, request_stop

STALE_AFTER_SECONDS = 5.0            # heartbeat older than this = engine is dead / frozen
# DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW (Windows only)
WINDOWS_DETACHED_FLAGS = 0x00000008 | 0x00000200 | 0x08000000


# ----------------------------------------------------------------- state from status.json
@dataclass(frozen=True)
class TrayState:
    level: str            # "safe" (green) | "alert" (red) | "stopped" (grey)
    status_text: str      # the disabled first menu line
    tooltip: str
    running: bool


def _as_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def format_uptime(seconds):
    total = max(0, _as_int(seconds))
    if total >= 3600:
        return "%dh %02dm" % (total // 3600, (total % 3600) // 60)
    if total >= 60:
        return "%dm %02ds" % (total // 60, total % 60)
    return "%ds" % total


def compute_state(status, now=None, stale_after=STALE_AFTER_SECONDS):
    """Turn the (possibly missing / stale / garbage) status dict into what the tray shows. Never raises."""
    now = time.time() if now is None else now
    if not isinstance(status, dict):
        return TrayState("stopped", "Engine stopped", "RansomGuard: engine stopped", False)

    age = now - _as_float(status.get("updated_at"), default=float("-inf"))
    if age > stale_after:
        return TrayState("stopped", "Engine not responding (no heartbeat)",
                         "RansomGuard: engine not responding", False)

    state = str(status.get("status", "")).upper()
    if state not in ("RUNNING", "ALERT"):
        return TrayState("stopped", "Engine stopped", "RansomGuard: engine stopped", False)

    alerts = _as_int(status.get("alerts_triggered"))
    line = "%s | up %s | alerts: %d" % (
        "ALERT" if state == "ALERT" else "Protected", format_uptime(status.get("uptime_sec")), alerts)
    last = str(status.get("last_alert") or "none")
    tooltip = ("RansomGuard: %s\n%.1f events/s\nLast alert: %s" % (state, _as_float(status.get("eps_1s")), last))[:120]
    return TrayState("alert" if state == "ALERT" else "safe", line, tooltip, True)


# ----------------------------------------------------------------- icons (drawn in memory)
COLORS = {"safe": (34, 170, 84), "alert": (214, 48, 49), "stopped": (128, 128, 128)}
SHIELD = [(128, 14), (220, 46), (220, 128), (128, 242), (36, 128), (36, 46)]
BIG = 256                              # draw large, then shrink: smooth, crisp edges
_ICON_CACHE = {}


def _scale_about_center(points, factor, center=(128, 128)):
    return [(center[0] + (x - center[0]) * factor, center[1] + (y - center[1]) * factor)
            for x, y in points]


def _draw_glyph(draw, level):
    white = (255, 255, 255, 255)
    if level == "safe":                                   # check mark
        draw.line([(88, 126), (118, 158), (172, 96)], fill=white, width=20, joint="curve")
    elif level == "alert":                                # exclamation mark
        draw.rounded_rectangle((116, 76, 140, 150), radius=10, fill=white)
        draw.ellipse((114, 164, 142, 192), fill=white)
    else:                                                 # stopped: pause bars
        draw.rounded_rectangle((92, 96, 114, 164), radius=8, fill=white)
        draw.rounded_rectangle((142, 96, 164, 164), radius=8, fill=white)


def make_icon(level, size=64):
    """A shield icon (RGBA) in the colour of `level`. Cached; callers get their own copy."""
    if level not in COLORS:
        level = "stopped"
    cached = _ICON_CACHE.get((level, size))
    if cached is None:
        base = COLORS[level]
        dark = tuple(int(c * 0.6) for c in base)
        big = Image.new("RGBA", (BIG, BIG), (0, 0, 0, 0))
        draw = ImageDraw.Draw(big)
        draw.polygon(SHIELD, fill=dark + (255,))                              # outline
        draw.polygon(_scale_about_center(SHIELD, 0.86), fill=base + (255,))   # body
        _draw_glyph(draw, level)
        resample = getattr(Image, "Resampling", Image).LANCZOS
        cached = big.resize((size, size), resample)
        _ICON_CACHE[(level, size)] = cached
    return cached.copy()


# ----------------------------------------------------------------- helpers
def _run(command, timeout=15):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _wait_for(predicate, timeout, interval=0.25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def is_daemon_cmdline(parts):
    return "engine.daemon" in " ".join(parts or [])


def python_for_background():
    """UNTESTED on real Windows: pythonw.exe (no console window) when it sits next to python.exe."""
    if os.name == "nt":
        candidate = Path(sys.executable).with_name("pythonw.exe")
        if candidate.exists():
            return str(candidate)
    return sys.executable


def acquire_single_instance_lock(port=47653):
    """Holds a localhost port while the tray lives. Returns the socket, or None if another tray has it."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", port))
        return sock
    except OSError:
        sock.close()
        return None


def open_alerts_file(data_dir):
    """Open data/alerts.txt in the default text editor. Returns (ok, message). Never raises."""
    path = Path(data_dir) / ALERTS_NAME
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
    except OSError as error:
        return False, "Cannot create the alerts file: %s" % error
    try:
        if os.name == "nt":
            os.startfile(str(path))                        # UNTESTED on real Windows
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
        return True, "Opened %s" % path.name
    except (OSError, AttributeError) as error:
        return False, "Could not open the alerts file: %s" % error


# ----------------------------------------------------------------- start / stop the engine
class EngineController:
    """Linux: uses the systemd user unit when it is installed, else launches a detached process.
    Windows: launches a detached background process. Methods block, so call them from a worker thread."""

    def __init__(self, project_root, data_dir, service_name="ransomguard.service"):
        self._root = Path(project_root)
        self._data_dir = Path(data_dir)
        self._service = service_name

    def _is_running(self):
        return compute_state(read_status(self._data_dir)).running

    def _is_stopped(self):
        return not self._is_running()

    def service_installed(self):
        if not sys.platform.startswith("linux") or shutil.which("systemctl") is None:
            return False
        result = _run(["systemctl", "--user", "cat", self._service])
        return result is not None and result.returncode == 0

    def _service_active(self):
        result = _run(["systemctl", "--user", "is-active", "--quiet", self._service])
        return result is not None and result.returncode == 0

    def start(self):
        """Returns (ok, message)."""
        if self._is_running():
            return True, "Engine already running"
        if self.service_installed():
            result = _run(["systemctl", "--user", "start", self._service], timeout=30)
            if result is None or result.returncode != 0:
                detail = (result.stderr.strip() if result is not None and result.stderr else "systemctl failed")
                return False, "Could not start the service: %s" % detail[:80]
        else:
            ok, message = self._spawn_daemon()
            if not ok:
                return False, message
        if _wait_for(self._is_running, 10.0):
            return True, "Engine started"
        return False, "No heartbeat yet: see data/daemon.log or journalctl --user -u %s" % self._service

    def stop(self):
        """Returns (ok, message). Clean stop first; terminating the process is the last resort."""
        if self.service_installed() and self._service_active():
            result = _run(["systemctl", "--user", "stop", self._service], timeout=30)
            if result is None or result.returncode != 0:
                return False, "systemctl stop failed"
        else:
            request_stop(self._data_dir)
            if not _wait_for(self._is_stopped, 8.0) and not self._terminate_verified_daemon():
                return False, "Engine did not stop"
        if _wait_for(self._is_stopped, 8.0):
            return True, "Engine stopped"
        return False, "Engine still running"

    def _spawn_daemon(self):
        try:
            self._data_dir.mkdir(parents=True, exist_ok=True)
            command = [python_for_background(), "-m", "engine.daemon", "--data-dir", str(self._data_dir)]
            kwargs = {"cwd": str(self._root), "stdin": subprocess.DEVNULL, "close_fds": True}
            if os.name == "nt":
                kwargs["creationflags"] = WINDOWS_DETACHED_FLAGS      # UNTESTED on real Windows
            else:
                kwargs["start_new_session"] = True                    # survives the tray quitting
            with open(self._data_dir / "daemon.log", "ab") as log_file:
                kwargs["stdout"] = log_file
                kwargs["stderr"] = log_file
                subprocess.Popen(command, **kwargs)
            return True, "Launched"
        except OSError as error:
            return False, "Could not launch the engine: %s" % error

    def _terminate_verified_daemon(self):
        """Last resort. Only acts on a process whose pid, start time AND command line match our daemon.
        On Windows terminate() is TerminateProcess: UNTESTED on real Windows."""
        status = read_status(self._data_dir) or {}
        try:
            proc = psutil.Process(int(status["pid"]))
            if abs(proc.create_time() - float(status["pid_create_time"])) > 1.0:
                return False
            if not is_daemon_cmdline(proc.cmdline()):
                return False
            proc.terminate()
            try:
                proc.wait(5)
            except psutil.TimeoutExpired:
                proc.kill()
            return True
        except (KeyError, TypeError, ValueError, psutil.Error):
            return False