"""
engine/daemon.py -- the HEADLESS RansomGuard engine. No GUI code lives in this process.

Runs sensor -> aggregator -> inspection worker -> backup guard -> model, and writes
data/status.json once per second. The tray app only READS that file.
It ALERTS only (notification + data/alerts.txt); it never kills anything by itself.

    python -m engine.daemon [--watch FOLDER ...] [--data-dir DIR] [--no-model]
Stop it with SIGTERM / Ctrl+C or the tray's stop-request file. Exit code 0 = clean stop.
Limit: watching a huge folder tree can exceed fs.inotify.max_user_watches on Linux.
"""

import argparse
import logging
import logging.handlers
import os
import queue
import signal
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import psutil  # noqa: E402

from engine.aggregator import Aggregator, AggregatorRunner  # noqa: E402
from engine.alert_gate import AlertGate  # noqa: E402
from engine.alerts import send_alert  # noqa: E402
from engine.backup_guard import BackupGuard, BackupGuardRunner  # noqa: E402
from engine.features_schema import FEATURE_NAMES  # noqa: E402
from engine.inspection_worker import InspectionWorker  # noqa: E402
from engine.inspector import Inspector  # noqa: E402
from engine.sensor import FileSensor  # noqa: E402
from engine.status_file import (  # noqa: E402
    ALERTS_NAME, STATUS_NAME, clear_stop_request, default_data_dir, read_status,
    stop_requested, write_status)

HEARTBEAT_SECONDS = 1.0
EPS_INDEX = FEATURE_NAMES.index("events_per_sec_1s")

log = logging.getLogger("ransomguard.engine")
alerts_log = logging.getLogger("ransomguard.alerts")


def setup_logging(data_dir, level):
    if sys.stderr is not None:
        handler = logging.StreamHandler()                       # systemd captures this in the journal
    else:                                                       # pythonw.exe has no console
        handler = logging.handlers.RotatingFileHandler(
            data_dir / "daemon.log", maxBytes=500000, backupCount=2, encoding="utf-8")
    logging.basicConfig(level=level, handlers=[handler],
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    alerts_handler = logging.handlers.RotatingFileHandler(
        data_dir / ALERTS_NAME, maxBytes=1000000, backupCount=3, encoding="utf-8")
    alerts_handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
    alerts_log.addHandler(alerts_handler)


class EngineDaemon:
    def __init__(self, args):
        self.args = args
        self.data_dir = Path(args.data_dir)
        self._stop = threading.Event()
        self._lock = threading.Lock()                # protects the counters below
        self._started = time.monotonic()
        self._created = psutil.Process().create_time()
        self._alerts_triggered = 0
        self._last_alert = ""
        self._last_alert_epoch = None
        self._alert_until = 0.0                      # monotonic time until which status says ALERT
        self._eps = 0.0
        self._model_errors = 0
        self._status_failing = False
        self._predictor = None
        self._gate = None
        self._aggregator = None
        self._runner = None
        self._watching = []
        self._warnings = []

    # ------------------------------------------------------------ main flow
    def run(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        setup_logging(self.data_dir, self.args.log_level)
        if self._another_instance_running():
            log.error("another engine is already running (see %s)", self.data_dir / STATUS_NAME)
            return 3
        try:
            self._gate = AlertGate(self.args.alert_window, self.args.alert_needed,
                                   self.args.alert_cooldown)
            watch = self._watch_folders()
        except (ValueError, OSError) as error:
            log.error("bad configuration: %s", error)
            return 2

        clear_stop_request(self.data_dir)            # a leftover request from last time must not stop us
        self._install_signal_handlers()
        self._predictor = self._load_predictor()

        ignore = [self.data_dir] + [Path(p).expanduser() for p in self.args.ignore]
        sensor = FileSensor(watch_paths=watch, ignore_paths=ignore)
        worker = InspectionWorker(Inspector(), tick_seconds=self.args.tick)
        self._aggregator = Aggregator()
        self._runner = AggregatorRunner(
            self._aggregator, sensor.event_queue, tick_seconds=self.args.tick,
            inspection_queue=worker.output_queue, event_hook=worker.submit)
        guard = BackupGuardRunner(BackupGuard(backup_paths=self.args.backup_path),
                                  self._on_backup_match, interval=1.0)

        exit_code = 0
        try:
            worker.start()
            self._runner.start()
            guard.start()
            sensor.start()
            for warning in sensor.startup_warnings:
                log.warning(warning)
            log.info("engine running, watching %s", self._watching)
            self._heartbeat_loop()
        except Exception:
            log.exception("engine failed")
            exit_code = 1
        finally:
            self._write_status("STOPPING")
            sensor.stop()                            # producer first, then the consumers
            self._runner.stop()
            guard.stop()
            worker.stop()
            self._write_status("STOPPED")
            clear_stop_request(self.data_dir)
            log.info("engine stopped")
        return exit_code

    def _heartbeat_loop(self):
        self._write_status("RUNNING")
        while not self._stop.wait(HEARTBEAT_SECONDS):
            if stop_requested(self.data_dir):
                log.info("stop requested through the control file")
                break
            self._drain_rows()
            self._write_status()

    # ------------------------------------------------------------ detection
    def _drain_rows(self):
        while True:
            try:
                row = self._runner.output_queue.get_nowait()
            except queue.Empty:
                return
            if row.source_key != "global":
                continue
            self._eps = float(row.values[EPS_INDEX])
            if self._predictor is None:
                continue
            result = self._predictor.predict_detailed(row)
            if not result.ok:
                self._model_errors += 1
                continue
            if self._gate.update(result.is_ransomware, time.monotonic()):
                self._fire_alert("Suspicious file activity detected (model score %.2f)"
                                 % result.probability)

    def _on_backup_match(self, match):
        """Runs in the backup-guard thread."""
        if self._aggregator is not None:
            self._aggregator.note_backup_kill(time.monotonic())
        self._fire_alert("Backup-destroying command detected: %s (pid %d, %s)"
                         % (match.pattern, match.pid, match.name or "?"))

    def _fire_alert(self, message, severity="critical"):
        with self._lock:
            self._alerts_triggered += 1
            self._last_alert = "%s %s" % (time.strftime("%H:%M:%S"), message)
            self._last_alert_epoch = time.time()
            self._alert_until = time.monotonic() + self.args.alert_hold
        alerts_log.warning(message)
        try:
            send_alert("RansomGuard", message, severity)
        except Exception:                            # send_alert should never raise; be safe anyway
            log.exception("could not show the notification")

    # ------------------------------------------------------------ status file
    def _write_status(self, state=None):
        with self._lock:
            if state is None:
                state = "ALERT" if time.monotonic() < self._alert_until else "RUNNING"
            payload = {
                "schema": 1,
                "status": state,                                     # RUNNING | ALERT | STOPPING | STOPPED
                "uptime_sec": int(time.monotonic() - self._started),
                "eps_1s": round(self._eps, 2),
                "alerts_triggered": self._alerts_triggered,
                "last_alert": self._last_alert,
                "last_alert_time": self._last_alert_epoch,
                "pid": os.getpid(),
                "pid_create_time": self._created,
                "updated_at": time.time(),
                "model": "loaded" if self._predictor is not None else "not loaded",
                "model_errors": self._model_errors,
                "watching": self._watching,
                "warnings": self._warnings[:5],
            }
        ok = write_status(self.data_dir, payload)
        if not ok and not self._status_failing:
            log.warning("cannot write %s", self.data_dir / STATUS_NAME)
        self._status_failing = not ok

    # ------------------------------------------------------------ setup helpers
    def _watch_folders(self):
        folders = self.args.watch or [str(PROJECT_ROOT / "sandbox")]
        result = []
        for folder in folders:
            path = Path(folder).expanduser()
            if not self.args.watch:                  # only the built-in default folder is created for you
                path.mkdir(parents=True, exist_ok=True)
            if not path.is_dir():
                raise OSError("watch folder does not exist: %s" % path)
            result.append(path)
        self._watching = [str(p) for p in result]
        return result

    def _load_predictor(self):
        if self.args.no_model:
            self._warnings.append("model disabled (--no-model)")
            return None
        try:
            from engine.model import Predictor           # imported here so a missing sklearn cannot stop the engine
            predictor = Predictor(Path(self.args.model), Path(self.args.meta))
            self._warnings.extend(predictor.warnings)
            return predictor
        except Exception as error:
            message = "model not loaded: %s" % error
            log.warning(message)
            self._warnings.append(message)
            return None

    def _another_instance_running(self):
        status = read_status(self.data_dir)
        if not status or status.get("status") not in ("RUNNING", "ALERT"):
            return False
        try:
            if time.time() - float(status["updated_at"]) > 5.0:
                return False                                  # stale file from a crashed engine
            pid = int(status["pid"])
            if pid == os.getpid():
                return False
            proc = psutil.Process(pid)
            return abs(proc.create_time() - float(status["pid_create_time"])) < 1.0
        except (KeyError, TypeError, ValueError, psutil.Error):
            return False

    def _install_signal_handlers(self):
        for name in ("SIGTERM", "SIGINT", "SIGBREAK"):       # SIGBREAK exists on Windows only
            number = getattr(signal, name, None)
            if number is None:
                continue
            try:
                signal.signal(number, self._on_signal)
            except (ValueError, OSError):
                pass

    def _on_signal(self, _signum, _frame):
        self._stop.set()


def parse_args(argv=None):
    from engine.model import DEFAULT_META_PATH, DEFAULT_MODEL_PATH
    parser = argparse.ArgumentParser(description="RansomGuard headless engine")
    parser.add_argument("--watch", action="append", default=None,
                        help="folder to watch (repeatable). Default: <project>/sandbox")
    parser.add_argument("--ignore", action="append", default=[], help="folder to ignore (repeatable)")
    parser.add_argument("--backup-path", action="append", default=[],
                        help="folder whose recursive 'rm' should count as a backup attack (repeatable)")
    parser.add_argument("--data-dir", default=str(default_data_dir()))
    parser.add_argument("--model", default=str(DEFAULT_MODEL_PATH))
    parser.add_argument("--meta", default=str(DEFAULT_META_PATH))
    parser.add_argument("--no-model", action="store_true")
    parser.add_argument("--tick", type=float, default=1.0)
    parser.add_argument("--alert-window", type=int, default=5)
    parser.add_argument("--alert-needed", type=int, default=3)
    parser.add_argument("--alert-cooldown", type=float, default=60.0)
    parser.add_argument("--alert-hold", type=float, default=120.0,
                        help="seconds the status stays ALERT (tray icon stays red) after an alert")
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args(argv)


def main(argv=None):
    return EngineDaemon(parse_args(argv)).run()


if __name__ == "__main__":
    sys.exit(main())