"""
engine/backup_guard.py -- Stage 5: DETECT backup-destroying commands. It only READS command lines.
It never executes, stops or changes anything.

Wire it into the aggregator (sets backup_kill_cmd = 1 for 5 s after a match):
    aggregator = Aggregator()
    runner = BackupGuardRunner(BackupGuard(), lambda m: aggregator.note_backup_kill(time.monotonic()))
    runner.start() ... runner.stop()
"""

import os
import re
import threading
from dataclasses import dataclass

import psutil

DEFAULT_PATTERNS = (
    ("vssadmin delete shadows", r"vssadmin(?:\.exe)?\s+delete\s+shadows"),
    ("wmic shadowcopy delete", r"wmic(?:\.exe)?\b.*\bshadowcopy\b.*\bdelete\b"),
    ("wbadmin delete catalog/backup",
     r"wbadmin(?:\.exe)?\s+delete\s+(?:catalog|backup|systemstatebackup)"),
    ("bcdedit recoveryenabled no", r"bcdedit(?:\.exe)?\b.*\brecoveryenabled\s+(?:no|off)\b"),
    ("bcdedit ignoreallfailures", r"bcdedit(?:\.exe)?\b.*\bbootstatuspolicy\s+ignoreallfailures\b"),
    ("powershell Win32_ShadowCopy delete",
     r"(?:powershell|pwsh)(?:\.exe)?\b.*win32_shadowcopy.*delete"),
    ("btrfs subvolume delete", r"\bbtrfs\s+subvolume\s+delete\b"),
    ("timeshift --delete", r"\btimeshift\b.*--delete\b"),
)


@dataclass(frozen=True)
class BackupMatch:
    pid: int
    name: str
    pattern: str
    create_time: float = 0.0     # keep it: contain(pid, expected_create_time=...) detects PID reuse
    cmdline: str = ""


def backup_kill_flag(matches):
    """The backup_kill_cmd feature value: 1 if anything matched, else 0."""
    return 1 if matches else 0


class BackupGuard:
    def __init__(self, backup_paths=(), own_pid=None, iter_func=psutil.process_iter):
        self._patterns = [(label, re.compile(rx, re.IGNORECASE)) for label, rx in DEFAULT_PATTERNS]
        for path in backup_paths:        # "rm -r ..." (any flag containing r) on a backup path
            rx = r"\brm\b(?=.*\s(?:-[a-z]*r[a-z]*|--recursive)(?:\s|$)).*" + re.escape(path)
            self._patterns.append(("rm -r on backup path %s" % path, re.compile(rx, re.IGNORECASE)))
        self._own_pid = own_pid if own_pid is not None else os.getpid()
        self._iter_func = iter_func      # injectable for tests

    def match_text(self, text):
        """Label of the first pattern that matches this command line, or None."""
        for label, regex in self._patterns:
            if regex.search(text):
                return label
        return None

    def scan(self):
        """One pass over all processes. Returns a list of BackupMatch. Never raises."""
        matches = []
        try:
            for proc in self._iter_func(["pid", "name", "cmdline", "create_time"]):
                info = proc.info
                if info.get("pid") == self._own_pid:
                    continue
                parts = info.get("cmdline")
                if not parts:                # None = AccessDenied, [] = no command line
                    continue
                text = " ".join(parts)
                label = self.match_text(text)
                if label:
                    matches.append(BackupMatch(
                        pid=info["pid"], name=info.get("name") or "", pattern=label,
                        create_time=info.get("create_time") or 0.0, cmdline=text))
        except psutil.Error:
            pass
        return matches


class BackupGuardRunner:
    """Polls guard.scan() every `interval` seconds; calls on_match(match) once per process+pattern."""

    def __init__(self, guard, on_match, interval=1.0):
        self._guard = guard
        self._on_match = on_match
        self._interval = interval
        self._thread = None
        self._stop_event = threading.Event()
        self.last_error = None

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("BackupGuardRunner is already running")
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="backup-guard", daemon=True)
        self._thread.start()

    def stop(self, timeout=5.0):
        thread = self._thread
        if thread is None:
            return True
        self._stop_event.set()
        thread.join(timeout)
        finished = not thread.is_alive()
        if finished:
            self._thread = None
        return finished

    def _run(self):
        seen = set()
        while True:
            try:
                for match in self._guard.scan():
                    key = (match.pid, match.create_time, match.pattern)
                    if key not in seen:
                        seen.add(key)
                        self._on_match(match)
                if len(seen) > 10000:
                    seen.clear()
            except Exception as error:       # keep polling no matter what
                self.last_error = repr(error)
            if self._stop_event.wait(self._interval):
                break