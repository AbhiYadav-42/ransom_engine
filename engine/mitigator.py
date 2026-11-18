"""
engine/mitigator.py -- Stage 5: contain a process tree and quarantine files.

SAFETY: dry_run is ON by default. Hard protections (own pid, parent chain, system pids,
critical process names) are module constants: no config can remove them.
Limit: a process we cannot read (AccessDenied) is skipped, never forced.
"""

import json
import logging
import os
import shutil
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import psutil

log = logging.getLogger("engine.mitigator")

CREATE_TIME_TOLERANCE = 0.5     # seconds; a bigger difference means the PID was reused
WAIT_TIMEOUT_SECONDS = 3

# Names (lower case, without ".exe") that are NEVER touched.
LINUX_PROTECTED_STEMS = frozenset([
    "serpantinum", "serpantinumd", "quickshell", "hyprland",
    "systemd", "init", "dbus-daemon", "dbus-broker", "sshd", "xorg", "xwayland",
    "kitty", "alacritty", "foot", "wezterm", "wezterm-gui", "konsole",
    "gnome-terminal", "gnome-terminal-server", "xterm", "tmux",
    "code", "codium", "cursor", "nvim", "vim", "emacs", "zed", "pycharm",
])
# --- UNTESTED on real Windows ---
WINDOWS_PROTECTED_STEMS = frozenset([
    "explorer", "winlogon", "csrss", "svchost", "msmpeng", "lsass", "services",
    "wininit", "smss", "dwm", "system", "windowsterminal", "wt", "conhost",
])
PROTECTED_STEMS = LINUX_PROTECTED_STEMS | WINDOWS_PROTECTED_STEMS


@dataclass
class MitigatorConfig:
    dry_run: bool = True                 # True = only log what would happen
    allowlist_names: tuple = ()          # process names that are never touched
    allowlist_pids: tuple = ()           # PIDs that are never touched
    max_kills_per_minute: int = 5        # how many contain() actions per minute
    quarantine_dir: str = "quarantine"   # add this folder to FileSensor's ignore_paths too


@dataclass
class ContainResult:
    pid: int
    reason: str = ""
    dry_run: bool = True
    contained: bool = False              # True only if every targeted process is gone
    steps: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    killed_pids: list = field(default_factory=list)


@dataclass
class QuarantineResult:
    pid: int
    score: float
    dry_run: bool = True
    moved: list = field(default_factory=list)      # (original, quarantined) pairs
    steps: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def get_create_time(pid):
    """Store this next to a PID so contain() can detect PID reuse later."""
    try:
        return psutil.Process(pid).create_time()
    except psutil.Error:
        return None


def _name_stem(name):
    name = name.lower()
    return name[:-4] if name.endswith(".exe") else name


def _matches_protected(stem):
    if stem in PROTECTED_STEMS:
        return True
    # Linux cuts process names to 15 characters ("gnome-terminal-").
    return len(stem) == 15 and any(p.startswith(stem) for p in PROTECTED_STEMS)


def _always_protected_pids():
    """Pid 0/1/4, ourselves, our parent and every ancestor (shell, terminal, editor)."""
    pids = set([0, 1, 4, os.getpid(), os.getppid()])
    try:
        for parent in psutil.Process().parents():
            pids.add(parent.pid)
    except psutil.Error:
        pass
    return pids


class Mitigator:
    def __init__(self, config=None, clock=time.monotonic, sleep=time.sleep,
                 process_factory=psutil.Process, wait_func=psutil.wait_procs):
        self.config = config if config is not None else MitigatorConfig()
        self._clock = clock
        self._sleep = sleep
        self._process_factory = process_factory      # injectable for tests
        self._wait_func = wait_func                  # injectable for tests
        self._kill_times = deque()
        self._lock = threading.Lock()

    # ------------------------------------------------------------ contain
    def contain(self, pid, reason="", expected_create_time=None):
        """Suspend the process and its whole tree, kill children first, wait, report.
        Never raises: everything ends up in the returned ContainResult."""
        result = ContainResult(pid=pid, reason=reason, dry_run=self.config.dry_run)
        try:
            self._contain(pid, result, expected_create_time)
        except Exception as error:
            result.errors.append("unexpected error: %r" % (error,))
        return result

    def _contain(self, pid, result, expected_create_time):
        # 1. find the process and read its start time
        try:
            proc = self._process_factory(pid)
            created = proc.create_time()
        except psutil.ZombieProcess:
            result.skipped.append("process is a zombie (already dead)")
            return
        except psutil.NoSuchProcess:
            result.skipped.append("no such process")
            return
        except psutil.AccessDenied:
            result.skipped.append("access denied reading process info")
            return

        # 2. PID reuse check
        if expected_create_time is not None and \
                abs(created - expected_create_time) > CREATE_TIME_TOLERANCE:
            result.skipped.append("pid %d was reused by another process (create_time changed)" % pid)
            return

        # 3. hard protections, then the allowlist
        why = self._protection_reason(proc) or self._allowlist_reason(proc)
        if why:
            result.skipped.append(why)
            return

        # 4. dry run: only say what would happen (does not use the rate limit)
        if self.config.dry_run:
            children = self._list_children(proc, result)
            self._note(result, "DRY RUN: would suspend pids %s"
                       % ([proc.pid] + [c.pid for c in children]))
            self._note(result, "DRY RUN: would kill children first %s, then pid %d"
                       % ([c.pid for c in children], proc.pid))
            return

        # 5. rate limit
        if not self._take_kill_slot():
            result.skipped.append("rate limit: more than %d actions in the last minute"
                                  % self.config.max_kills_per_minute)
            return

        # 6. suspend the parent first (a frozen parent cannot start new children),
        #    then list and suspend the children, kill children first, then the parent.
        self._suspend(proc, result)
        children = self._list_children(proc, result)
        for child in children:
            self._suspend(child, result)
        for child in children:
            self._kill(child, result, "child")
        self._kill(proc, result, "target")
        self._wait_and_report([proc] + children, result)

    def _protection_reason(self, proc):
        if proc.pid in _always_protected_pids():
            return "protected: own process, parent chain or system pid (%d)" % proc.pid
        try:
            stem = _name_stem(proc.name())
        except psutil.AccessDenied:
            return "protected: cannot read the name of pid %d (access denied)" % proc.pid
        except psutil.NoSuchProcess:
            return None
        if _matches_protected(stem):
            return "protected: critical process name '%s'" % stem
        return None

    def _allowlist_reason(self, proc):
        if proc.pid in self.config.allowlist_pids:
            return "allowlisted: pid %d" % proc.pid
        try:
            stem = _name_stem(proc.name())
        except psutil.Error:
            return None
        if stem in [_name_stem(n) for n in self.config.allowlist_names]:
            return "allowlisted: name '%s'" % stem
        return None

    def _list_children(self, proc, result):
        try:
            children = proc.children(recursive=True)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
            result.errors.append("could not list children: %r" % (error,))
            return []
        kept = []
        for child in children:
            why = self._protection_reason(child) or self._allowlist_reason(child)
            if why:
                result.skipped.append("child pid %d skipped, %s" % (child.pid, why))
            else:
                kept.append(child)
        return kept

    def _take_kill_slot(self):
        now = self._clock()
        with self._lock:
            while self._kill_times and now - self._kill_times[0] >= 60.0:
                self._kill_times.popleft()
            if len(self._kill_times) >= self.config.max_kills_per_minute:
                return False
            self._kill_times.append(now)
            return True

    def _suspend(self, proc, result):
        try:
            proc.suspend()
            self._note(result, "suspended pid %d" % proc.pid)
        except psutil.ZombieProcess:
            result.skipped.append("pid %d is a zombie" % proc.pid)
        except psutil.NoSuchProcess:
            result.skipped.append("pid %d already gone" % proc.pid)
        except psutil.AccessDenied:
            result.errors.append("access denied suspending pid %d" % proc.pid)

    def _kill(self, proc, result, label):
        try:
            proc.kill()    # POSIX: SIGKILL. Windows: TerminateProcess (UNTESTED on real Windows).
            self._note(result, "killed %s pid %d" % (label, proc.pid))
        except psutil.ZombieProcess:
            result.skipped.append("pid %d is a zombie" % proc.pid)
        except psutil.NoSuchProcess:
            result.skipped.append("pid %d already gone" % proc.pid)
        except psutil.AccessDenied:
            result.errors.append("access denied killing pid %d" % proc.pid)

    def _wait_and_report(self, family, result):
        try:
            _gone, alive = self._wait_func(family, timeout=WAIT_TIMEOUT_SECONDS)
        except Exception as error:
            result.errors.append("wait failed: %r" % (error,))
            return
        still = [p for p in alive if not self._is_dead(p)]
        result.killed_pids = [p.pid for p in family if p not in still]
        if still:
            result.errors.append("still alive after %d s: %s"
                                 % (WAIT_TIMEOUT_SECONDS, [p.pid for p in still]))
        else:
            self._note(result, "all %d processes are gone" % len(family))
        result.contained = not still

    def _is_dead(self, proc):
        try:
            return proc.status() == psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            return True
        except psutil.AccessDenied:
            return False

    def _note(self, result, text):
        result.steps.append(text)
        log.warning(text)

    # --------------------------------------------------------- quarantine
    def quarantine_files(self, paths, pid, score, expected_create_time=None):
        """Move files into quarantine_dir (+ a JSON record each). Only after the process is stopped.
        Never raises."""
        result = QuarantineResult(pid=pid, score=score, dry_run=self.config.dry_run)
        try:
            self._quarantine(paths, pid, score, expected_create_time, result)
        except Exception as error:
            result.errors.append("unexpected error: %r" % (error,))
        return result

    def _quarantine(self, paths, pid, score, expected_create_time, result):
        if self._still_running(pid, expected_create_time):
            result.errors.append("process %d is still running; contain() it first" % pid)
            return
        quarantine = Path(self.config.quarantine_dir)
        if not self.config.dry_run:
            quarantine.mkdir(parents=True, exist_ok=True)

        for raw in paths:
            source = Path(raw)
            if source.is_symlink():
                result.skipped.append("%s: symlink" % source)
                continue
            if not source.exists():
                result.skipped.append("%s: missing" % source)
                continue
            if not source.is_file():
                result.skipped.append("%s: not a regular file" % source)
                continue
            if quarantine.resolve() in source.resolve().parents:
                result.skipped.append("%s: already in quarantine" % source)
                continue
            if self.config.dry_run:
                text = "DRY RUN: would move %s into %s" % (source, quarantine)
                result.steps.append(text)
                log.warning(text)
                continue

            stamp = time.strftime("%Y%m%d-%H%M%S")
            dest = quarantine / ("%s_pid%d_%s_%s" % (stamp, pid, uuid.uuid4().hex[:8], source.name))
            try:
                self._move_with_retry(str(source), str(dest))
            except Exception as error:
                result.errors.append("could not move %s: %r" % (source, error))
                continue
            record = {"original_path": str(source), "quarantined_path": str(dest),
                      "time": time.time(), "time_iso": time.strftime("%Y-%m-%d %H:%M:%S"),
                      "pid": pid, "score": score}
            try:
                with open(str(dest) + ".json", "w") as handle:
                    json.dump(record, handle, indent=2)
            except OSError as error:
                result.errors.append("moved, but could not write the record for %s: %r" % (dest, error))
            result.moved.append((str(source), str(dest)))
            log.warning("quarantined %s -> %s", source, dest)

    def _still_running(self, pid, expected_create_time):
        try:
            proc = self._process_factory(pid)
            if proc.status() == psutil.STATUS_ZOMBIE:
                return False
            if expected_create_time is not None and \
                    abs(proc.create_time() - expected_create_time) > CREATE_TIME_TOLERANCE:
                return False                 # the pid belongs to a different process now
            return True
        except psutil.NoSuchProcess:
            return False
        except psutil.AccessDenied:
            return True                      # cannot tell: be safe and refuse

    # --- UNTESTED on real Windows (sharing violations are the usual PermissionError) ---
    def _move_with_retry(self, src, dest):
        try:
            shutil.move(src, dest)
        except PermissionError:
            self._sleep(0.2)
            shutil.move(src, dest)           # one retry; a second error reaches the caller