"""Mitigator tests. Real kills happen ONLY to sleepers spawned here; everything else uses fakes."""

import json
import os
import subprocess
import sys
import time
from unittest import mock

import psutil

from engine.mitigator import Mitigator, MitigatorConfig, get_create_time

SLEEP_CODE = "import time; time.sleep(120)"
FAMILY_CODE = (
    "import subprocess, sys, time\n"
    "kids = [subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']) for _ in range(2)]\n"
    "time.sleep(120)\n"
)


# ----- helpers --------------------------------------------------------------
def spawn_sleeper():
    return subprocess.Popen([sys.executable, "-c", SLEEP_CODE])


def spawn_family():
    parent = subprocess.Popen([sys.executable, "-c", FAMILY_CODE])
    deadline = time.time() + 10
    while time.time() < deadline:
        if len(psutil.Process(parent.pid).children(recursive=True)) >= 2:
            break
        time.sleep(0.05)
    return parent


def cleanup(*procs):
    """Safety net: kill ONLY what this test spawned."""
    for proc in procs:
        try:
            for child in psutil.Process(proc.pid).children(recursive=True):
                child.kill()
        except psutil.Error:
            pass
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass


def is_gone(pid):
    try:
        return psutil.Process(pid).status() == psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return True


def dead_pid():
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeProc:
    """Stands in for psutil.Process; records suspend/kill calls."""

    def __init__(self, pid, name="evil.exe", children=None, fail_suspend=False, fail_kill=False):
        self.pid = pid
        self._name = name
        self._children = children or []
        self.fail_suspend = fail_suspend
        self.fail_kill = fail_kill
        self.calls = []

    def name(self):
        return self._name

    def create_time(self):
        return 5000.0

    def children(self, recursive=False):
        return list(self._children)

    def suspend(self):
        if self.fail_suspend:
            raise psutil.AccessDenied(self.pid)
        self.calls.append("suspend")

    def kill(self):
        if self.fail_kill:
            raise psutil.AccessDenied(self.pid)
        self.calls.append("kill")

    def status(self):
        return psutil.STATUS_ZOMBIE if "kill" in self.calls else psutil.STATUS_RUNNING


def factory_for(fakes):
    def factory(pid):
        if pid not in fakes:
            raise psutil.NoSuchProcess(pid)
        return fakes[pid]
    return factory


def fake_wait(procs, timeout=None):
    return list(procs), []


def stuck_wait(procs, timeout=None):
    return [], list(procs)


def make_mitigator(fakes, clock=None, wait_func=fake_wait, **config_kwargs):
    if clock is None:
        clock = FakeClock()
    return Mitigator(MitigatorConfig(**config_kwargs), clock=clock, sleep=lambda s: None,
                     process_factory=factory_for(fakes), wait_func=wait_func)


# ----- config, dry run, real kill ------------------------------------------
def test_defaults_are_safe():
    config = MitigatorConfig()
    assert config.dry_run is True
    assert config.max_kills_per_minute >= 1


def test_dry_run_changes_nothing():
    proc = spawn_sleeper()
    try:
        result = Mitigator(MitigatorConfig(dry_run=True)).contain(proc.pid, "test")
        assert result.dry_run is True
        assert result.contained is False
        assert any(step.startswith("DRY RUN") for step in result.steps)
        time.sleep(0.2)
        assert proc.poll() is None
        assert psutil.Process(proc.pid).status() != psutil.STATUS_STOPPED
    finally:
        cleanup(proc)


def test_real_contain_kills_the_whole_tree_children_first():
    parent = spawn_family()
    try:
        family = [parent.pid] + [c.pid for c in psutil.Process(parent.pid).children(recursive=True)]
        assert len(family) == 3
        created = get_create_time(parent.pid)
        result = Mitigator(MitigatorConfig(dry_run=False)).contain(
            parent.pid, "test", expected_create_time=created)
        assert result.contained is True
        assert sorted(result.killed_pids) == sorted(family)
        assert all(is_gone(pid) for pid in family)
        steps = result.steps
        assert steps[0] == "suspended pid %d" % parent.pid
        child_kills = [i for i, s in enumerate(steps) if s.startswith("killed child")]
        target_kills = [i for i, s in enumerate(steps) if s.startswith("killed target")]
        assert len(child_kills) == 2 and len(target_kills) == 1
        assert max(child_kills) < target_kills[0]
    finally:
        cleanup(parent)


# ----- allowlist ------------------------------------------------------------
def test_allowlisted_name_is_skipped():
    proc = spawn_sleeper()
    try:
        name = psutil.Process(proc.pid).name()
        result = Mitigator(MitigatorConfig(dry_run=False, allowlist_names=(name,))).contain(proc.pid)
        assert any("allowlist" in s for s in result.skipped)
        assert result.contained is False
        time.sleep(0.2)
        assert proc.poll() is None
    finally:
        cleanup(proc)


def test_allowlisted_pid_is_skipped():
    proc = spawn_sleeper()
    try:
        result = Mitigator(MitigatorConfig(dry_run=False, allowlist_pids=(proc.pid,))).contain(proc.pid)
        assert any("allowlist" in s for s in result.skipped)
        time.sleep(0.2)
        assert proc.poll() is None
    finally:
        cleanup(proc)


# ----- hard protections -----------------------------------------------------
def test_own_parent_and_system_pids_are_protected():
    mitigator = Mitigator(MitigatorConfig(dry_run=True))
    for pid in (os.getpid(), os.getppid(), 1, 4):
        result = mitigator.contain(pid)
        assert result.steps == []
        assert result.skipped != []
        assert result.contained is False
    assert any("protected" in s for s in mitigator.contain(os.getpid()).skipped)


def test_protected_names_are_refused():
    names = ["svchost.exe", "EXPLORER.EXE", "winlogon.exe", "csrss.exe", "MsMpEng.exe",
             "hyprland", "Hyprland", "quickshell", "serpantinum", "kitty", "code", "code.exe"]
    fakes = {}
    for index, name in enumerate(names):
        fakes[880200 + index] = FakeProc(880200 + index, name)
    mitigator = make_mitigator(fakes, dry_run=False)
    for pid, fake in fakes.items():
        result = mitigator.contain(pid)
        assert fake.calls == []
        assert any("protected" in s for s in result.skipped)


def test_name_cut_to_15_characters_is_still_protected():
    fake = FakeProc(880300, "gnome-terminal-")
    mitigator = make_mitigator({880300: fake}, dry_run=False)
    result = mitigator.contain(880300)
    assert fake.calls == []
    assert any("protected" in s for s in result.skipped)


def test_protected_child_is_skipped_but_siblings_are_killed():
    worker = FakeProc(880011, "worker.exe")
    system = FakeProc(880012, "svchost.exe")
    parent = FakeProc(880010, "evil.exe", children=[worker, system])
    mitigator = make_mitigator({880010: parent}, dry_run=False)
    result = mitigator.contain(880010)
    assert parent.calls == ["suspend", "kill"]
    assert worker.calls == ["suspend", "kill"]
    assert system.calls == []
    assert any("880012" in s for s in result.skipped)


# ----- errors never raise ---------------------------------------------------
def test_access_denied_is_reported_not_raised():
    fake = FakeProc(880020, "evil.exe", fail_suspend=True, fail_kill=True)
    mitigator = make_mitigator({880020: fake}, wait_func=stuck_wait, dry_run=False)
    result = mitigator.contain(880020)
    assert result.contained is False
    assert any("access denied" in e for e in result.errors)


def test_missing_and_zombie_processes_are_skipped():
    result = Mitigator(MitigatorConfig(dry_run=False)).contain(99999999)
    assert any("no such process" in s for s in result.skipped)

    def zombie_factory(pid):
        raise psutil.ZombieProcess(pid)

    mitigator = Mitigator(MitigatorConfig(dry_run=False), process_factory=zombie_factory)
    assert any("zombie" in s for s in mitigator.contain(4321).skipped)


def test_contain_never_raises():
    def broken_factory(pid):
        raise RuntimeError("boom")

    result = Mitigator(MitigatorConfig(dry_run=False), process_factory=broken_factory).contain(4321)
    assert any("unexpected" in e for e in result.errors)


# ----- PID reuse and rate limit --------------------------------------------
def test_pid_reuse_is_detected():
    proc = spawn_sleeper()
    try:
        wrong_time = get_create_time(proc.pid) - 100.0
        result = Mitigator(MitigatorConfig(dry_run=False)).contain(
            proc.pid, expected_create_time=wrong_time)
        assert any("reused" in s for s in result.skipped)
        time.sleep(0.2)
        assert proc.poll() is None
    finally:
        cleanup(proc)


def test_kill_rate_limit_blocks_extra_actions_then_resets():
    clock = FakeClock()
    fakes = dict((880001 + i, FakeProc(880001 + i)) for i in range(4))
    mitigator = make_mitigator(fakes, clock=clock, dry_run=False, max_kills_per_minute=2)
    first = mitigator.contain(880001)
    second = mitigator.contain(880002)
    third = mitigator.contain(880003)
    assert first.contained and second.contained
    assert not third.contained
    assert any("rate limit" in s for s in third.skipped)
    assert fakes[880003].calls == []
    clock.advance(61)
    assert mitigator.contain(880004).contained


def test_dry_run_does_not_use_the_rate_limit():
    fakes = dict((880050 + i, FakeProc(880050 + i)) for i in range(6))
    mitigator = make_mitigator(fakes, dry_run=True, max_kills_per_minute=1)
    for pid in fakes:
        assert not any("rate limit" in s for s in mitigator.contain(pid).skipped)
    mitigator.config.dry_run = False
    assert mitigator.contain(880050).contained
    assert any("rate limit" in s for s in mitigator.contain(880051).skipped)


# ----- quarantine -----------------------------------------------------------
def make_files(folder, names=("a.txt", "b.txt")):
    folder.mkdir(parents=True, exist_ok=True)
    paths = []
    for name in names:
        path = folder / name
        path.write_text("dummy " + name)
        paths.append(path)
    return paths


def test_quarantine_moves_files_and_writes_json_records(tmp_path):
    files = make_files(tmp_path / "work")
    quarantine = tmp_path / "q"
    mitigator = Mitigator(MitigatorConfig(dry_run=False, quarantine_dir=str(quarantine)))
    result = mitigator.quarantine_files([str(f) for f in files], dead_pid(), 0.93)
    assert len(result.moved) == 2
    assert result.errors == []
    assert all(not f.exists() for f in files)
    records = sorted(quarantine.glob("*.json"))
    assert len(records) == 2
    data = json.loads(records[0].read_text())
    for key in ("original_path", "quarantined_path", "time", "pid", "score"):
        assert key in data
    assert data["score"] == 0.93
    assert len([p for p in quarantine.iterdir() if p.suffix != ".json"]) == 2


def test_quarantine_dry_run_moves_nothing(tmp_path):
    files = make_files(tmp_path / "work")
    quarantine = tmp_path / "q"
    mitigator = Mitigator(MitigatorConfig(dry_run=True, quarantine_dir=str(quarantine)))
    result = mitigator.quarantine_files([str(f) for f in files], dead_pid(), 0.9)
    assert result.moved == []
    assert any(s.startswith("DRY RUN") for s in result.steps)
    assert all(f.exists() for f in files)
    assert not quarantine.exists()


def test_quarantine_refuses_while_process_is_alive(tmp_path):
    files = make_files(tmp_path / "work")
    proc = spawn_sleeper()
    try:
        mitigator = Mitigator(MitigatorConfig(dry_run=False, quarantine_dir=str(tmp_path / "q")))
        result = mitigator.quarantine_files([str(f) for f in files], proc.pid, 0.9)
        assert any("still running" in e for e in result.errors)
        assert result.moved == []
        assert all(f.exists() for f in files)
    finally:
        cleanup(proc)


def test_quarantine_gives_unique_names_to_same_filename(tmp_path):
    first = make_files(tmp_path / "d1", names=("x.txt",))[0]
    second = make_files(tmp_path / "d2", names=("x.txt",))[0]
    quarantine = tmp_path / "q"
    mitigator = Mitigator(MitigatorConfig(dry_run=False, quarantine_dir=str(quarantine)))
    result = mitigator.quarantine_files([str(first), str(second)], dead_pid(), 0.9)
    assert len(result.moved) == 2
    names = [p.name for p in quarantine.iterdir() if p.suffix != ".json"]
    assert len(set(names)) == 2


def test_quarantine_skips_missing_directories_and_files_already_quarantined(tmp_path):
    quarantine = tmp_path / "q"
    quarantine.mkdir()
    already = quarantine / "old.txt"
    already.write_text("x")
    folder = tmp_path / "somefolder"
    folder.mkdir()
    mitigator = Mitigator(MitigatorConfig(dry_run=False, quarantine_dir=str(quarantine)))
    result = mitigator.quarantine_files(
        [str(tmp_path / "missing.txt"), str(folder), str(already)], dead_pid(), 0.9)
    assert result.moved == []
    assert len(result.skipped) == 3
    assert already.exists()


def test_quarantine_retries_once_on_permission_error(tmp_path):
    files = make_files(tmp_path / "work", names=("a.txt",))
    mitigator = Mitigator(MitigatorConfig(dry_run=False, quarantine_dir=str(tmp_path / "q")),
                          sleep=lambda s: None)
    with mock.patch("engine.mitigator.shutil.move",
                    side_effect=[PermissionError("busy"), None]) as moved:
        result = mitigator.quarantine_files([str(files[0])], dead_pid(), 0.9)
    assert moved.call_count == 2
    assert len(result.moved) == 1
    assert result.errors == []


def test_quarantine_second_permission_error_is_reported(tmp_path):
    files = make_files(tmp_path / "work", names=("a.txt",))
    mitigator = Mitigator(MitigatorConfig(dry_run=False, quarantine_dir=str(tmp_path / "q")),
                          sleep=lambda s: None)
    with mock.patch("engine.mitigator.shutil.move", side_effect=PermissionError("busy")) as moved:
        result = mitigator.quarantine_files([str(files[0])], dead_pid(), 0.9)
    assert moved.call_count == 2
    assert result.moved == []
    assert any("could not move" in e for e in result.errors)
    assert files[0].exists()