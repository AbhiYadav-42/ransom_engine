"""Backup guard tests. The guard only reads command lines; nothing destructive is ever run."""

import subprocess
import sys
import time
from pathlib import Path
from unittest import mock

from engine.aggregator import Aggregator
from engine.backup_guard import BackupGuard, BackupGuardRunner, BackupMatch, backup_kill_flag
from engine.features_schema import FEATURE_NAMES

DECOY = str(Path(__file__).resolve().parent.parent / "sim" / "decoy_vss.py")


class FakeIterProc:
    def __init__(self, info):
        self.info = info


# ----- regexes --------------------------------------------------------------
def test_vssadmin_delete_shadows_variants():
    guard = BackupGuard()
    for text in ("vssadmin delete shadows /all /quiet", "VSSADMIN.EXE  Delete   Shadows /for=c:",
                 "C:\\Windows\\System32\\vssadmin.exe delete shadows"):
        assert guard.match_text(text) == "vssadmin delete shadows"
    assert guard.match_text("vssadmin list shadows") is None


def test_wmic_shadowcopy_delete():
    guard = BackupGuard()
    assert guard.match_text("wmic shadowcopy delete") == "wmic shadowcopy delete"
    assert guard.match_text('wmic.exe shadowcopy where "ID=\'x\'" delete') == "wmic shadowcopy delete"
    assert guard.match_text("wmic shadowcopy list") is None


def test_wbadmin_delete_catalog_and_backup():
    guard = BackupGuard()
    for text in ("wbadmin delete catalog -quiet", "wbadmin.exe DELETE BACKUP -keepVersions:0",
                 "wbadmin delete systemstatebackup"):
        assert guard.match_text(text) == "wbadmin delete catalog/backup"
    assert guard.match_text("wbadmin get versions") is None


def test_bcdedit_recovery_tampering():
    guard = BackupGuard()
    assert guard.match_text("bcdedit /set {default} recoveryenabled no") == "bcdedit recoveryenabled no"
    assert guard.match_text("bcdedit /set {default} bootstatuspolicy ignoreallfailures") \
        == "bcdedit ignoreallfailures"
    assert guard.match_text("bcdedit /set {default} recoveryenabled yes") is None


def test_powershell_win32_shadowcopy_delete():
    guard = BackupGuard()
    text = "powershell.exe Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }"
    assert guard.match_text(text) == "powershell Win32_ShadowCopy delete"
    assert guard.match_text("powershell.exe Get-WmiObject Win32_ShadowCopy") is None


def test_linux_backup_tools():
    guard = BackupGuard()
    assert guard.match_text("btrfs subvolume delete /snapshots/daily") == "btrfs subvolume delete"
    assert guard.match_text("btrfs subvolume list /") is None
    assert guard.match_text("timeshift --delete --snapshot 2024") == "timeshift --delete"
    assert guard.match_text("timeshift --list") is None


def test_rm_on_a_configured_backup_path():
    guard = BackupGuard(backup_paths=["/mnt/backup"])
    assert guard.match_text("rm -rf /mnt/backup/2024") is not None
    assert guard.match_text("rm -r /mnt/backup") is not None
    assert guard.match_text("rm -fr /mnt/backup") is not None
    assert guard.match_text("rm -rf /tmp/other") is None
    assert guard.match_text("ls /mnt/backup") is None
    assert guard.match_text("rm /mnt/backup/file.txt") is None


def test_rm_pattern_needs_a_configured_path():
    assert BackupGuard().match_text("rm -rf /mnt/backup") is None


# ----- scan -----------------------------------------------------------------
def test_scan_returns_matches_and_skips_own_and_unreadable():
    procs = [
        FakeIterProc({"pid": 101, "name": "vssadmin.exe",
                      "cmdline": ["vssadmin.exe", "Delete", "Shadows", "/all"], "create_time": 5.0}),
        FakeIterProc({"pid": 102, "name": "notepad.exe", "cmdline": ["notepad.exe", "a.txt"],
                      "create_time": 6.0}),
        FakeIterProc({"pid": 103, "name": "secret", "cmdline": None, "create_time": 7.0}),
        FakeIterProc({"pid": 999, "name": "self", "cmdline": ["vssadmin", "delete", "shadows"],
                      "create_time": 8.0}),
    ]
    guard = BackupGuard(own_pid=999, iter_func=lambda attrs: procs)
    matches = guard.scan()
    assert len(matches) == 1
    assert matches[0].pid == 101
    assert matches[0].name == "vssadmin.exe"
    assert matches[0].pattern == "vssadmin delete shadows"
    assert matches[0].create_time == 5.0


def test_scan_never_executes_anything():
    procs = [FakeIterProc({"pid": 101, "name": "vssadmin.exe",
                           "cmdline": ["vssadmin", "delete", "shadows"], "create_time": 5.0})]
    guard = BackupGuard(own_pid=1, iter_func=lambda attrs: procs)
    with mock.patch("subprocess.Popen") as popen, mock.patch("os.system") as system:
        assert len(guard.scan()) == 1
    assert not popen.called
    assert not system.called


def test_backup_kill_flag_is_zero_or_one():
    assert backup_kill_flag([]) == 0
    assert backup_kill_flag([BackupMatch(1, "x", "p")]) == 1


def test_decoy_script_is_detected_by_a_real_scan():
    decoy = subprocess.Popen([sys.executable, DECOY, "vssadmin", "delete", "shadows", "/all", "/quiet"])
    found = []
    try:
        guard = BackupGuard()
        deadline = time.time() + 10
        while time.time() < deadline and not found:
            found = [m for m in guard.scan() if m.pid == decoy.pid]
            time.sleep(0.1)
    finally:
        decoy.kill()
        decoy.wait()
    assert found
    assert found[0].pattern == "vssadmin delete shadows"


# ----- runner ---------------------------------------------------------------
class FakeGuard:
    def __init__(self, results):
        self.results = results
        self.calls = 0

    def scan(self):
        self.calls += 1
        item = self.results[min(self.calls - 1, len(self.results) - 1)]
        if isinstance(item, Exception):
            raise item
        return item


def test_runner_reports_each_match_once():
    match = BackupMatch(pid=7, name="vssadmin.exe", pattern="vssadmin delete shadows", create_time=1.0)
    guard = FakeGuard([[match]])
    seen = []
    runner = BackupGuardRunner(guard, seen.append, interval=0.01)
    runner.start()
    time.sleep(0.3)
    finished = runner.stop()
    assert finished is True
    assert guard.calls >= 2
    assert len(seen) == 1


def test_runner_survives_a_scan_error():
    match = BackupMatch(pid=8, name="x", pattern="p", create_time=2.0)
    guard = FakeGuard([RuntimeError("boom"), [match]])
    seen = []
    runner = BackupGuardRunner(guard, seen.append, interval=0.01)
    runner.start()
    time.sleep(0.3)
    runner.stop()
    assert len(seen) == 1
    assert "boom" in runner.last_error


# ----- aggregator wiring ----------------------------------------------------
def test_note_backup_kill_sets_the_feature_for_five_seconds():
    agg = Aggregator(windows_style=False)
    index = FEATURE_NAMES.index("backup_kill_cmd")
    assert index == 8
    assert agg.compute_features(1.0).values[index] == 0.0
    agg.note_backup_kill(10.0)
    assert agg.compute_features(10.5).values[index] == 1.0
    assert agg.compute_features(14.9).values[index] == 1.0
    assert agg.compute_features(15.0).values[index] == 0.0
