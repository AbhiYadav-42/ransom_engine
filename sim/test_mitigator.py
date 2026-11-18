"""sim/test_mitigator.py -- spawns its OWN harmless sleepers (1 parent + 2 children) and contains them.
Run: python sim/test_mitigator.py     It only ever touches the pids it spawned."""

import subprocess
import sys
import tempfile
import time
from pathlib import Path

import psutil

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from engine.mitigator import Mitigator, MitigatorConfig, get_create_time  # noqa: E402

FAMILY_CODE = (
    "import subprocess, sys, time\n"
    "kids = [subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']) for _ in range(2)]\n"
    "time.sleep(120)\n"
)


def spawn_family():
    parent = subprocess.Popen([sys.executable, "-c", FAMILY_CODE])
    deadline = time.time() + 10
    while time.time() < deadline:
        if len(psutil.Process(parent.pid).children(recursive=True)) >= 2:
            break
        time.sleep(0.05)
    return parent


def is_alive(pid):
    try:
        return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def show(label, result):
    print("\n== %s ==" % label)
    print("pid=%d dry_run=%s contained=%s killed=%s" % (
        result.pid, result.dry_run, getattr(result, "contained", "-"),
        getattr(result, "killed_pids", "-")))
    for title, items in (("step", result.steps), ("skipped", result.skipped), ("error", result.errors)):
        for item in items:
            print("  %-8s %s" % (title, item))


def main():
    parent = spawn_family()
    spawned = set([parent.pid])
    spawned.update(c.pid for c in psutil.Process(parent.pid).children(recursive=True))
    print("Spawned pids (the only ones this script touches):", sorted(spawned))
    try:
        created = get_create_time(parent.pid)

        dry = Mitigator(MitigatorConfig(dry_run=True))
        show("DRY RUN", dry.contain(parent.pid, "demo", expected_create_time=created))
        print("alive after dry run:", [p for p in sorted(spawned) if is_alive(p)])

        real = Mitigator(MitigatorConfig(dry_run=False))
        show("REAL", real.contain(parent.pid, "demo", expected_create_time=created))
        print("alive after real run:", [p for p in sorted(spawned) if is_alive(p)])

        # quarantine demo with dummy files only (the process is stopped now)
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp) / "work"
            work.mkdir()
            files = []
            for name in ("a.txt", "b.txt"):
                path = work / name
                path.write_text("dummy " + name)
                files.append(str(path))
            config = MitigatorConfig(dry_run=False, quarantine_dir=str(Path(temp) / "quarantine"))
            result = Mitigator(config).quarantine_files(files, parent.pid, 0.95,
                                                        expected_create_time=created)
            show("QUARANTINE", result)
            for record in sorted(Path(config.quarantine_dir).glob("*.json")):
                print("\nrecord", record.name, "->", record.read_text())
    finally:
        for pid in spawned:
            try:
                psutil.Process(pid).kill()
            except psutil.Error:
                pass
        try:
            parent.wait(timeout=5)
        except Exception:
            pass


if __name__ == "__main__":
    main()
