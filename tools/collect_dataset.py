"""tools/collect_dataset.py -- run generators inside the LIVE pipeline, write labeled rows to data/<name>.csv.

LABEL RULE: label = 1 for ticks from the simulator's 'attack_start' until --label-tail seconds
(default 5 = one window) after its 'attack_end'; every other tick (setup, idle, benign runs) = 0.
Columns: FEATURE_NAMES + label, run_id, os, variant (variant is used for per-variant recall).
Windows: Defender may react to the simulator; exclude ONLY --sandbox-root.

    python tools/collect_dataset.py --name features_linux --os-tag linux --repeats 3
"""

import argparse
import csv
import queue
import random
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from engine.aggregator import Aggregator, AggregatorRunner  # noqa: E402
from engine.backup_guard import BackupGuard, BackupGuardRunner  # noqa: E402
from engine.features_schema import FEATURE_NAMES  # noqa: E402
from engine.inspection_worker import InspectionWorker  # noqa: E402
from engine.inspector import Inspector  # noqa: E402
from engine.sensor import FileSensor  # noqa: E402
from sim import gen_benign, gen_ransomware  # noqa: E402
from sim.sandbox_common import MARKER_NAME  # noqa: E402


def label_for(tick_time, attack_start, attack_end, tail):
    """1 if the tick is inside [attack_start, attack_end + tail], else 0."""
    if attack_start is None:
        return 0
    if attack_end is None:
        attack_end = tick_time
    return 1 if attack_start <= tick_time <= attack_end + tail else 0


def csv_header():
    return list(FEATURE_NAMES) + ["label", "run_id", "os", "variant"]


def open_dataset(path):
    """Append to an existing file only if its header matches the current schema."""
    header = csv_header()
    if path.exists() and path.stat().st_size > 0:
        with open(path, newline="") as existing:
            first = next(csv.reader(existing), [])
        if first != header:
            raise SystemExit("%s has a different header (schema changed?). Move it aside or use "
                             "another --name." % path)
        handle = open(path, "a", newline="")
        return handle, csv.writer(handle)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "w", newline="")
    writer = csv.writer(handle)
    writer.writerow(header)
    return handle, writer


def drain_rows(output_queue, rows, timeout):
    try:
        row = output_queue.get(timeout=timeout)
    except queue.Empty:
        return
    if row.source_key == "global":
        rows.append(row)


def run_one(kind, variant, args, seed, writer):
    """One run with a FRESH pipeline. Returns (rows_written, positive_rows)."""
    run_id = "%s_%s_%s" % (args.os_tag, variant, uuid.uuid4().hex[:8])
    root = Path(args.sandbox_root)
    sandbox = root / run_id
    sandbox.mkdir(parents=True)
    (sandbox / MARKER_NAME).write_text("ransom_engine sandbox\n")   # consent marker for the generator

    sensor = FileSensor(watch_paths=[sandbox])
    worker = InspectionWorker(Inspector(), tick_seconds=args.tick)
    aggregator = Aggregator()
    runner = AggregatorRunner(aggregator, sensor.event_queue, tick_seconds=args.tick,
                              inspection_queue=worker.output_queue, event_hook=worker.submit)

    def on_backup_match(match):
        aggregator.note_backup_kill(time.monotonic())

    guard = BackupGuardRunner(BackupGuard(), on_backup_match, interval=0.5)

    script = PROJECT_ROOT / "sim" / ("gen_%s.py" % kind)
    cmd = [sys.executable, str(script), "--sandbox", str(sandbox), "--variant", variant,
           "--seed", str(seed)]
    phases, lines, rows = {}, [], []
    proc = None
    try:
        worker.start()
        runner.start()
        guard.start()
        sensor.start()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        def read_output():
            for line in proc.stdout:
                text = line.strip()
                lines.append(text)
                if text.startswith("PHASE "):
                    phases[text.split()[1]] = time.monotonic()   # same clock as the tick times

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()

        deadline = time.monotonic() + args.timeout
        while proc.poll() is None and time.monotonic() < deadline:
            drain_rows(runner.output_queue, rows, 0.2)
        if proc.poll() is None:
            proc.kill()
            print("  timeout: generator killed")
        reader.join(timeout=2)
        end_wait = time.monotonic() + args.label_tail + 2.0    # keep ticks after the attack too
        while time.monotonic() < end_wait:
            drain_rows(runner.output_queue, rows, 0.2)
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
        sensor.stop()
        runner.stop()
        guard.stop()
        worker.stop()

    start, end = phases.get("attack_start"), phases.get("attack_end")
    if kind == "ransomware" and start is None:
        print("  WARNING: no attack phase seen, run discarded. Output:\n    " + "\n    ".join(lines[-5:]))
        written = (0, 0)
    else:
        if start is not None and end is None:
            end = time.monotonic()                              # generator died mid-attack
        positives = 0
        for row in rows:
            label = label_for(row.timestamp, start, end, args.label_tail)
            positives += label
            writer.writerow(list(row.values) + [label, run_id, args.os_tag, variant])
        written = (len(rows), positives)

    if not args.keep_sandboxes and (sandbox / MARKER_NAME).exists() \
            and root.resolve() in sandbox.resolve().parents:
        shutil.rmtree(sandbox, ignore_errors=True)              # only folders created above
    return written


def parse_args():
    parser = argparse.ArgumentParser(description="Collect labeled feature rows")
    parser.add_argument("--name", required=True, help="writes data/<name>.csv")
    parser.add_argument("--os-tag", default="windows" if sys.platform == "win32" else "linux")
    parser.add_argument("--repeats", type=int, default=2, help="runs per variant")
    parser.add_argument("--kinds", choices=["both", "benign", "ransomware"], default="both")
    parser.add_argument("--variants", nargs="+", default=None,
                        help="collect only named variants (for example sim_slow_stealth)")
    parser.add_argument("--tick", type=float, default=1.0)
    parser.add_argument("--label-tail", type=float, default=5.0)
    parser.add_argument("--timeout", type=float, default=120.0, help="seconds per generator run")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--sandbox-root", default=str(PROJECT_ROOT / "data" / "sandboxes"))
    parser.add_argument("--keep-sandboxes", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    plan = []
    if args.kinds in ("both", "ransomware"):
        ransomware_variants = gen_ransomware.VARIANTS
        if args.variants:
            requested = set(args.variants)
            ransomware_variants = [v for v in ransomware_variants if v in requested]
        plan += [("ransomware", v) for v in ransomware_variants]
    if args.kinds in ("both", "benign"):
        benign_variants = gen_benign.VARIANTS
        if args.variants:
            requested = set(args.variants)
            benign_variants = [v for v in benign_variants if v in requested]
        plan += [("benign", v) for v in benign_variants]
    if args.variants:
        all_known = set(gen_ransomware.VARIANTS) | set(gen_benign.VARIANTS)
        unknown = set(args.variants) - all_known
        if unknown:
            raise SystemExit("unknown variants: %s" % ", ".join(sorted(unknown)))
    plan = plan * args.repeats
    random.Random(args.seed).shuffle(plan)
    print("%d runs planned (roughly %d-%d minutes)" % (len(plan), len(plan) // 3, len(plan) // 2 + 1))

    path = PROJECT_ROOT / "data" / ("%s.csv" % args.name)
    handle, writer = open_dataset(path)
    total_rows = total_pos = 0
    try:
        for index, (kind, variant) in enumerate(plan, start=1):
            rows, positives = run_one(kind, variant, args, args.seed * 1000 + index, writer)
            handle.flush()
            total_rows += rows
            total_pos += positives
            print("[%d/%d] %-10s %-20s rows=%d positives=%d" % (
                index, len(plan), kind, variant, rows, positives))
    finally:
        handle.close()
    print("\nwrote %s: %d rows, %d positive" % (path, total_rows, total_pos))


if __name__ == "__main__":
    main()