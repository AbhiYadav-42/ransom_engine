"""
sim/test_inspector.py -- manual demo of Stage 4.

STEP 1 (default): creates 5 test files in a temporary folder and prints every metric.
STEP 2 (--live):  runs sensor + aggregator + inspection worker on a sandbox folder
                  and prints one feature row per tick.

    python sim/test_inspector.py
    python sim/test_inspector.py --live [--sandbox PATH] [--csv PATH] [--tick S] [--hide-idle]
Only dummy files are touched. No real ransomware, ever.
"""

import argparse
import os
import queue
import sys
import tempfile
import time
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from engine.aggregator import Aggregator, AggregatorRunner  # noqa: E402
from engine.features_schema import (  # noqa: E402
    FEATURE_NAMES, SCHEMA_VERSION, FeatureSchemaError, schema_fingerprint)
from engine.inspection_worker import InspectionWorker  # noqa: E402
from engine.inspector import Inspector  # noqa: E402
from engine.sensor import FileSensor  # noqa: E402

SAMPLE = 65536
ORDER = ["notes.txt", "archive.zip", "random.bin", "zeros.bin", "fake.docx"]

# (column title, feature name) for the live table; positions are looked up by NAME.
SHOW = [("eps_1s", "events_per_sec_1s"), ("files_mod", "distinct_files_modified"),
        ("inspected", "files_inspected"), ("max_ent", "max_entropy"),
        ("mean_ent", "mean_entropy"), ("frac_hi", "fraction_high_entropy"),
        ("mean_chi2", "mean_chi_square"), ("max_null", "max_null_fraction"),
        ("hdr_mis", "header_mismatch_count"), ("ent_jump", "entropy_jump_count")]
SHOW_INDEX = [FEATURE_NAMES.index(name) for _title, name in SHOW]


# ---------------------------------------------------------------- step 1
def make_test_files(folder):
    sentence = "The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs. "
    (folder / "notes.txt").write_bytes((sentence * 1000).encode("ascii")[:SAMPLE])
    (folder / "random.bin").write_bytes(os.urandom(SAMPLE))
    (folder / "zeros.bin").write_bytes(bytes(SAMPLE))
    (folder / "fake.docx").write_bytes(os.urandom(SAMPLE))      # random bytes pretending to be a .docx
    with zipfile.ZipFile(folder / "archive.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("data.bin", os.urandom(70000))         # incompressible content


def run_table():
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        make_test_files(folder)
        inspector = Inspector()
        print("%-12s %-9s %7s %12s %9s %7s %7s %7s %4s %6s" % (
            "file", "status", "entropy", "chi_square", "null_frac",
            "blk_max", "blk_min", "blk_std", "hdr", "ext_ok"))
        for name in ORDER:
            r = inspector.inspect(str(folder / name))
            print("%-12s %-9s %7.3f %12.1f %9.4f %7.3f %7.3f %7.3f %4d %6d" % (
                name, r.status, r.entropy, r.chi_square, r.null_fraction,
                r.block_entropy_max, r.block_entropy_min, r.block_entropy_std,
                r.has_known_header, r.ext_matches_header))
    print("\nNotice: random.bin and archive.zip look the same to entropy and chi-square.")
    print("The header check is what separates them from fake.docx (ext_ok = 0).")


# ---------------------------------------------------------------- step 2
def header_line():
    text = "%8s %-10s" % ("time(s)", "source")
    for title, _name in SHOW:
        text += " %9s" % title
    return text


def row_line(row, start_time):
    text = "%8.2f %-10s" % (row.timestamp - start_time, row.source_key)
    for index in SHOW_INDEX:
        text += " %9.2f" % row.values[index]
    return text


def run_live(args):
    sandbox = Path(args.sandbox)
    sandbox.mkdir(parents=True, exist_ok=True)
    ignored = sandbox / "_ignored"
    ignored.mkdir(exist_ok=True)

    if args.csv is not None and sandbox.resolve() in Path(args.csv).resolve().parents:
        print("ERROR: the CSV must NOT be inside the watched sandbox.")
        return 1

    sensor = FileSensor(watch_paths=[sandbox], ignore_paths=[ignored])
    worker = InspectionWorker(Inspector(), max_files_per_tick=50, tick_seconds=args.tick)
    aggregator = Aggregator()
    runner = AggregatorRunner(aggregator, sensor.event_queue, tick_seconds=args.tick,
                              csv_path=args.csv, inspection_queue=worker.output_queue,
                              event_hook=worker.submit)

    print("Schema version %s, fingerprint %s, %d features" % (
        SCHEMA_VERSION, schema_fingerprint(), len(FEATURE_NAMES)))
    print("Watching: %s   tick: %.2fs   (Ctrl+C to stop)\n" % (sandbox.resolve(), args.tick))

    try:
        runner.start()                    # raises here if the CSV header does not match
    except FeatureSchemaError as error:
        print("ERROR: %s" % error)
        return 1
    worker.start()
    sensor.start()

    start_time = time.monotonic()
    printed = 0
    try:
        while True:
            try:
                row = runner.output_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if args.hide_idle and not any(row.values):
                continue
            if printed % 20 == 0:
                print(header_line())
            print(row_line(row, start_time))
            printed += 1
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        sensor.stop()                     # producer first, then consumers
        runner.stop()
        finished = worker.stop()
        print("Clean shutdown: %s" % finished)
        print("Sensor stats:     %s" % sensor.get_stats())
        print("Worker stats:     %s" % worker.get_stats())
        print("Aggregator stats: %s" % runner.get_stats())
        if worker.last_error or runner.last_error:
            print("Last errors: %s | %s" % (worker.last_error, runner.last_error))
    return 0


def main():
    parser = argparse.ArgumentParser(description="Stage 4 demo")
    parser.add_argument("--live", action="store_true", help="step 2: run the whole pipeline")
    parser.add_argument("--sandbox", default=str(PROJECT_ROOT / "sandbox"))
    parser.add_argument("--csv", default=None, help="optional CSV path, OUTSIDE the sandbox")
    parser.add_argument("--tick", type=float, default=1.0)
    parser.add_argument("--hide-idle", action="store_true")
    args = parser.parse_args()
    if args.live:
        return run_live(args)
    run_table()
    return 0


if __name__ == "__main__":
    sys.exit(main())