"""
sim/test_aggregator.py -- live demo of Stage 2 (sensor) + Stage 3 (aggregator).

Run from the project root:
    python sim/test_aggregator.py [--sandbox PATH] [--csv PATH] [--tick SECONDS]
                                  [--hide-idle] [--split-by-subfolder]
Prints one feature row per tick. Stop with Ctrl+C.
Only dummy files in the sandbox are touched. No real ransomware, ever.
"""

import argparse
import queue
import sys
import time
from pathlib import Path

# Make "import engine" work when this file is run as a script from anywhere.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from engine.aggregator import Aggregator, AggregatorRunner  # noqa: E402
from engine.aggregator_windows import describe_monotonic_clock  # noqa: E402
from engine.features_schema import (  # noqa: E402
    FEATURE_NAMES, SCHEMA_VERSION, FeatureSchemaError, schema_fingerprint)
from engine.sensor import FileSensor  # noqa: E402

# Short column titles, same order as FEATURE_NAMES.
COLUMN_LABELS = ["eps_1s", "eps_5s", "files_mod", "dirs", "renames",
                 "ext_chg", "mod_ratio", "canary", "bkp_kill"]
assert len(COLUMN_LABELS) == len(FEATURE_NAMES), "update COLUMN_LABELS to match the schema"


def parse_args():
    parser = argparse.ArgumentParser(description="Stage 2 sensor + Stage 3 aggregator, live")
    parser.add_argument("--sandbox", default=str(PROJECT_ROOT / "sandbox"))
    parser.add_argument("--csv", default=None, help="optional CSV path (must be OUTSIDE the sandbox)")
    parser.add_argument("--tick", type=float, default=1.0, help="seconds between rows")
    parser.add_argument("--hide-idle", action="store_true", help="do not print all-zero rows")
    parser.add_argument("--split-by-subfolder", action="store_true",
                        help="also emit one row per first-level subfolder (shows how keys work)")
    return parser.parse_args()


def make_subfolder_key_function(sandbox):
    """Returns a function: event -> "dir:<first folder under the sandbox>".
    Stage 5 will do the same kind of thing with a PID instead of a folder."""
    sandbox_parts = Path(sandbox).resolve().parts

    def key_function(event):
        relative = Path(event.src_path).parts[len(sandbox_parts):]
        if len(relative) > 1:
            return "dir:" + relative[0]
        return "dir:(root)"      # a file directly inside the sandbox

    return key_function


def header_line():
    text = "%9s %-12s" % ("time(s)", "source")
    for label in COLUMN_LABELS:
        text += " %9s" % label
    return text


def row_line(row, start_time):
    text = "%9.2f %-12s" % (row.timestamp - start_time, row.source_key)
    for value in row.values:
        text += " %9.2f" % value
    return text


def main():
    args = parse_args()
    sandbox = Path(args.sandbox)
    sandbox.mkdir(parents=True, exist_ok=True)
    ignored = sandbox / "_ignored"
    ignored.mkdir(exist_ok=True)

    if args.csv is not None:
        csv_path = Path(args.csv).resolve()
        if sandbox.resolve() in csv_path.parents:
            print("ERROR: the CSV must NOT be inside the watched sandbox (writing it would "
                  "create events that create more rows). Use e.g. --csv data/features.csv")
            return 1

    key_function = make_subfolder_key_function(sandbox) if args.split_by_subfolder else None
    sensor = FileSensor(watch_paths=[sandbox], ignore_paths=[ignored])
    aggregator = Aggregator(extra_key_func=key_function)
    runner = AggregatorRunner(aggregator, sensor.event_queue,
                              tick_seconds=args.tick, csv_path=args.csv)

    print("Schema version %s, fingerprint %s, %d features" % (
        SCHEMA_VERSION, schema_fingerprint(), len(FEATURE_NAMES)))
    print(describe_monotonic_clock())
    print("Watching: %s   tick: %.2fs   (Ctrl+C to stop)\n" % (sandbox.resolve(), args.tick))

    try:
        runner.start()                    # raises here if the CSV header does not match
    except FeatureSchemaError as error:
        print("ERROR: %s" % error)
        return 1
    sensor.start()
    for warning in sensor.startup_warnings:
        print(warning)

    start_time = time.monotonic()
    rows_printed = 0
    try:
        while True:
            try:
                row = runner.output_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if args.hide_idle and not any(row.values):
                continue
            if rows_printed % 20 == 0:
                print(header_line())
            print(row_line(row, start_time))
            rows_printed += 1
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        sensor.stop()                     # stop the producer first, then the consumer
        finished = runner.stop()
        print("Clean shutdown: %s" % finished)
        print("Sensor stats:     %s" % sensor.get_stats())
        print("Aggregator stats: %s" % runner.get_stats())
        if runner.last_error:
            print("Last error: %s" % runner.last_error)
    return 0


if __name__ == "__main__":
    sys.exit(main())