"""
sim/test_sensor.py -- manual, live demo of the Stage 2 sensor.

Run from the project root:   python sim/test_sensor.py [sandbox_folder]
It prints every SensorEvent as it arrives. Stop with Ctrl+C.
Only dummy files in the sandbox are touched. No real ransomware, ever.
"""

import queue
import sys
import time
from pathlib import Path

# Make "import engine" work when this file is run as a script from anywhere.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from engine.sensor import FileSensor  # noqa: E402

DEDUP_WINDOW = 0.25   # seconds; try 0 (off) or 2.0 to see the difference


def format_event(event, start_time):
    seconds = event.timestamp - start_time
    kind = "DIR " if event.is_directory else "FILE"
    line = "[%8.3fs] %-8s %s %s" % (seconds, event.event_type, kind, event.src_path)
    if event.dest_path is not None:
        line += "  ->  " + event.dest_path
        if event.extension_changed:
            line += "   <-- EXTENSION CHANGED"
    return line


def main():
    sandbox = Path(sys.argv[1]) if len(sys.argv) > 1 else PROJECT_ROOT / "sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    ignored = sandbox / "_ignored"      # anything in here must stay invisible
    ignored.mkdir(exist_ok=True)

    sensor = FileSensor(watch_paths=[sandbox], ignore_paths=[ignored], dedup_window=DEDUP_WINDOW)
    sensor.start()
    for warning in sensor.startup_warnings:
        print(warning)
    print("Watching: %s" % sandbox.resolve())
    print("Ignoring: %s" % ignored.resolve())
    print("De-dup window: %.2fs   (Ctrl+C to stop)\n" % DEDUP_WINDOW)

    start_time = time.monotonic()
    try:
        while True:
            try:
                event = sensor.event_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            print(format_event(event, start_time))
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        finished = sensor.stop()
        print("Clean shutdown: %s" % finished)
        print("Stats: %s" % sensor.get_stats())


if __name__ == "__main__":
    main()