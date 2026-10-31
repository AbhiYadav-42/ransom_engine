"""Manual test: shows real banners on your desktop.

Run from the project root:  python sim/test_notification.py
"""
import logging
import sys
import time
from pathlib import Path

# Let this script find the engine/ package when run as a plain file.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine import alerts  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


def show(label, result):
    print(f"[{label}] delivered={result.delivered} suppressed={result.suppressed} -> {result.reason}")


alerts.reset_rate_limiter()

show("1 normal (should show)", alerts.send_alert("System Alert", "Handled natively by Serpantinum", "normal"))
show("2 normal again (should be suppressed)", alerts.send_alert("System Alert", "Second normal alert", "normal"))
show("3 critical (should show, not blocked by normal)", alerts.send_alert("CRITICAL", "Suspicious activity detected", "critical"))
show("4 critical again (should be suppressed)", alerts.send_alert("CRITICAL", "Another critical alert", "critical"))

print("waiting 2.1 s for the critical timer to expire...")
time.sleep(2.1)
show("5 critical after wait (should show)", alerts.send_alert("CRITICAL", "Critical again after the wait", "critical"))

show("6 bad severity (should be rejected)", alerts.send_alert("Oops", "bad severity", "urgent"))
show("7 title starting with a dash (should show as plain text)", alerts.send_alert("-not an option", "dash title test", "low"))