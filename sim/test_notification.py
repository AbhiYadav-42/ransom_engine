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

logging.basicConfig(level=logging.WARNING)


def show(label, result):
    status = "DELIVERED" if result.delivered else ("SUPPRESSED" if result.suppressed else "NOT DELIVERED")
    print(f"[OK] {label}: {status}")


alerts.reset_rate_limiter()

show(
    "Stage 5 summary",
    alerts.send_alert(
        "Stage 5 Complete",
        "Process attribution, backup detection, containment, and quarantine verified.",
        "normal",
    ),
)

# Existing delivery checks, kept compact for manual verification.
show("Normal alert limiter", alerts.send_alert("RansomGuard", "A second notification", "normal"))
show("Critical alert", alerts.send_alert("RansomGuard — Critical", "Suspicious activity detected", "critical"))
show("Critical alert limiter", alerts.send_alert("RansomGuard — Critical", "A repeated alert", "critical"))

print("[WAIT] Checking notification delivery again after the critical limit expires...")
time.sleep(2.1)
show("Critical alert retry", alerts.send_alert("RansomGuard — Critical", "Critical notification retry", "critical"))

show("Invalid severity", alerts.send_alert("RansomGuard", "Invalid severity check", "urgent"))
show("Plain-text title", alerts.send_alert("-not an option", "Dash-prefixed titles remain plain text", "low"))