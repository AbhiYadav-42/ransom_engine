"""engine/status_file.py -- the heartbeat file shared by the daemon (writer) and the tray (reader).
Standard library only, so the tray can import it without loading numpy / scikit-learn."""

import json
import os
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATUS_NAME = "status.json"
ALERTS_NAME = "alerts.txt"           # .txt so every desktop knows which editor opens it
STOP_NAME = "stop.request"           # the tray drops this file to ask the daemon to stop
MAX_STATUS_BYTES = 65536


def default_data_dir():
    override = os.environ.get("RANSOMGUARD_DATA_DIR")
    return Path(override) if override else PROJECT_ROOT / "data"


def write_status(data_dir, payload, retries=3, retry_delay=0.02):
    """Atomic write (temp file + os.replace) so a reader never sees half a file.
    Never raises; returns True on success. No fsync: this file is rewritten every second."""
    path = Path(data_dir) / STATUS_NAME
    temp = path.with_name(STATUS_NAME + ".tmp")
    for _attempt in range(retries):
        try:
            with open(temp, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            os.replace(temp, path)
            return True
        except OSError:
            # UNTESTED on real Windows: replace can fail for a moment while the tray has the file open.
            time.sleep(retry_delay)
        except (TypeError, ValueError):
            return False                      # payload is not JSON-serialisable
    return False


def read_status(data_dir):
    """Returns the status dict, or None if the file is missing, unreadable, corrupt or not an object."""
    path = Path(data_dir) / STATUS_NAME
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_STATUS_BYTES + 1)
        if len(raw) > MAX_STATUS_BYTES:
            return None
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError):             # JSONDecodeError / UnicodeDecodeError are ValueErrors
        return None
    return data if isinstance(data, dict) else None


def request_stop(data_dir):
    try:
        (Path(data_dir) / STOP_NAME).write_text("stop\n")
        return True
    except OSError:
        return False


def stop_requested(data_dir):
    return (Path(data_dir) / STOP_NAME).exists()


def clear_stop_request(data_dir):
    try:
        (Path(data_dir) / STOP_NAME).unlink()
    except OSError:
        pass