"""
engine/inspector_windows.py -- the one Windows-specific helper of Stage 4.

*** STATUS: UNTESTED on real Windows. ***
The retry LOGIC is unit-tested on Linux with a fake opener, which proves the
logic but not Windows behaviour. Verify in your VM.

Background: Python's open() on Windows normally lets other programs keep a file
open while we read it. A PermissionError (sharing violation) happens when
another program holds it exclusively (some antivirus scans or editors do this
for a moment), so we wait a few milliseconds and try ONCE more.
"""

import sys
import time


# --- UNTESTED on real Windows -------------------------------------------------
def open_binary_with_retry(path, opener=open, is_windows=None, retry_delay=0.05,
                           sleep=time.sleep):
    """Open `path` in binary mode. On Windows only: if the first attempt raises
    PermissionError, wait retry_delay seconds and try exactly once more.
    On other systems a PermissionError is raised straight away.
    A second failure always reaches the caller (read_sample turns it into 'locked')."""
    if is_windows is None:
        is_windows = (sys.platform == "win32")
    try:
        return opener(path, "rb")
    except PermissionError:
        if not is_windows:
            raise
        sleep(retry_delay)
        return opener(path, "rb")