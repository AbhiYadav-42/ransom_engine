"""
engine/aggregator_windows.py -- small platform helpers for Stage 3.

*** STATUS: UNTESTED on real Windows. ***
The Windows path RULES come from Python's ntpath module, which works on any OS,
so tests/test_aggregator.py can check the string logic on Linux with fake paths.
That is not the same as verifying it on a real Windows machine. Verify in your VM.
"""

import ntpath
import posixpath
import sys
import time


def _path_module(windows_style):
    if windows_style is None:
        windows_style = (sys.platform == "win32")
    return ntpath if windows_style else posixpath


# --- UNTESTED on real Windows -------------------------------------------------
def split_for_counting(path, windows_style=None):
    """Return (normalized_path, normalized_parent_folder).
    Windows rules: lower-case, backslashes, so "C:/A/B.txt" == "c:\\a\\b.TXT".
    POSIX rules: case is kept (Linux paths are case-sensitive)."""
    module = _path_module(windows_style)
    normalized = module.normcase(module.normpath(path))
    return normalized, module.dirname(normalized)


# --- UNTESTED on real Windows -------------------------------------------------
def describe_monotonic_clock():
    """One line describing time.monotonic() on this machine.
    On some Windows/Python versions the resolution is coarse (about 15 ms), so two
    events a few ms apart may get the same timestamp. That is harmless for 1-second
    windows, but good to know."""
    info = time.get_clock_info("monotonic")
    text = "time.monotonic(): implementation=%s, reported resolution=%.4f ms" % (
        info.implementation, info.resolution * 1000.0)
    if info.resolution > 0.005:
        text += "  (coarse clock)"
    return text