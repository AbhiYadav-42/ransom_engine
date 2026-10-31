"""
engine/sensor_windows.py -- small Windows-only helpers for Stage 2.

*** STATUS: UNTESTED on real Windows. ***
The string logic can be unit-tested on Linux with fake paths (tests/test_sensor.py
does that), but nothing here has been verified on a real Windows machine.
Verify each function in your Windows VM.

Nothing in this file changes your computer: it only returns warnings / text.
"""

import ntpath   # Windows path rules, available on every OS (handy for tests)
import os
import sys

ONEDRIVE_ENV_VARS = ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")


def _normalize(path):
    # ntpath.normcase -> lower case + backslashes (Windows rules)
    return ntpath.normcase(ntpath.normpath(str(path)))


# --- UNTESTED on real Windows -------------------------------------------------
def looks_like_onedrive_path(path, check_environment=True):
    """True if the path seems to live in OneDrive. OneDrive may sync/lock files
    and can create extra events, so the sandbox must NOT be there."""
    normalized = _normalize(path)
    if any(part.startswith("onedrive") for part in normalized.split("\\")):
        return True
    if check_environment:
        for var in ONEDRIVE_ENV_VARS:
            root = os.environ.get(var)
            if root:
                root = _normalize(root)
                if normalized == root or normalized.startswith(root + "\\"):
                    return True
    return False


# --- UNTESTED on real Windows -------------------------------------------------
def defender_exclusion_command(path):
    """Text of the PowerShell command (run as Administrator) that excludes ONE
    folder from Defender scanning. We only RETURN the text; we never run it.
    Only ever exclude the sandbox folder, never a whole drive or your user folder."""
    return 'Add-MpPreference -ExclusionPath "%s"' % path


# --- UNTESTED on real Windows -------------------------------------------------
def is_file_locked(path):
    """True if opening the file for reading is refused with PermissionError
    (on Windows this is usually "another program has it open"). On Linux the
    same error also means "no permission", so it is only a hint there.
    Not used by the sensor itself; later stages (entropy reader) will need it.
    A missing file raises FileNotFoundError on purpose."""
    try:
        with open(path, "rb"):
            return False
    except PermissionError:
        return True


# --- UNTESTED on real Windows -------------------------------------------------
def get_sandbox_warnings(watch_paths, is_windows=None, check_environment=True):
    """List of human-readable warnings to show when the sensor starts.
    Empty on Linux. is_windows can be forced so tests can run on Linux."""
    if is_windows is None:
        is_windows = (sys.platform == "win32")
    if not is_windows:
        return []

    warnings_list = []
    for path in watch_paths:
        if looks_like_onedrive_path(path, check_environment):
            warnings_list.append(
                "WARNING: %s looks like a OneDrive folder. Move the sandbox outside OneDrive."
                % path)
        warnings_list.append(
            "NOTE: Windows Defender may scan or touch files in %s. If it interferes, exclude "
            "ONLY this folder (PowerShell as Administrator): %s"
            % (path, defender_exclusion_command(path)))
    return warnings_list