"""
ui/tray_app.py -- RansomGuard system tray: a remote control + status viewer for the engine daemon.
It only READS data/status.json and starts/stops the daemon. It never runs detection code.
"Quit & Stop Protection" stops the engine before closing the tray.

    python ui/tray_app.py                       run the tray
    python ui/tray_app.py --export-icon FILE    write the 64x64 shield PNG (for the .desktop launcher)
"""

import argparse
import os
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from engine.status_file import default_data_dir, read_status  # noqa: E402
from ui.tray_logic import (  # noqa: E402
    EngineController, TrayState, acquire_single_instance_lock, compute_state, make_icon,
    open_alerts_file)

INSTALL_HINT = """Cannot start the tray icon: {error}

Arch Linux:
  sudo pacman -S --needed libappindicator-gtk3 python-gobject
  # let the venv see the system 'gi' module (one line, then retry):
  sed -i 's/include-system-site-packages = false/include-system-site-packages = true/' .venv/pyvenv.cfg
  .venv/bin/python -m pip install -r requirements.txt
Windows: pip install -r requirements.txt
"""


def import_pystray():
    """Linux: ask for the AppIndicator backend first (works with StatusNotifierItem trays),
    then fall back to pystray's own choice."""
    def attempt():
        import pystray
        return pystray

    if sys.platform.startswith("linux") and "PYSTRAY_BACKEND" not in os.environ:
        os.environ["PYSTRAY_BACKEND"] = "appindicator"
        try:
            return attempt()
        except Exception:
            del os.environ["PYSTRAY_BACKEND"]
            for name in [n for n in sys.modules if n == "pystray" or n.startswith("pystray.")]:
                del sys.modules[name]
    return attempt()


class TrayApp:
    def __init__(self, pystray, data_dir, poll_seconds=1.5):
        self._pystray = pystray
        self._data_dir = Path(data_dir)
        self._controller = EngineController(PROJECT_ROOT, self._data_dir)
        self._poll_seconds = poll_seconds
        self._state = compute_state(None)
        self._icon = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._flash_text = ""
        self._flash_until = 0.0
        self._flash_active = False

    # ------------------------------------------------------------ run
    def run(self):
        self._icon = self._pystray.Icon("ransomguard", make_icon("stopped"), "RansomGuard",
                                        self._build_menu())
        self._icon.run(setup=self._setup)          # blocks until Quit Tray

    def _setup(self, icon):
        icon.visible = True
        threading.Thread(target=self._poll_loop, name="status-poller", daemon=True).start()

    def _build_menu(self):
        item = self._pystray.MenuItem
        return self._pystray.Menu(
            item(lambda _item: self._status_line(), None, enabled=False),     # live status (not clickable)
            self._pystray.Menu.SEPARATOR,
            item("Start Engine", self._on_start, visible=lambda _item: not self._state.running),
            item("Stop Engine", self._on_stop, visible=lambda _item: self._state.running),
            item("Open Recent Alerts", self._on_open_alerts),
            self._pystray.Menu.SEPARATOR,
            item("Quit & Stop Protection", self._on_quit),
        )

    # ------------------------------------------------------------ polling (background thread)
    def _poll_loop(self):
        while not self._stop_event.is_set():
            try:
                self._apply(compute_state(read_status(self._data_dir)))
                if self._flash_active and time.monotonic() >= self._flash_until:
                    self._flash_active = False
                    self._refresh_menu()
            except Exception as error:             # the poller must never die
                print("tray poll error: %r" % (error,), file=sys.stderr)
            self._stop_event.wait(self._poll_seconds)

    def _apply(self, new_state: TrayState):
        icon = self._icon
        if icon is None:
            return
        with self._lock:
            old = self._state
            self._state = new_state
        if new_state.level != old.level:
            icon.icon = make_icon(new_state.level)       # only redraw when the colour changes
        if new_state != old:
            icon.title = new_state.tooltip
            self._refresh_menu()

    def _refresh_menu(self):
        try:
            self._icon.update_menu()
        except Exception:
            pass

    def _status_line(self):
        if time.monotonic() < self._flash_until:
            return self._flash_text
        return self._state.status_text

    def _flash(self, text, seconds):
        self._flash_text = text
        self._flash_until = time.monotonic() + seconds
        self._flash_active = True
        self._refresh_menu()

    # ------------------------------------------------------------ menu actions
    def _background(self, work):
        """Menu callbacks may run on the tray's UI thread: never block them."""
        threading.Thread(target=work, daemon=True).start()

    def _on_start(self, icon, item):
        self._background(self._start_engine)

    def _on_stop(self, icon, item):
        self._background(self._stop_engine)

    def _start_engine(self):
        self._flash("Starting engine...", 15)
        ok, message = self._controller.start()
        self._flash(message, 6 if ok else 12)

    def _stop_engine(self):
        self._flash("Stopping engine...", 20)
        ok, message = self._controller.stop()
        self._flash(message, 6 if ok else 12)

    def _on_open_alerts(self, icon, item):
        def work():
            ok, message = open_alerts_file(self._data_dir)
            if not ok:
                self._flash(message, 10)
        self._background(work)

    def _quit_and_stop(self, icon):
        self._controller.stop()
        self._stop_event.set()
        icon.stop()

    def _on_quit(self, icon, item):
        self._background(lambda: self._quit_and_stop(icon))


def parse_args():
    parser = argparse.ArgumentParser(description="RansomGuard tray")
    parser.add_argument("--data-dir", default=str(default_data_dir()))
    parser.add_argument("--poll", type=float, default=1.5, help="seconds between status checks")
    parser.add_argument("--export-icon", default=None, help="write the shield PNG to this path and exit")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.export_icon:
        target = Path(args.export_icon).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        make_icon("safe").save(target)
        print("wrote %s" % target)
        return 0

    lock = acquire_single_instance_lock()            # keep this variable alive: it holds the lock
    if lock is None:
        print("RansomGuard tray is already running.")
        return 0
    try:
        pystray = import_pystray()
    except Exception as error:
        print(INSTALL_HINT.format(error=error), file=sys.stderr)
        return 1
    TrayApp(pystray, args.data_dir, args.poll).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())