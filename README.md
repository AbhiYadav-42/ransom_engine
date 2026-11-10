# RansomGuard: Hybrid ML-Driven Ransomware Detection & Alert Engine

**RansomGuard** is a lightweight, cross-platform behavioral security engine designed to detect and mitigate active ransomware attacks in real time. Running entirely offline on local CPU architectures, the system captures filesystem metadata stream anomalies, fuses them into rolling temporal metrics, and utilizes a local machine learning classifier to forcefully terminate malicious cryptographic processes before widespread data loss occurs. 


# RansomGuard: Stage 1 (desktop alerts)

`engine/alerts.py` exposes one function:

```python
from engine import alerts
alerts.send_alert("System Alert", "Suspicious activity detected", "critical")
```

Severity is `low`, `normal` or `critical`. The function never raises; it returns an
`AlertResult(delivered, reason, suppressed)`. `delivered=True` means the backend accepted
the request, not that a banner was definitely seen.

## Platforms
- Linux: `notify-send` (package `libnotify`), shown by the session's notification server.
- Windows: `winotify` (preferred) or `plyer`.

## Rate limiting
Each severity has its own timer (`RATE_LIMIT_SECONDS`): low 30 s, normal 10 s, critical 2 s.
Suppressed alerts return `suppressed=True`. The engine must still log the underlying event.

## Run it
- Manual banners: `python sim/test_notification.py`
- Automated tests: `python -m pytest -v`

## If no banner appears
1. `which notify-send` (Linux) or `pip show winotify` (Windows).
2. Read the `reason` text in the result; it names the failing step.
3. Linux: check that the session D-Bus and your shell's notification server are running.
4. Windows: check that Focus Assist / Do Not Disturb is off.




## Stage 1 status

- Linux (Arch + Hyprland + Serpantinum): complete. 15 automated tests pass, and normal and critical banners were seen on screen.
- Windows (`winotify` / `plyer`): code written, **not yet tested on real Windows**. To be verified in a Windows VM.

## Notes from testing

- Serpantinum has its own built-in notification server, so `mako` and `dunst` must not be installed. Only `libnotify` (for `notify-send`) is needed.
- When several alerts arrive at almost the same instant, Serpantinum may show only one popup. Each alert sent on its own shows normally. This is the notification server's display behavior, not a bug in `send_alert()`.
- Each severity has its own rate-limit timer, so a `normal` alert never blocks a `critical` one.
- Titles that start with `-` are passed safely because the command uses `--` before the title.



# Stage 2: Behavioral file sensor

`engine/sensor.py` watches sandbox folders with `watchdog` (inotify on Linux,
ReadDirectoryChangesW on Windows) and puts one `SensorEvent` per filesystem
event on a `queue.Queue`. It does **no** aggregation, entropy, ML, killing or alerting.

### SensorEvent
| field | meaning |
|---|---|
| `timestamp` | `time.monotonic()` when the handler saw the event |
| `event_type` | `created`, `modified`, `moved`, `deleted` |
| `src_path` | path as reported by watchdog |
| `dest_path` | only for `moved`, else `None` |
| `is_directory` | True for folders |
| `extension_changed` | for file moves: last suffix differs (case-insensitive) |

### What is dropped / kept
- **Dropped:** `modified` for the same path less than `dedup_window` s (default 0.25) after the last *kept* `modified` for it; directory `modified` events (switchable); anything inside an ignored folder (for a move, if either end is ignored).
- **Kept:** the first `modified`, later ones after the window, `modified` for other paths, and **all** `created` / `moved` / `deleted`.
- Counters in `sensor.get_stats()` show how many events were dropped and why.

### Known limitations (honest list)
- **No process ID.** watchdog does not provide one; attribution comes later via psutil.
- **Events can be lost** if the OS event buffer overflows during huge bursts. Callbacks are kept tiny to reduce this, but it cannot be eliminated. Linux limit: `/proc/sys/fs/inotify/max_queued_events`.
- One real action can produce several events; behaviour differs between OSes and watchdog versions.
- A file moved out of the watched tree appears as `deleted`; moved in appears as `created`.

### Windows notes (UNTESTED on real Windows)
- Keep the sandbox **outside OneDrive** (sync can lock/touch files and create extra events).
- Windows Defender may scan sandbox files. If it interferes, exclude **only the sandbox folder**
  (PowerShell as Administrator): `Add-MpPreference -ExclusionPath "C:\sandbox"`.
  Remove later with `Remove-MpPreference -ExclusionPath "C:\sandbox"`.
- Files can be locked by other programs; `is_file_locked()` in `engine/sensor_windows.py` is a hint for later stages.
- Paths are compared with `PureWindowsPath` (case-insensitive, `/` and `\` equal).

### Run
```bash
pip install -r requirements.txt
python -m pytest tests/ -v            # always point pytest at tests/
python sim/test_sensor.py             # live demo; generate events from a 2nd terminal
```


# Stage 3: Temporal aggregator

`engine/aggregator.py` reads Stage 2's `SensorEvent` queue, keeps 1 s and 5 s sliding
windows, and every tick (default 1 s) emits one `FeatureRow` (timestamp, source_key,
values in the exact order of `engine/features_schema.py::FEATURE_NAMES`).
It does **no** entropy, ML, process killing or alerting.

### The column contract (`engine/features_schema.py`)
Column ORDER is the contract: a trained model trusts position. Never reorder, rename or
insert; add new features at the END, change `SCHEMA_VERSION`, tell your partner, retrain.
Compare `schema_fingerprint()` on both machines.

| Feature | Definition |
|---|---|
| events_per_sec_1s / _5s | events in the window / window length |
| distinct_files_modified | distinct file paths with a `modified` event (5 s) |
| distinct_dirs_touched | distinct parent folders of events, move destinations included (5 s) |
| rename_count | `moved` events on files (5 s) |
| extension_change_count | file moves whose extension changed (5 s) |
| modify_ratio | modified events / all events (5 s), 0 when none |
| canary_touched, backup_kill_cmd | placeholders, always 0 until later stages |

### Things to know
- Numbers are computed from what Stage 2 delivers: repeated `modified` events are de-duplicated,
  directory-modified events are skipped, ignored folders never arrive. Each new file is ~2 events
  (created + modified). Changing Stage 2 settings changes the features: retrain.
- Memory is bounded: each window is capped (default 20,000 events/s). In a huge burst the oldest
  records are evicted, rates saturate and distinct counts under-count. Counters are in `get_stats()`.
- Source keys: everything feeds `"global"`; an optional `extra_key_func(event)` adds a second key
  (a folder now, a PID in Stage 5).
- CSV (`--csv`): the header comes from `FEATURE_NAMES`; an existing file with a different header is
  refused. Keep the CSV **outside** the watched sandbox. `data/` is git-ignored.

### Windows notes (UNTESTED on real Windows)
- `time.monotonic()` may be coarse (about 15 ms on some versions); the sim prints the reported resolution.
- Paths are compared with Windows rules (case-insensitive, `\`) via `aggregator_windows.py`.
- Do not keep the CSV open in Excel while collecting (it locks the file; the runner counts `csv_errors`).
- Same columns on both OSes does not guarantee the same values: compare rows for the same simulated
  activity on both before trusting a Linux-trained model on Windows.

### Run
```bash
python -m pytest tests/ -q
python sim/test_aggregator.py --csv data/features.csv
```