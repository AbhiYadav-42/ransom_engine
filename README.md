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