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