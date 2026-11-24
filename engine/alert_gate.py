"""engine/alert_gate.py -- turns per-tick model verdicts into occasional alerts. Standard library only."""

from collections import deque


class AlertGate:
    """Fires when at least `needed` of the last `window` ticks were flagged, then stays quiet for
    `cooldown_seconds`. One noisy second can therefore never raise an alert."""

    def __init__(self, window=5, needed=3, cooldown_seconds=60.0):
        if window < 1 or needed < 1 or needed > window:
            raise ValueError("need 1 <= needed <= window")
        self.needed = needed
        self.cooldown = cooldown_seconds
        self._recent = deque(maxlen=window)
        self._last_fired = None

    def update(self, flagged, now):
        """Feed one tick. Returns True if an alert should fire now."""
        self._recent.append(bool(flagged))
        if sum(self._recent) < self.needed:
            return False
        if self._last_fired is not None and now - self._last_fired < self.cooldown:
            return False
        self._last_fired = now
        return True