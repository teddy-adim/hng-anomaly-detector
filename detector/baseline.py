import time
import math
from collections import deque


class BaselineTracker:
    """
    Tracks request rates over time and computes
    a rolling baseline of mean and standard deviation.

    Uses a 30-minute rolling window of per-second counts.
    Recalculates every 60 seconds.
    Maintains per-hour slots for better accuracy.
    """

    def __init__(self, config):
        self.window_minutes = config["detection"]["baseline_window_minutes"]
        self.recalc_interval = config["detection"]["recalculation_interval"]
        self.floor = config["detection"]["baseline_floor"]
        self.min_samples = config["detection"]["min_baseline_samples"]

        # Rolling window of (timestamp, count) tuples
        self.window = deque()

        # Per-hour slots - key is hour (0-23), value is list of counts
        self.hourly_slots = {}

        # Current baseline values
        self.mean = self.floor
        self.stddev = 0.0

        # Error rate baseline
        self.error_mean = self.floor
        self.error_stddev = 0.0

        self.last_recalc = time.time()
        self.start_time = time.time()

    def record(self, count, error_count=0):
        """Record a per-second count into the rolling window."""
        now = time.time()
        hour = time.localtime(now).tm_hour

        self.window.append((now, count, error_count))

        # Store in hourly slot
        if hour not in self.hourly_slots:
            self.hourly_slots[hour] = []
        self.hourly_slots[hour].append(count)

        # Evict entries older than window_minutes
        cutoff = now - (self.window_minutes * 60)
        while self.window and self.window[0][0] < cutoff:
            self.window.popleft()

        # Recalculate if interval has passed
        if now - self.last_recalc >= self.recalc_interval:
            self._recalculate()
            self.last_recalc = now

    def _recalculate(self):
        """
        Recalculate mean and stddev from the rolling window.
        Prefer current hour's data if it has enough samples.
        """
        now = time.time()
        current_hour = time.localtime(now).tm_hour

        # Try current hour's data first
        hourly_data = self.hourly_slots.get(current_hour, [])

        if len(hourly_data) >= self.min_samples:
            counts = hourly_data
        else:
            # Fall back to full rolling window
            counts = [c for _, c, _ in self.window]

        if len(counts) < 2:
            return

        self.mean = max(self.floor, sum(counts) / len(counts))
        variance = sum((c - self.mean) ** 2 for c in counts) / len(counts)
        self.stddev = math.sqrt(variance)

        # Calculate error baseline
        error_counts = [e for _, _, e in self.window]
        if error_counts:
            self.error_mean = max(
                self.floor,
                sum(error_counts) / len(error_counts)
            )
            e_variance = sum(
                (e - self.error_mean) ** 2 for e in error_counts
            ) / len(error_counts)
            self.error_stddev = math.sqrt(e_variance)

        print(
            f"[Baseline] Recalculated — "
            f"mean={self.mean:.2f} stddev={self.stddev:.2f} "
            f"samples={len(counts)}"
        )

    def get_zscore(self, rate):
        """Calculate z-score for a given rate."""
        if self.stddev == 0:
            return 0.0
        return (rate - self.mean) / self.stddev

    def is_anomalous(self, rate, multiplier, zscore_threshold):
        """
        Returns True if rate is anomalous.
        Fires if z-score > threshold OR rate > multiplier * mean.
        Whichever fires first.
        """
        zscore = self.get_zscore(rate)
        rate_exceeded = rate > (multiplier * self.mean)
        zscore_exceeded = zscore > zscore_threshold
        return zscore_exceeded or rate_exceeded
