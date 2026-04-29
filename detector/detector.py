import time
from collections import deque, defaultdict


class AnomalyDetector:
    """
    Tracks request rates using sliding windows.
    Uses two deques — one per IP, one global.
    Window covers the last 60 seconds.
    """

    def __init__(self, config):
        self.window_seconds = config["detection"]["window_seconds"]
        self.zscore_threshold = config["detection"]["zscore_threshold"]
        self.rate_multiplier = config["detection"]["rate_multiplier"]
        self.error_multiplier = config["detection"]["error_rate_multiplier"]

        # Global sliding window — list of timestamps
        self.global_window = deque()

        # Per-IP sliding windows — dict of IP -> deque of timestamps
        self.ip_windows = defaultdict(deque)

        # Per-IP error windows
        self.ip_error_windows = defaultdict(deque)

        # Global error window
        self.global_error_window = deque()

    def record(self, ip, is_error=False):
        """Record a request from an IP."""
        now = time.time()
        cutoff = now - self.window_seconds

        # Add to global window
        self.global_window.append(now)

        # Add to IP window
        self.ip_windows[ip].append(now)

        if is_error:
            self.global_error_window.append(now)
            self.ip_error_windows[ip].append(now)

        # Evict old entries from global window
        while self.global_window and self.global_window[0] < cutoff:
            self.global_window.popleft()

        # Evict old entries from IP window
        while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
            self.ip_windows[ip].popleft()

        # Evict old error entries
        while (self.global_error_window and
               self.global_error_window[0] < cutoff):
            self.global_error_window.popleft()

        while (self.ip_error_windows[ip] and
               self.ip_error_windows[ip][0] < cutoff):
            self.ip_error_windows[ip].popleft()

    def get_global_rate(self):
        """Get current global requests per second."""
        return len(self.global_window) / self.window_seconds

    def get_ip_rate(self, ip):
        """Get current requests per second for an IP."""
        return len(self.ip_windows[ip]) / self.window_seconds

    def get_ip_error_rate(self, ip):
        """Get current error rate for an IP."""
        return len(self.ip_error_windows[ip]) / self.window_seconds

    def get_top_ips(self, n=10):
        """Get top N IPs by request count."""
        ip_counts = {
            ip: len(window)
            for ip, window in self.ip_windows.items()
        }
        return sorted(
            ip_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:n]

    def check_ip(self, ip, baseline, banned_ips):
        """
        Check if an IP is anomalous.
        Returns (is_anomalous, rate, reason)
        """
        if ip in banned_ips:
            return False, 0, None

        rate = self.get_ip_rate(ip)
        error_rate = self.get_ip_error_rate(ip)

        # Tighten thresholds if error rate is high
        multiplier = self.rate_multiplier
        zscore_threshold = self.zscore_threshold

        if baseline.error_mean > 0:
            if error_rate > (self.error_multiplier * baseline.error_mean):
                multiplier = multiplier * 0.5
                zscore_threshold = zscore_threshold * 0.5

        if baseline.is_anomalous(rate, multiplier, zscore_threshold):
            zscore = baseline.get_zscore(rate)
            reason = (
                f"rate={rate:.2f}/s zscore={zscore:.2f} "
                f"baseline_mean={baseline.mean:.2f}"
            )
            return True, rate, reason

        return False, rate, None

    def check_global(self, baseline):
        """
        Check if global traffic is anomalous.
        Returns (is_anomalous, rate, reason)
        """
        rate = self.get_global_rate()

        if baseline.is_anomalous(
            rate,
            self.rate_multiplier,
            self.zscore_threshold
        ):
            zscore = baseline.get_zscore(rate)
            reason = (
                f"global_rate={rate:.2f}/s zscore={zscore:.2f} "
                f"baseline_mean={baseline.mean:.2f}"
            )
            return True, rate, reason

        return False, rate, None
