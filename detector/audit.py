import time


class AuditLogger:
    """
    Writes structured audit log entries for:
    - Bans
    - Unbans
    - Baseline recalculations
    Format: [timestamp] ACTION ip | condition | rate | baseline | duration
    """

    def __init__(self, log_file):
        self.log_file = log_file

    def _write(self, line):
        """Write a line to the audit log."""
        try:
            with open(self.log_file, "a") as f:
                f.write(line + "\n")
        except Exception as e:
            print(f"[Audit] Failed to write log: {e}")

    def log_ban(self, ip, condition, rate, baseline_mean, duration):
        """Log a ban event."""
        now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        duration_str = str(duration) if duration > 0 else "permanent"
        line = (
            f"[{now}] BAN {ip} | "
            f"condition={condition} | "
            f"rate={rate:.2f} | "
            f"baseline={baseline_mean:.2f} | "
            f"duration={duration_str}"
        )
        self._write(line)
        print(f"[Audit] {line}")

    def log_unban(self, ip, duration, next_duration):
        """Log an unban event."""
        now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        next_str = (
            str(next_duration) if next_duration > 0 else "permanent"
        )
        line = (
            f"[{now}] UNBAN {ip} | "
            f"duration={duration} | "
            f"next_ban_duration={next_str}"
        )
        self._write(line)
        print(f"[Audit] {line}")

    def log_baseline(self, mean, stddev, samples):
        """Log a baseline recalculation event."""
        now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        line = (
            f"[{now}] BASELINE_RECALC | "
            f"mean={mean:.2f} | "
            f"stddev={stddev:.2f} | "
            f"samples={samples}"
        )
        self._write(line)
        print(f"[Audit] {line}")
