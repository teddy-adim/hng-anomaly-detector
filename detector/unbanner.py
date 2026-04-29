import time
import threading


class Unbanner:
    """
    Runs in a background thread.
    Checks for IPs that should be unbanned
    and handles reban scheduling.
    """

    def __init__(self, blocker, notifier, audit_logger):
        self.blocker = blocker
        self.notifier = notifier
        self.audit_logger = audit_logger
        self.running = True

    def start(self):
        """Start the unbanner in a background thread."""
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()
        print("[Unbanner] Started background unban checker")

    def _run(self):
        """Check for unbans every 30 seconds."""
        while self.running:
            try:
                self._check_unbans()
            except Exception as e:
                print(f"[Unbanner] Error: {e}")
            time.sleep(30)

    def _check_unbans(self):
        """Process any IPs due for unbanning."""
        to_unban = self.blocker.check_unbans()

        for ip in to_unban:
            info = self.blocker.banned_ips.get(ip, {})
            ban_count = info.get("ban_count", 0)
            duration = info.get("duration", 0)

            # Get next ban duration for notification
            schedule = self.blocker.unban_schedule
            next_index = min(ban_count + 1, len(schedule) - 1)
            next_duration = schedule[next_index]

            self.blocker.release(ip)
            self.notifier.unban_alert(ip, next_duration)
            self.audit_logger.log_unban(ip, duration, next_duration)

            print(f"[Unbanner] Released {ip} after {duration}s ban")
