import requests
import time


class Notifier:
    """Sends alerts to Slack."""

    def __init__(self, config):
        self.webhook_url = config["slack"]["webhook_url"]

    def send(self, message):
        """Send a message to Slack."""
        if not self.webhook_url:
            print(f"[Notifier] No webhook URL configured: {message}")
            return

        try:
            response = requests.post(
                self.webhook_url,
                json={"text": message},
                timeout=5
            )
            if response.status_code != 200:
                print(f"[Notifier] Slack error: {response.status_code}")
        except Exception as e:
            print(f"[Notifier] Failed to send alert: {e}")

    def ban_alert(self, ip, rate, baseline_mean, condition, duration):
        """Send a ban notification."""
        now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        duration_str = (
            f"{duration}s" if duration > 0 else "permanent"
        )
        message = (
            f":rotating_light: *IP BANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Condition:* {condition}\n"
            f"*Current Rate:* {rate:.2f} req/s\n"
            f"*Baseline Mean:* {baseline_mean:.2f} req/s\n"
            f"*Ban Duration:* {duration_str}\n"
            f"*Timestamp:* {now}"
        )
        self.send(message)

    def unban_alert(self, ip, duration):
        """Send an unban notification."""
        now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        duration_str = (
            f"{duration}s" if duration > 0 else "permanent"
        )
        message = (
            f":white_check_mark: *IP UNBANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Next Ban Duration:* {duration_str}\n"
            f"*Timestamp:* {now}"
        )
        self.send(message)

    def global_alert(self, rate, baseline_mean, condition):
        """Send a global anomaly notification."""
        now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        message = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f"*Condition:* {condition}\n"
            f"*Current Rate:* {rate:.2f} req/s\n"
            f"*Baseline Mean:* {baseline_mean:.2f} req/s\n"
            f"*Timestamp:* {now}"
        )
        self.send(message)
