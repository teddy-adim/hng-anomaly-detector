import subprocess
import time


class Blocker:
    """
    Manages iptables rules to block and unblock IPs.
    Maintains a list of banned IPs with unban schedules.
    """

    def __init__(self, config):
        self.unban_schedule = config["blocking"]["unban_schedule"]

        # banned_ips: dict of IP -> {
        #   banned_at, unban_at, ban_count, permanent
        # }
        self.banned_ips = {}

    def ban(self, ip):
        """Add iptables DROP rule for an IP."""
        if ip in self.banned_ips:
            return

        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )

            now = time.time()
            ban_count = 0
            duration = self.unban_schedule[ban_count]

            self.banned_ips[ip] = {
                "banned_at": now,
                "unban_at": now + duration if duration > 0 else -1,
                "ban_count": ban_count,
                "permanent": duration == -1,
                "duration": duration
            }

            print(f"[Blocker] Banned IP: {ip} for {duration}s")

        except subprocess.CalledProcessError as e:
            print(f"[Blocker] Failed to ban {ip}: {e}")

    def unban(self, ip):
        """Remove iptables DROP rule for an IP."""
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            print(f"[Blocker] Unbanned IP: {ip}")

        except subprocess.CalledProcessError as e:
            print(f"[Blocker] Failed to unban {ip}: {e}")

    def reban(self, ip):
        """
        Re-ban an IP with the next duration in the schedule.
        Implements backoff — 10min, 30min, 2hrs, permanent.
        """
        info = self.banned_ips.get(ip, {})
        ban_count = info.get("ban_count", 0) + 1

        if ban_count >= len(self.unban_schedule):
            ban_count = len(self.unban_schedule) - 1

        duration = self.unban_schedule[ban_count]
        now = time.time()

        self.ban(ip)
        self.banned_ips[ip]["ban_count"] = ban_count
        self.banned_ips[ip]["duration"] = duration
        self.banned_ips[ip]["banned_at"] = now
        self.banned_ips[ip]["unban_at"] = (
            now + duration if duration > 0 else -1
        )
        self.banned_ips[ip]["permanent"] = duration == -1

    def check_unbans(self):
        """
        Check if any IPs should be unbanned.
        Returns list of unbanned IPs.
        """
        now = time.time()
        to_unban = []

        for ip, info in list(self.banned_ips.items()):
            if info["permanent"]:
                continue
            if info["unban_at"] > 0 and now >= info["unban_at"]:
                to_unban.append(ip)

        return to_unban

    def release(self, ip):
        """Unban and remove from banned list for reban scheduling."""
        self.unban(ip)
        if ip in self.banned_ips:
            del self.banned_ips[ip]

    def get_banned(self):
        """Return current banned IPs dict."""
        return self.banned_ips
