import time
import signal
import sys
from config import load_config
from monitor import tail_log
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from notifier import Notifier
from unbanner import Unbanner
from audit import AuditLogger
from dashboard import start_dashboard

# Load config
config = load_config()

# Initialize components
audit = AuditLogger(config["audit_log"])
baseline = BaselineTracker(config)
detector = AnomalyDetector(config)
blocker = Blocker(config)
notifier = Notifier(config)
unbanner = Unbanner(blocker, notifier, audit)

# Shared state for dashboard
shared_state = {
    "banned_ips": blocker.banned_ips,
    "global_rate": 0.0,
    "top_ips": [],
    "baseline_mean": baseline.mean,
    "baseline_stddev": baseline.stddev,
    "start_time": time.time(),
    "total_requests": 0,
}

# Start dashboard
start_dashboard(config["dashboard"]["port"], shared_state)

# Start unbanner
unbanner.start()

# Graceful shutdown
def handle_shutdown(signum, frame):
    print("\n[Main] Shutting down...")
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)

print("[Main] HNG Anomaly Detector started")
print(f"[Main] Monitoring: {config['log_file']}")

# Per-second counter for baseline
second_count = 0
second_error_count = 0
last_second = time.time()
last_baseline_update = time.time()

# Main loop - process log entries
for entry in tail_log(config["log_file"]):
    now = time.time()
    ip = entry.get("source_ip", "")
    status = entry.get("status", 200)
    is_error = status >= 400

    if not ip:
        continue

    # Skip already banned IPs
    if ip in blocker.banned_ips:
        continue

    # Record in detector sliding windows
    detector.record(ip, is_error)
    shared_state["total_requests"] += 1

    # Count for baseline (per second)
    second_count += 1
    if is_error:
        second_error_count += 1

    # Every second - update baseline and check anomalies
    if now - last_second >= 1.0:
        # Record per-second count in baseline
        baseline.record(second_count, second_error_count)

        # Log baseline recalculation
        if now - last_baseline_update >= config["detection"][
            "recalculation_interval"
        ]:
            audit.log_baseline(
                baseline.mean,
                baseline.stddev,
                len(baseline.window)
            )
            last_baseline_update = now

        # Update dashboard state
        shared_state["global_rate"] = detector.get_global_rate()
        shared_state["top_ips"] = detector.get_top_ips(10)
        shared_state["baseline_mean"] = baseline.mean
        shared_state["baseline_stddev"] = baseline.stddev

        # Reset per-second counters
        second_count = 0
        second_error_count = 0
        last_second = now

    # Check IP anomaly
    is_anomalous, rate, reason = detector.check_ip(
        ip, baseline, blocker.banned_ips
    )

    if is_anomalous and reason:
        print(f"[Detector] IP anomaly detected: {ip} — {reason}")

        # Ban the IP
        blocker.ban(ip)
        info = blocker.banned_ips.get(ip, {})
        duration = info.get("duration", 600)

        # Send Slack alert
        notifier.ban_alert(
            ip, rate, baseline.mean, reason, duration
        )

        # Write audit log
        audit.log_ban(
            ip, reason, rate, baseline.mean, duration
        )

    # Check global anomaly
    is_global, global_rate, global_reason = detector.check_global(
        baseline
    )

    if is_global and global_reason:
        print(f"[Detector] Global anomaly: {global_reason}")
        notifier.global_alert(
            global_rate, baseline.mean, global_reason
        )
