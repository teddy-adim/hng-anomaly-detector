# HNG Anomaly Detection Engine

A real-time HTTP traffic anomaly detection and auto-blocking system built alongside Nextcloud.

## Live URLs

- Server IP: 18.250.21.245
- Metrics Dashboard: http://18.250.21.245:8080
- GitHub: https://github.com/Teddy-adim/hng-anomaly-detector
- Blog Post: [Add link after publishing]

## Language Choice

Built in Python because:
- Readable and easy to debug
- Excellent libraries for JSON parsing, HTTP, and system operations
- Fast development cycle ideal for DevOps tooling
- Strong ecosystem for networking and system-level programming

## How the Sliding Window Works

Two deque-based windows track request rates — one global, one per IP.

Each window covers the last 60 seconds:

- Every incoming request adds a timestamp to the right of the deque
- On each check, timestamps older than 60 seconds are evicted from the left
- Rate = number of timestamps remaining in deque divided by 60

This gives a real-time view of request rate without storing all historical data.
A deque is used instead of a list because removing from the left is instant (O1) rather than slow (ON).

## How the Baseline Works

- A 30-minute rolling window of per-second request counts is maintained
- Every 60 seconds, mean and standard deviation are recalculated from the window
- Per-hour slots track counts separately for each hour of the day (0-23)
- If the current hour has 10 or more samples, it is preferred over the full window
- A floor value of 1.0 prevents division by zero during low-traffic periods
- Baseline is never hardcoded — it always reflects real recent traffic

## How Detection Works

An IP or global rate is flagged as anomalous if either condition fires first:

1. Z-score exceeds 3.0 — the rate is 3 standard deviations above normal
2. Rate exceeds 5x the baseline mean

If an IP's error rate (4xx/5xx) is 3x the baseline error rate, thresholds are automatically tightened by 50% to catch aggressive IPs faster.

Z-score formula: z = (current_rate - baseline_mean) / baseline_stddev

## How Blocking Works

Per-IP anomaly:
- iptables DROP rule added immediately
- Slack alert sent within 10 seconds
- Auto-unban on backoff schedule: 10 minutes, 30 minutes, 2 hours, then permanent

Global anomaly:
- Slack alert only (no block — could affect legitimate users)

## Architecture

    Internet
        |
        v
    Nginx (port 80) -----> Nextcloud
        |
        v
    HNG-nginx-logs volume (named Docker volume)
        |
        v
    Detector daemon (reads logs in real time)
        |              |               |
        v              v               v
    iptables      Slack alerts    Dashboard (port 8080)
        |
        v
    Auto-unban (background thread, checks every 30 seconds)

## Repository Structure

    detector/
      main.py          Entry point, main processing loop
      monitor.py       Tails and parses Nginx access log
      baseline.py      Rolling baseline tracker
      detector.py      Sliding window anomaly detector
      blocker.py       iptables ban/unban manager
      unbanner.py      Background auto-unban thread
      notifier.py      Slack alert sender
      dashboard.py     Flask web dashboard
      audit.py         Structured audit logger
      config.yaml      All thresholds and settings
      requirements.txt Python dependencies
      Dockerfile
    nginx/
      nginx.conf       JSON access log configuration
    docs/
      architecture.png
    screenshots/
      Tool-running.png
      Ban-slack.png
      Unban-slack.png
      Global-alert-slack.png
      Iptables-banned.png
      Audit-log.png
      Baseline-graph.png
    README.md
    docker-compose.yml
    .env.example

## Setup Instructions

### Prerequisites

- Ubuntu 22.04 VPS (minimum 2 vCPU, 2GB RAM)
- Docker and Docker Compose installed
- Slack webhook URL

### Step 1 - Install Docker

    sudo apt update
    sudo apt install -y docker.io
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    sudo usermod -aG docker ubuntu
    exit

SSH back in after running exit.

### Step 2 - Clone the Repository

    git clone https://github.com/Teddy-adim/hng-anomaly-detector.git
    cd hng-anomaly-detector

### Step 3 - Configure Environment

    cp .env.example .env
    nano .env

Add your Slack webhook URL to the .env file.

### Step 4 - Start the Stack

    docker-compose up -d --build

### Step 5 - Verify Everything is Running

    docker-compose ps
    docker-compose logs -f detector

You should see the detector tailing the Nginx log and printing baseline recalculations every 60 seconds.

### Step 6 - Access the Dashboard

Visit http://YOUR_SERVER_IP:8080 in your browser.

### What a Successful Startup Looks Like

    NAME         STATUS
    nextcloud    running
    nginx        running
    detector     running

Detector logs should show:

    [Main] HNG Anomaly Detector started
    [Main] Monitoring: /var/log/nginx/hng-access.log
    [Dashboard] Started on port 5000
    [Unbanner] Started background unban checker
    [Baseline] Recalculated - mean=X.XX stddev=X.XX samples=XX

## Audit Log Format

Every ban, unban, and baseline recalculation is written to /app/audit.log:

    [2026-04-29 10:00:00 UTC] BAN 1.2.3.4 | condition=rate=45.20/s zscore=4.10 | rate=45.20 | baseline=8.30 | duration=600
    [2026-04-29 10:10:00 UTC] UNBAN 1.2.3.4 | duration=600 | next_ban_duration=1800
    [2026-04-29 10:01:00 UTC] BASELINE_RECALC | mean=8.30 | stddev=2.10 | samples=1800

## Environment Variables

See .env.example for all required variables.

    SLACK_WEBHOOK_URL    Your Slack incoming webhook URL
**Blog Post:** https://medium.com/@teddycayne/how-i-built-a-real-time-ddos-detection-system-that-blocks-attackers-in-under-10-seconds-f924a4f0d606
