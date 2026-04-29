import time
import threading
import psutil
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

# Shared state - will be set by main.py
state = {
    "banned_ips": {},
    "global_rate": 0.0,
    "top_ips": [],
    "baseline_mean": 0.0,
    "baseline_stddev": 0.0,
    "start_time": time.time(),
    "total_requests": 0,
}

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>HNG Anomaly Detector</title>
    <meta http-equiv="refresh" content="3">
    <style>
        body {
            font-family: monospace;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
        }
        h1 { color: #58a6ff; }
        h2 { color: #8b949e; border-bottom: 1px solid #30363d; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }
        th, td {
            padding: 8px;
            text-align: left;
            border: 1px solid #30363d;
        }
        th { background: #161b22; color: #58a6ff; }
        tr:hover { background: #161b22; }
        .metric {
            display: inline-block;
            background: #161b22;
            padding: 15px 25px;
            margin: 10px;
            border-radius: 8px;
            border: 1px solid #30363d;
        }
        .metric-value {
            font-size: 2em;
            color: #58a6ff;
        }
        .banned { color: #f85149; }
        .safe { color: #3fb950; }
    </style>
</head>
<body>
    <h1>HNG Anomaly Detection Dashboard</h1>

    <div>
        <div class="metric">
            <div>Uptime</div>
            <div class="metric-value">{{ uptime }}</div>
        </div>
        <div class="metric">
            <div>Global Req/s</div>
            <div class="metric-value">{{ global_rate }}</div>
        </div>
        <div class="metric">
            <div>Banned IPs</div>
            <div class="metric-value banned">{{ banned_count }}</div>
        </div>
        <div class="metric">
            <div>CPU Usage</div>
            <div class="metric-value">{{ cpu }}%</div>
        </div>
        <div class="metric">
            <div>Memory Usage</div>
            <div class="metric-value">{{ memory }}%</div>
        </div>
    </div>

    <h2>Baseline</h2>
    <table>
        <tr>
            <th>Mean (req/s)</th>
            <th>Std Dev</th>
        </tr>
        <tr>
            <td>{{ baseline_mean }}</td>
            <td>{{ baseline_stddev }}</td>
        </tr>
    </table>

    <h2>Banned IPs</h2>
    <table>
        <tr>
            <th>IP</th>
            <th>Banned At</th>
            <th>Unban At</th>
            <th>Ban Count</th>
            <th>Permanent</th>
        </tr>
        {% for ip, info in banned_ips.items() %}
        <tr>
            <td class="banned">{{ ip }}</td>
            <td>{{ info.banned_at_str }}</td>
            <td>{{ info.unban_at_str }}</td>
            <td>{{ info.ban_count }}</td>
            <td>{{ info.permanent }}</td>
        </tr>
        {% endfor %}
    </table>

    <h2>Top 10 Source IPs</h2>
    <table>
        <tr>
            <th>IP</th>
            <th>Requests (last 60s)</th>
        </tr>
        {% for ip, count in top_ips %}
        <tr>
            <td>{{ ip }}</td>
            <td>{{ count }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""


@app.route("/")
def dashboard():
    uptime_seconds = int(time.time() - state["start_time"])
    hours = uptime_seconds // 3600
    minutes = (uptime_seconds % 3600) // 60
    seconds = uptime_seconds % 60

    banned_ips = {}
    for ip, info in state["banned_ips"].items():
        banned_ips[ip] = {
            **info,
            "banned_at_str": time.strftime(
                "%H:%M:%S", time.localtime(info["banned_at"])
            ),
            "unban_at_str": (
                time.strftime(
                    "%H:%M:%S", time.localtime(info["unban_at"])
                )
                if info["unban_at"] > 0
                else "Never"
            ),
        }

    return render_template_string(
        HTML,
        uptime=f"{hours:02d}:{minutes:02d}:{seconds:02d}",
        global_rate=f"{state['global_rate']:.2f}",
        banned_count=len(state["banned_ips"]),
        cpu=psutil.cpu_percent(),
        memory=psutil.virtual_memory().percent,
        baseline_mean=f"{state['baseline_mean']:.2f}",
        baseline_stddev=f"{state['baseline_stddev']:.2f}",
        banned_ips=banned_ips,
        top_ips=state["top_ips"],
    )


@app.route("/api/metrics")
def metrics():
    return jsonify({
        "global_rate": state["global_rate"],
        "banned_ips": list(state["banned_ips"].keys()),
        "baseline_mean": state["baseline_mean"],
        "baseline_stddev": state["baseline_stddev"],
        "uptime": int(time.time() - state["start_time"]),
        "cpu": psutil.cpu_percent(),
        "memory": psutil.virtual_memory().percent,
    })


def start_dashboard(port, shared_state):
    """Start the dashboard in a background thread."""
    global state
    state = shared_state
    thread = threading.Thread(
        target=lambda: app.run(
            host="0.0.0.0",
            port=port,
            debug=False,
            use_reloader=False
        ),
        daemon=True
    )
    thread.start()
    print(f"[Dashboard] Started on port {port}")
