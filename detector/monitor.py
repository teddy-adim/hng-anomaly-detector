import json
import time
import os


def tail_log(log_file):
    """
    Continuously tail the log file line by line.
    Like running 'tail -f' in the terminal.
    Yields parsed log entries as dictionaries.
    """
    # Wait for log file to exist
    while not os.path.exists(log_file):
        print(f"Waiting for log file: {log_file}")
        time.sleep(2)

    print(f"Monitoring log file: {log_file}")

    with open(log_file, "r") as f:
        # Go to end of file
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
                yield entry
            except json.JSONDecodeError:
                continue
