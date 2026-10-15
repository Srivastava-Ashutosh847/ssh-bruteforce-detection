

import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from detection_rules import detect_bruteforce
from log_parser import parse_failed_login
from alert_writer import write_alert

THRESHOLD = 3
WINDOW = "5 minutes ago"
PROJECT_DIR = Path("/home/ashutosh/soc-bruteforce-detection")
ALERT_FILE = PROJECT_DIR / "alerts.jsonl"
STATE_FILE = PROJECT_DIR / ".alert_state.json"


result = subprocess.run(
    ["journalctl", "-u", "ssh", "--since", WINDOW,
     "--no-pager", "-o", "short-iso"],
    capture_output=True, text=True, check=True
)

counts = Counter(
    ip
    for line in result.stdout.splitlines()
    if (ip := parse_failed_login(line)) is not None
)

try:
    state = json.loads(STATE_FILE.read_text())
except (FileNotFoundError, json.JSONDecodeError):
    state = {}
detected = detect_bruteforce(counts, threshold=THRESHOLD)

for ip, count in counts.items():
    if ip not in detected:
        state.pop(ip, None)
        continue

    if state.get(ip) == count:
        continue

    alert = write_alert(ALERT_FILE, ip, count)

    print(json.dumps(alert, indent=2))
    state[ip] = count

    with ALERT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")

    print(json.dumps(alert, indent=2))
    state[ip] = count

STATE_FILE.write_text(json.dumps(state))
if not counts or all(count < THRESHOLD for count in counts.values()):
    print("[INFO] No brute-force threshold reached.")
