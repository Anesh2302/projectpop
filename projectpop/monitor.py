import re
import os
import time
import json
import threading
from datetime import datetime
from pathlib import Path

from .config import load_config
from .notifier import send_security_alert
from .ip_blocker import block_ip


LOG_PATTERNS = {
    "brute_force": [
        r"(?i)(Failed password|authentication failure|Invalid user)",
    ],
    "sql_injection": [
        r"(?i)(union.*select|select.*from|drop\s+table|--\s+|';|1=1)",
    ],
    "path_traversal": [
        r"(?i)(\.\./|\.\.\\|/etc/passwd|/proc/self)",
    ],
    "xss_attempt": [
        r"(?i)(<script|<iframe|alert\(|onerror=|onload=)",
    ],
    "scanning": [
        r"(?i)(nikto|nmap|dirbuster|gobuster|wpscan|acunetix)",
    ],
}

FAILURE_LIMIT = 5
ip_failure_count = {}
blocked_ips = set()


def parse_log_line(line):
    patterns = [
        (r'(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\d+)', "apache_common"),
        (r'(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"', "apache_combined"),
        (r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\d+)', "nginx"),
    ]

    for pat, fmt in patterns:
        m = re.match(pat, line)
        if m:
            groups = m.groups()
            ip = groups[0]
            ts_str = groups[1]
            request = groups[2]
            status = groups[3]
            ua = groups[5] if len(groups) > 5 else ""

            ts = datetime.now()
            try:
                ts = datetime.strptime(ts_str.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                pass

            return {
                "ip": ip,
                "time": ts.isoformat(),
                "request": request,
                "status": status,
                "user_agent": ua,
            }
    return None


def analyze_request(parsed):
    if not parsed:
        return None

    ip = parsed["ip"]
    request = parsed["request"]
    ua = parsed.get("user_agent", "")
    combined = f"{request} {ua}"

    if ip in blocked_ips:
        return None

    for attack_type, patterns in LOG_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, combined):
                return {
                    "type": attack_type,
                    "ip": ip,
                    "time": parsed["time"],
                    "endpoint": request.split(" ")[1] if " " in request else request,
                    "user_agent": ua[:100],
                }

    return None


def is_whitelisted(ip):
    cfg = load_config()
    return ip in cfg.get("monitor", {}).get("whitelist_ips", [])


def watch_logs():
    cfg = load_config()
    log_paths = cfg.get("monitor", {}).get("log_paths", [])
    interval = cfg.get("monitor", {}).get("watch_interval", 5)
    max_failures = cfg.get("monitor", {}).get("max_failures", 5)

    if not log_paths:
        print("No log paths configured. Run: projectpop config add-log <path>")
        return

    positions = {p: 0 for p in log_paths if os.path.exists(p)}
    print(f"Watching {len(positions)} log files...")

    while True:
        for log_path in list(positions.keys()):
            if not os.path.exists(log_path):
                continue
            try:
                with open(log_path, encoding="utf-8", errors="ignore") as f:
                    f.seek(positions[log_path])
                    for line in f:
                        parsed = parse_log_line(line)
                        incident = analyze_request(parsed)
                        if incident and not is_whitelisted(incident["ip"]):
                            handle_incident(incident, max_failures)
                    positions[log_path] = f.tell()
            except (OSError, PermissionError):
                pass

        time.sleep(interval)


def handle_incident(incident, max_failures):
    ip = incident["ip"]
    ip_failure_count[ip] = ip_failure_count.get(ip, 0) + 1
    count = ip_failure_count[ip]

    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
          f"{incident['type'].upper()} from {ip} (count: {count}/{max_failures})")

    if count >= max_failures:
        incident["action"] = "IP blocked via firewall"
        block_ip(ip)
        blocked_ips.add(ip)
        send_security_alert(incident)
        print(f">>> BLOCKED {ip}")
        del ip_failure_count[ip]


def monitor_daemon():
    t = threading.Thread(target=watch_logs, daemon=True)
    t.start()
    return t
