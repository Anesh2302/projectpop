import subprocess
import sys
import os
import json
from datetime import datetime

BLOCKLIST_JSON = os.path.expanduser("~/.projectpop/blocked_ips.json")


def _load_blocklist():
    if os.path.exists(BLOCKLIST_JSON):
        with open(BLOCKLIST_JSON) as f:
            return json.load(f)
    return []


def _save_blocklist(entries):
    os.makedirs(os.path.dirname(BLOCKLIST_JSON), exist_ok=True)
    with open(BLOCKLIST_JSON, "w") as f:
        json.dump(entries, f, indent=2)


def block_ip(ip):
    platform = sys.platform

    if platform == "win32":
        rule_name = f"projectpop_block_{ip.replace('.', '_')}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in", "action=block",
            f"remoteip={ip}",
        ]
        try:
            subprocess.run(cmd, capture_output=True, check=True)
            _log_block(ip, "Windows Firewall")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP: {e.stderr.decode()}")
            return False

    elif platform == "linux":
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, check=True,
            )
            _log_block(ip, "iptables")
            return True
        except subprocess.CalledProcessError:
            pass
        try:
            subprocess.run(
                ["ufw", "deny", "from", ip],
                capture_output=True, check=True,
            )
            _log_block(ip, "UFW")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("No firewall tool found. Install iptables or ufw.")
            return False

    elif platform == "darwin":
        try:
            subprocess.run(
                ["pfctl", "-t", "blocklist", "-T", "add", ip],
                capture_output=True, check=True,
            )
            _log_block(ip, "pf")
            return True
        except subprocess.CalledProcessError:
            print("Could not add to pf blocklist.")
            return False

    else:
        _log_block(ip, "manual (no firewall automation)")
        return False


def unblock_ip(ip):
    entries = _load_blocklist()
    entries = [e for e in entries if e["ip"] != ip]
    _save_blocklist(entries)

    platform = sys.platform
    if platform == "win32":
        rule_name = f"projectpop_block_{ip.replace('.', '_')}"
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            capture_output=True,
        )
    elif platform == "linux":
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
    print(f"Unblocked {ip}")


def _log_block(ip, method):
    entries = _load_blocklist()
    entries.append({
        "ip": ip,
        "blocked_at": datetime.now().isoformat(),
        "method": method,
    })
    _save_blocklist(entries)


def list_blocked():
    entries = _load_blocklist()
    if not entries:
        print("No blocked IPs.")
        return []
    print(f"{'IP Address':<20} {'Blocked At':<25} {'Method'}")
    print("-" * 60)
    for e in entries:
        print(f"{e['ip']:<20} {e['blocked_at']:<25} {e['method']}")
    return entries
