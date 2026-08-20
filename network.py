import subprocess
import platform
import os
import socket
import struct


def get_platform():
    return platform.system().lower()


def is_admin():
    if get_platform() == "windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


def block_ip_firewall(ip_address, reason="Blocked by ProjectPop"):
    system = get_platform()
    rule_name = f"ProjectPop_Block_{ip_address.replace('.', '_')}"

    try:
        if system == "windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip_address}",
                f"description={reason}",
                "enable=yes",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                return True, f"Blocked {ip_address} via Windows Firewall"
            return False, f"Firewall error: {result.stderr.strip()}"

        elif system == "linux":
            cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                cmd2 = ["iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"]
                subprocess.run(cmd2, capture_output=True, text=True, timeout=15)
                return True, f"Blocked {ip_address} via iptables"
            return False, f"iptables error: {result.stderr.strip()}"

        elif system == "darwin":
            cmd = [
                "/usr/libexec/ApplicationFirewall/socketfilterfw",
                "--setblockall", "on",
            ]
            pf_rule = f"block drop from {ip_address} to any\nblock drop from any to {ip_address}"
            cmd_pf = ["pfctl", "-ef", pf_rule]
            result = subprocess.run(cmd_pf, capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                return True, f"Blocked {ip_address} via pf firewall"
            return False, f"pf error: {result.stderr.strip()}"

        return False, f"Unsupported platform: {system}"
    except FileNotFoundError:
        return False, f"Firewall tool not found on {system}"
    except subprocess.TimeoutExpired:
        return False, "Firewall command timed out"
    except Exception as e:
        return False, f"Error: {str(e)}"


def unblock_ip_firewall(ip_address):
    system = get_platform()
    rule_name = f"ProjectPop_Block_{ip_address.replace('.', '_')}"

    try:
        if system == "windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                return True, f"Unblocked {ip_address}"
            return False, f"Error: {result.stderr.strip()}"

        elif system == "linux":
            for chain in ["INPUT", "OUTPUT"]:
                cmd = ["iptables", "-D", chain, "-s" if chain == "INPUT" else "-d",
                       ip_address, "-j", "DROP"]
                subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return True, f"Removed iptables rules for {ip_address}"

        return False, f"Unsupported platform: {system}"
    except Exception as e:
        return False, f"Error: {str(e)}"


def get_blocked_ips_firewall():
    system = get_platform()
    blocked = []

    try:
        if system == "windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "show", "rule",
                "name=all", "dir=in", "action=block",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                current_rule = {}
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if line.startswith("Rule Name:"):
                        name = line.split(":", 1)[1].strip()
                        if name.startswith("ProjectPop_Block_"):
                            ip = name.replace("ProjectPop_Block_", "").replace("_", ".")
                            current_rule = {"ip": ip, "name": name}
                    elif line.startswith("RemoteIP:") and current_rule:
                        current_rule["remote_ip"] = line.split(":", 1)[1].strip()
                        blocked.append(current_rule)
                        current_rule = {}
            return blocked

        elif system == "linux":
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "DROP" in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == "0.0.0.0/0" and i + 1 < len(parts):
                                ip = parts[i + 1] if parts[i + 1] != "0.0.0.0/0" else None
                                if ip and ip != "0.0.0.0/0":
                                    blocked.append({"ip": ip, "source": "iptables"})
            return blocked

    except Exception:
        pass
    return blocked


def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def check_port(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def get_network_info():
    info = {
        "hostname": socket.gethostname(),
        "platform": get_platform(),
        "is_admin": is_admin(),
        "local_ip": None,
    }
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["local_ip"] = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    return info
