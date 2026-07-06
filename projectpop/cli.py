import sys
import os
import json
from datetime import datetime

from . import __version__
from .config import load_config, save_config, set_smtp_password, set_github_token
from .scanner import scan_project, scan_all_projects, generate_report_text
from .notifier import send_email, send_scan_report, send_security_alert, send_daily_summary
from .monitor import watch_logs, monitor_daemon
from .ip_blocker import block_ip, unblock_ip, list_blocked
from .otp import register_user, generate_otp, verify_otp
from .github_publisher import push_local_project


BANNER = f"""
{'='*58}
    P R O J E C T P O P   v{__version__}
    Project Analyzer · Security Monitor · GitHub Publisher
    Built for Simon Peter Chappell
{'='*58}
"""


def cmd_scan(args):
    cfg = load_config()
    paths = args or cfg.get("scan", {}).get("project_paths", [])

    if not paths:
        print("No project paths specified.")
        print("  Set paths: projectpop config add-scan-path <path>")
        print("  Or pass:   projectpop scan <path1> <path2> ...")
        return

    for p in paths:
        p = os.path.abspath(p)
        print(f"\n{'='*50}")
        print(f"Scanning: {p}")
        print("=" * 50)
        result = scan_project(p)
        report = generate_report_text(result)
        print(report)

        cfg_user = cfg.get("notifications", {})
        if cfg_user.get("on_project_change", True):
            send_scan_report(result["project"], report)
            print("  [Report emailed]")


def cmd_monitor(args):
    if args and args[0] == "daemon":
        print("Starting security monitor daemon...")
        print("Press Ctrl+C to stop.")
        try:
            watch_logs()
        except KeyboardInterrupt:
            print("\nMonitor stopped.")
    elif args and args[0] == "test-alert":
        incident = {
            "type": "brute_force",
            "ip": "203.0.113.42",
            "time": datetime.now().isoformat(),
            "endpoint": "/wp-login.php",
            "user_agent": "Mozilla/5.0 (compatible; test)",
            "action": "test alert",
            "location": "Test City, Testland",
        }
        send_security_alert(incident)
        print("Test alert sent.")
    else:
        print("Usage:")
        print("  projectpop monitor daemon       - Start monitoring")
        print("  projectpop monitor test-alert   - Send test alert")


def cmd_block(args):
    if not args:
        list_blocked()
        return
    action = args[0]
    if action == "list":
        list_blocked()
    elif action == "add" and len(args) >= 2:
        block_ip(args[1])
    elif action == "remove" and len(args) >= 2:
        unblock_ip(args[1])
    else:
        print("Usage:")
        print("  projectpop block list           - Show blocked IPs")
        print("  projectpop block add <ip>       - Block an IP")
        print("  projectpop block remove <ip>    - Unblock an IP")


def cmd_otp(args):
    if not args:
        print("Usage:")
        print("  projectpop otp register <user_id> <email>")
        print("  projectpop otp generate <user_id>")
        print("  projectpop otp verify <user_id> <code>")
        return

    action = args[0]
    if action == "register" and len(args) >= 3:
        secret = register_user(args[1], args[2])
        print(f"User '{args[1]}' registered. OTP secret generated.")
    elif action == "generate" and len(args) >= 2:
        code = generate_otp(args[1])
        if code:
            print(f"OTP sent to registered email for '{args[1]}'.")
        else:
            print(f"User '{args[1]}' not found.")
    elif action == "verify" and len(args) >= 3:
        ok = verify_otp(args[1], args[2])
        print("OTP VERIFIED" if ok else "INVALID OTP")
    else:
        print("Invalid otp command.")


def cmd_github(args):
    if not args:
        print("Usage:")
        print("  projectpop github push <local_path> <repo_name>")
        return

    action = args[0]
    if action == "push" and len(args) >= 3:
        local_path = os.path.abspath(args[1])
        repo_name = args[2]
        print(f"Pushing '{local_path}' to GitHub as '{repo_name}'...")
        push_local_project(local_path, repo_name)
    else:
        print("Invalid github command.")


def cmd_report(args):
    cfg = load_config()
    paths = cfg.get("scan", {}).get("project_paths", [])
    if args:
        paths = [os.path.abspath(p) for p in args]

    if not paths:
        print("No projects configured or specified.")
        return

    full_report = []
    for p in paths:
        r = scan_project(p)
        full_report.append(generate_report_text(r))

    report_text = "\n\n".join(full_report)
    date_str = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    report_file = f"projectpop_report_{date_str}.txt"
    with open(report_file, "w") as f:
        f.write(report_text)
    print(f"Report saved to {report_file}")

    send_email(
        f"[projectpop] Full Scan Report - {date_str}",
        report_text.replace("\n", "<br>"),
        html=True,
    )
    print("Report emailed.")


def cmd_config(args):
    cfg = load_config()

    if not args:
        print(json.dumps(cfg, indent=2))
        return

    action = args[0]

    if action == "setup":
        print("Configuring projectpop...")
        email = input(f"Email [{cfg['user']['email']}]: ").strip() or cfg['user']['email']
        cfg['user']['email'] = email
        save_config(cfg)

        smtp_user = input(f"SMTP username [{cfg['smtp']['username']}]: ").strip() or cfg['smtp']['username']
        cfg['smtp']['username'] = smtp_user
        save_config(cfg)

        set_smtp_password()
        print("SMTP configured.")

        gh_token = input("GitHub token (leave blank to skip): ").strip()
        if gh_token:
            cfg['github']['token'] = gh_token
            save_config(cfg)
        print("Setup complete.")

    elif action == "add-scan-path" and len(args) >= 2:
        p = os.path.abspath(args[1])
        if p not in cfg["scan"]["project_paths"]:
            cfg["scan"]["project_paths"].append(p)
            save_config(cfg)
            print(f"Added scan path: {p}")
        else:
            print("Path already exists.")

    elif action == "add-log" and len(args) >= 2:
        p = os.path.abspath(args[1])
        if p not in cfg["monitor"]["log_paths"]:
            cfg["monitor"]["log_paths"].append(p)
            save_config(cfg)
            print(f"Added log path: {p}")
        else:
            print("Log path already exists.")

    elif action == "whitelist" and len(args) >= 3:
        ip = args[2]
        if args[1] == "add":
            if ip not in cfg["monitor"]["whitelist_ips"]:
                cfg["monitor"]["whitelist_ips"].append(ip)
                save_config(cfg)
                print(f"Whitelisted: {ip}")
        elif args[1] == "remove":
            cfg["monitor"]["whitelist_ips"] = [i for i in cfg["monitor"]["whitelist_ips"] if i != ip]
            save_config(cfg)
            print(f"Removed from whitelist: {ip}")

    elif action == "smtp-pass":
        set_smtp_password()

    elif action == "github-token":
        set_github_token()

    else:
        print("Commands:")
        print("  projectpop config setup                    - Initial setup")
        print("  projectpop config add-scan-path <path>    - Add project to scan")
        print("  projectpop config add-log <path>          - Add log file to watch")
        print("  projectpop config whitelist add <ip>      - Whitelist an IP")
        print("  projectpop config whitelist remove <ip>   - Remove IP whitelist")
        print("  projectpop config smtp-pass               - Set SMTP password")
        print("  projectpop config github-token             - Set GitHub token")


def cmd_test_email(args):
    ok = send_email("Test from projectpop", "This is a test email from projectpop.")
    print("Email sent successfully!" if ok else "Failed to send email.")


def cmd_schedule(args):
    if not args:
        print("Usage: projectpop schedule daily [--install]")
        return

    if args[0] == "daily" and "--install" in args:
        from pathlib import Path
        script = Path(__file__).resolve().parent.parent / "run_daily.bat"
        task_name = "projectpop-daily-summary"
        cmd = (
            f'SCHTASKS /CREATE /SC DAILY /TN "{task_name}" '
            f'/TR "{script}" /ST 09:00 /F'
        )
        os.system(cmd)
        print(f"Scheduled task '{task_name}' created. Runs daily at 9:00 AM.")
        return

    if args[0] != "daily":
        print("Usage: projectpop schedule daily [--install]")
        return

    cfg = load_config()
    blocked_list = list_blocked()
    blocked_count = len(blocked_list)

    today_todos = []
    try:
        import urllib.request
        resp = urllib.request.urlopen("http://localhost:5000/admin/todos/today", timeout=5)
        today_todos = json.loads(resp.read())
    except Exception as e:
        print(f"Could not fetch today's todos from talentos API: {e}")

    pending_count = sum(1 for t in today_todos if t.get("status") == "pending")

    incidents = []
    try:
        with open(os.path.expanduser("~/.projectpop/blocked_ips.json")) as f:
            incidents = json.load(f)
            if isinstance(incidents, list):
                incidents = [{"type": "Auto-block", "ip": i.get("ip", "?"), "endpoint": i.get("endpoint", "N/A"), "action": "Blocked"} for i in incidents[-5:]]
    except Exception:
        pass

    ok = send_daily_summary(today_todos, pending_count, blocked_ips=blocked_count, incidents=incidents)
    print("Daily summary sent!" if ok else "Failed to send daily summary.")


def main():
    print(BANNER)

    if len(sys.argv) < 2:
        print("Usage: projectpop <command> [args]")
        print()
        print("Commands:")
        print("  scan [path...]            Scan projects for issues")
        print("  report [path...]          Generate & email full report")
        print("  monitor daemon            Start security log watcher")
        print("  monitor test-alert        Send test security alert")
        print("  block list                Show blocked IPs")
        print("  block add <ip>            Block an IP")
        print("  block remove <ip>         Unblock an IP")
        print("  otp register <id> <email> Register user for OTP")
        print("  otp generate <id>         Send OTP code")
        print("  otp verify <id> <code>    Verify OTP code")
        print("  github push <path> <name> Push local project to GitHub")
        print("  config [args]             View/update configuration")
        print("  schedule daily            Send daily summary email")
        print("  schedule daily --install  Install Windows daily task (9:00 AM)")
        print("  test-email                Send test email")
        print("  version                   Show version")
        print("  env-setup                 Quick setup SMTP + GitHub")
        return

    command = sys.argv[1]
    args = sys.argv[2:]

    commands = {
        "scan": cmd_scan,
        "report": cmd_report,
        "monitor": cmd_monitor,
        "block": cmd_block,
        "otp": cmd_otp,
        "github": cmd_github,
        "config": cmd_config,
        "test-email": cmd_test_email,
        "schedule": cmd_schedule,
    }

    if command == "version":
        print(f"projectpop v{__version__}")
    elif command == "env-setup":
        cfg = load_config()
        cfg["smtp"]["username"] = "simonpetercys@gmail.com"
        cfg["smtp"]["password"] = "bdsg ebwt aoog hasj"
        cfg["user"]["email"] = "simonpetercys@gmail.com"
        cfg["user"]["name"] = "Simon Peter Chappell"
        cfg["github"]["username"] = "simonpeter"
        cfg["github"]["token"] = open(os.devnull, "r").read() if False else ""
        try:
            import subprocess
            result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
            if result.returncode == 0:
                cfg["github"]["token"] = result.stdout.strip()
        except Exception:
            pass
        save_config(cfg)
        print("Environment configured: SMTP and GitHub set.")
    elif command in commands:
        commands[command](args)
    else:
        print(f"Unknown command: {command}")
        print("Run 'projectpop' without arguments to see available commands.")


if __name__ == "__main__":
    main()
