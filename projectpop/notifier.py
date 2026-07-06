import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

from .config import load_config


def send_email(subject, body, html=False, recipient=None):
    cfg = load_config()
    smtp = cfg["smtp"]
    user = cfg["user"]

    if not smtp["username"] or not smtp["password"]:
        print("SMTP not configured. Run: projectpop config setup")
        return False

    to = recipient or user["email"]

    msg = MIMEMultipart("alternative")
    msg["From"] = f"{user['name']} <{smtp['username']}>"
    msg["To"] = to
    msg["Subject"] = subject

    content = MIMEText(body, "html" if html else "plain")
    msg.attach(content)

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(smtp["server"], smtp["port"], timeout=15) as server:
            server.starttls(context=ctx)
            server.login(smtp["username"], smtp["password"])
            server.sendmail(smtp["username"], [to], msg.as_string())
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False


def send_scan_report(project_name, issues_summary):
    subject = f"[projectpop] Scan Report: {project_name}"
    body = f"""<h2>Project Scan Report: {project_name}</h2>
<p>Scanned at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<hr>
<pre>{issues_summary}</pre>
<hr>
<p><small>Sent by projectpop security monitor</small></p>"""
    return send_email(subject, body, html=True)


def send_security_alert(incident):
    subject = f"[SECURITY ALERT] {incident['type']} from {incident['ip']}"
    body = f"""<h2 style="color:red">Security Incident Detected</h2>
<table border="1" cellpadding="6" style="border-collapse:collapse">
<tr><td><b>Time</b></td><td>{incident['time']}</td></tr>
<tr><td><b>Type</b></td><td>{incident['type']}</td></tr>
<tr><td><b>Source IP</b></td><td>{incident['ip']}</td></tr>
<tr><td><b>Location</b></td><td>{incident.get('location', 'Unknown')}</td></tr>
<tr><td><b>Endpoint</b></td><td>{incident.get('endpoint', 'N/A')}</td></tr>
<tr><td><b>User Agent</b></td><td>{incident.get('user_agent', 'N/A')}</td></tr>
<tr><td><b>Action Taken</b></td><td style="color:green">{incident.get('action', 'IP blocked')}</td></tr>
</table>
<hr>
<p><small>Sent by projectpop security monitor</small></p>"""
    return send_email(subject, body, html=True)


def send_otp_email(otp_code, recipient_email):
    subject = "Your OTP Code"
    body = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;background:#f4f7fb">
  <table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
    <table width="480" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);overflow:hidden">
      <tr><td style="background:linear-gradient(135deg,#2563eb,#7c3aed);padding:24px;text-align:center">
        <h1 style="margin:0;color:#fff;font-size:22px">projectpop</h1>
      </td></tr>
      <tr><td style="padding:32px 28px;text-align:center">
        <p style="color:#6b7280;font-size:14px;margin:0 0 20px">Your one-time password</p>
        <div style="background:#f0f5ff;border-radius:10px;padding:20px;margin-bottom:20px;letter-spacing:8px;font-size:36px;font-weight:bold;color:#2563eb;font-family:monospace">{otp_code}</div>
        <p style="color:#6b7280;font-size:13px;margin:0">This code expires in <strong style="color:#374151">5 minutes</strong>.</p>
        <p style="color:#9ca3af;font-size:12px;margin:20px 0 0;border-top:1px solid #e5e7eb;padding-top:16px">If you did not request this code, please ignore this email.</p>
      </td></tr>
    </table>
  </td></tr></table>
</body></html>"""
    return send_email(subject, body, html=True, recipient=recipient_email)


def send_daily_summary(todos_today=None, pending_count=0, blocked_ips=None, incidents=None):
    today_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    todos_today = todos_today or []
    incidents = incidents or []

    rows = ""
    for t in todos_today:
        rows += f"<tr><td>{t.get('scheduled_time', '—')}</td><td>{t['title']}</td>"
        rows += f"<td><span style='background:#f0883e;padding:2px 8px;border-radius:12px;color:#000;font-size:11px'>{t['priority']}</span></td>"
        rows += f"<td><span style='background:#58a6ff;padding:2px 8px;border-radius:12px;color:#fff;font-size:11px'>{t['status']}</span></td></tr>"

    alert_rows = ""
    for inc in incidents:
        alert_rows += f"<tr><td>{inc['type']}</td><td>{inc['ip']}</td>"
        alert_rows += f"<td>{inc.get('endpoint', 'N/A')}</td>"
        alert_rows += f"<td style='color:green'>{inc.get('action', 'Blocked')}</td></tr>"

    blocked_info = f"<p><b>Blocked IPs:</b> {blocked_ips}</p>" if blocked_ips is not None else ""

    body = f"""<h2>Daily Summary — {today_str}</h2>
{blocked_info}
<h3 style="color:#f0883e">Today's Schedule ({len(todos_today)})</h3>
<table border="1" cellpadding="6" style="border-collapse:collapse;width:100%">
<tr style="background:#1c2128"><th>Time</th><th>Task</th><th>Priority</th><th>Status</th></tr>
{rows or '<tr><td colspan="4" style="text-align:center;color:#484f58">No tasks scheduled</td></tr>'}
</table>
<p><b>Pending tasks:</b> {pending_count}</p>
<hr>
<h3 style="color:red">Security Alerts ({len(incidents)})</h3>
<table border="1" cellpadding="6" style="border-collapse:collapse;width:100%">
<tr style="background:#1c2128"><th>Type</th><th>Source IP</th><th>Endpoint</th><th>Action</th></tr>
{alert_rows or '<tr><td colspan="4" style="text-align:center;color:#484f58">No security incidents today</td></tr>'}
</table>
<hr>
<p><small>Sent by projectpop daily summary</small></p>"""
    return send_email(f"[projectpop] Daily Summary — {datetime.now().strftime('%Y-%m-%d')}", body, html=True)
