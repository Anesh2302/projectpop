from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Website, Scan, BlockedIP, Alert, AuditLog
from scanner import scan_website
from network import block_ip_firewall, unblock_ip_firewall, get_network_info, is_admin
from config import Config
import json
import pyotp
import qrcode
import io
import base64
from datetime import datetime


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager = LoginManager(app)
    login_manager.login_view = "login"
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email="admin@projectpop.com").first():
            admin = User(email="admin@projectpop.com", name="Admin", role="admin")
            admin.set_password("admin123")
            admin.otp_enabled = False
            db.session.add(admin)
            db.session.commit()

    def log_action(action, target="", details=""):
        if current_user.is_authenticated:
            entry = AuditLog(
                user_id=current_user.id, action=action, target=target,
                details=details, ip_address=request.remote_addr or ""
            )
            db.session.add(entry)
            db.session.commit()

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                if user.otp_enabled:
                    session["pending_2fa_user"] = user.id
                    return redirect(url_for("verify_2fa"))
                login_user(user)
                user.last_seen = datetime.utcnow()
                db.session.commit()
                log_action("login", user.email)
                return redirect(url_for("dashboard"))
            flash("Invalid email or password", "danger")
        return render_template("login.html")

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            if not all([name, email, password]):
                flash("All fields are required", "danger")
                return render_template("signup.html")
            if User.query.filter_by(email=email).first():
                flash("Email already registered", "danger")
                return render_template("signup.html")
            user = User(name=name, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
        return render_template("signup.html")

    @app.route("/verify-2fa", methods=["GET", "POST"])
    def verify_2fa():
        user_id = session.get("pending_2fa_user")
        if not user_id:
            return redirect(url_for("login"))
        user = User.query.get(user_id)
        if not user:
            return redirect(url_for("login"))
        if request.method == "POST":
            token = request.form.get("token", "").strip()
            if user.verify_otp(token):
                session.pop("pending_2fa_user", None)
                login_user(user)
                user.last_seen = datetime.utcnow()
                db.session.commit()
                log_action("2fa_login", user.email)
                return redirect(url_for("dashboard"))
            flash("Invalid 2FA code", "danger")
        return render_template("verify_2fa.html")

    @app.route("/setup-2fa", methods=["GET", "POST"])
    @login_required
    def setup_2fa():
        if request.method == "POST":
            token = request.form.get("token", "").strip()
            if current_user.verify_otp(token):
                db.session.commit()
                log_action("2fa_enabled")
                flash("2FA enabled successfully!", "success")
                return redirect(url_for("dashboard"))
            flash("Invalid code. Try again.", "danger")

        if not current_user.otp_secret:
            current_user.generate_otp_secret()
            db.session.commit()

        totp = pyotp.TOTP(current_user.otp_secret)
        uri = totp.provisioning_uri(current_user.email, issuer_name="ProjectPop")
        qr = qrcode.make(uri)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
        return render_template("setup_2fa.html", qr_code=qr_b64, secret=current_user.otp_secret)

    @app.route("/dashboard")
    @login_required
    def dashboard():
        websites = Website.query.filter_by(user_id=current_user.id).order_by(Website.created_at.desc()).all()
        total_scans = Scan.query.filter_by(user_id=current_user.id).count()
        alerts = Alert.query.filter_by(user_id=current_user.id, read=False).count()
        blocked = BlockedIP.query.filter_by(is_active=True).count()
        recent_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).limit(5).all()
        stats = {
            "websites": len(websites),
            "scans": total_scans,
            "alerts": alerts,
            "blocked_ips": blocked,
            "avg_score": 0,
        }
        scores = [s.score for s in Scan.query.filter_by(user_id=current_user.id).all()]
        if scores:
            stats["avg_score"] = round(sum(scores) / len(scores))
        return render_template("dashboard.html", websites=websites, stats=stats, recent_scans=recent_scans)

    @app.route("/scanner", methods=["GET", "POST"])
    @login_required
    def scanner():
        result = None
        url_input = ""
        if request.method == "POST":
            url_input = request.form.get("url", "").strip()
            if url_input:
                if not url_input.startswith("http"):
                    url_input = "https://" + url_input
                parsed_url = url_input
                from urllib.parse import urlparse as _urlparse
                domain = _urlparse(url_input).hostname or url_input
                website = Website.query.filter_by(user_id=current_user.id, domain=domain).first()
                if not website:
                    website = Website(user_id=current_user.id, url=url_input, domain=domain, status="scanning")
                    db.session.add(website)
                    db.session.commit()

                scan_data = scan_website(url_input)
                scan = Scan(
                    website_id=website.id, user_id=current_user.id, url=url_input,
                    ssl_valid=scan_data["ssl_valid"], ssl_issuer=scan_data["ssl_issuer"],
                    ssl_expiry=scan_data["ssl_expiry"], ssl_protocol=scan_data["ssl_protocol"],
                    security_headers=json.dumps(scan_data["security_headers"]),
                    missing_headers=json.dumps(scan_data["missing_headers"]),
                    dns_resolved=scan_data["dns_resolved"],
                    dns_ips=json.dumps(scan_data["dns_ips"]),
                    open_ports=json.dumps(scan_data["open_ports"]),
                    server_header=scan_data["server_header"],
                    response_time=scan_data["response_time"],
                    status_code=scan_data["status_code"],
                    technologies=json.dumps(scan_data["technologies"]),
                    issues=json.dumps(scan_data["issues"]),
                    score=scan_data["score"],
                )
                db.session.add(scan)
                website.last_scan_id = scan.id
                website.status = "scanned"
                db.session.commit()
                result = scan
                log_action("scan", url_input, f"Score: {scan_data['score']}")
        return render_template("scanner.html", result=result, url_input=url_input)

    @app.route("/scan/<int:scan_id>")
    @login_required
    def scan_detail(scan_id):
        scan = Scan.query.get_or_404(scan_id)
        if scan.user_id != current_user.id and current_user.role != "admin":
            flash("Access denied", "danger")
            return redirect(url_for("dashboard"))
        return render_template("scan_detail.html", scan=scan)

    @app.route("/ip-blocker", methods=["GET", "POST"])
    @login_required
    def ip_blocker():
        net_info = get_network_info()
        if request.method == "POST":
            ip = request.form.get("ip", "").strip()
            reason = request.form.get("reason", "").strip()
            if ip:
                existing = BlockedIP.query.filter_by(ip_address=ip, is_active=True).first()
                if existing:
                    flash("IP already blocked", "warning")
                else:
                    fw_ok, fw_msg = block_ip_firewall(ip, reason)
                    block = BlockedIP(
                        ip_address=ip, reason=reason, blocked_by=current_user.id,
                        firewall_applied=fw_ok,
                    )
                    db.session.add(block)
                    db.session.commit()
                    log_action("ip_blocked", ip, reason)
                    if fw_ok:
                        flash(f"Blocked {ip} on network firewall", "success")
                    else:
                        flash(f"Added to blocklist. Firewall: {fw_msg}", "warning")
        blocked = BlockedIP.query.filter_by(is_active=True).order_by(BlockedIP.created_at.desc()).all()
        return render_template("ip_blocker.html", blocked_ips=blocked, net_info=net_info)

    @app.route("/unblock/<int:block_id>", methods=["POST"])
    @login_required
    def unblock(block_id):
        block = BlockedIP.query.get_or_404(block_id)
        fw_ok, fw_msg = unblock_ip_firewall(block.ip_address)
        block.is_active = False
        db.session.commit()
        log_action("ip_unblocked", block.ip_address)
        if fw_ok:
            flash(f"Unblocked {block.ip_address} from network firewall", "success")
        else:
            flash(f"Removed from blocklist. Firewall: {fw_msg}", "warning")
        return redirect(url_for("ip_blocker"))

    @app.route("/alerts")
    @login_required
    def alerts():
        all_alerts = Alert.query.filter_by(user_id=current_user.id).order_by(Alert.created_at.desc()).all()
        return render_template("alerts.html", alerts=all_alerts)

    @app.route("/alerts/read/<int:alert_id>", methods=["POST"])
    @login_required
    def mark_alert_read(alert_id):
        alert = Alert.query.get_or_404(alert_id)
        if alert.user_id == current_user.id:
            alert.read = True
            db.session.commit()
        return jsonify({"ok": True})

    @app.route("/reports")
    @login_required
    def reports():
        scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).all()
        return render_template("reports.html", scans=scans)

    @app.route("/admin")
    @login_required
    def admin_panel():
        if current_user.role != "admin":
            flash("Admin access required", "danger")
            return redirect(url_for("dashboard"))
        users = User.query.all()
        all_scans = Scan.query.order_by(Scan.created_at.desc()).limit(50).all()
        audit = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(50).all()
        blocked = BlockedIP.query.filter_by(is_active=True).all()
        all_websites = Website.query.all()
        all_scans_full = Scan.query.all()

        total_scans_count = len(all_scans_full)
        total_users_count = len(users)
        total_websites_count = len(all_websites)
        total_blocked = len(blocked)

        domain_stats = []
        for w in all_websites:
            w_scans = [s for s in all_scans_full if s.website_id == w.id]
            if w_scans:
                scores = [s.score for s in w_scans]
                avg = round(sum(scores) / len(scores))
            else:
                avg = 0
            domain_stats.append({
                "domain": w.domain,
                "url": w.url,
                "scan_count": len(w_scans),
                "avg_score": avg,
                "status": w.status,
                "user": w.user.name if w.user else "Unknown",
                "last_scan": w_scans[0].created_at if w_scans else None,
            })
        domain_stats.sort(key=lambda x: x["scan_count"], reverse=True)

        score_dist = {"excellent": 0, "good": 0, "fair": 0, "poor": 0, "critical": 0}
        for s in all_scans_full:
            if s.score >= 90: score_dist["excellent"] += 1
            elif s.score >= 75: score_dist["good"] += 1
            elif s.score >= 50: score_dist["fair"] += 1
            elif s.score >= 25: score_dist["poor"] += 1
            else: score_dist["critical"] += 1

        all_issues = []
        for s in all_scans_full:
            try:
                issues = json.loads(s.issues) if isinstance(s.issues, str) else (s.issues or [])
                for issue in issues:
                    all_issues.append(issue)
            except Exception:
                pass
        issue_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for i in all_issues:
            sev = i.get("severity", "low")
            if sev in issue_counts:
                issue_counts[sev] += 1

        user_stats = []
        for u in users:
            u_scans = [s for s in all_scans_full if s.user_id == u.id]
            u_websites = [w for w in all_websites if w.user_id == u.id]
            user_stats.append({
                "user": u,
                "scan_count": len(u_scans),
                "website_count": len(u_websites),
                "avg_score": round(sum(s.score for s in u_scans) / len(u_scans)) if u_scans else 0,
            })

        return render_template("admin.html",
            users=users, scans=all_scans, audit=audit, blocked=blocked,
            stats={"total_users": total_users_count, "total_scans": total_scans_count,
                   "total_websites": total_websites_count, "blocked_ips": total_blocked},
            domain_stats=domain_stats, score_dist=score_dist, issue_counts=issue_counts,
            user_stats=user_stats)

    @app.route("/admin/user/<int:user_id>/role", methods=["POST"])
    @login_required
    def change_role(user_id):
        if current_user.role != "admin":
            return jsonify({"error": "Forbidden"}), 403
        user = User.query.get_or_404(user_id)
        new_role = request.form.get("role", "user")
        if new_role in ("user", "admin"):
            user.role = new_role
            db.session.commit()
            log_action("role_changed", user.email, new_role)
            flash(f"Updated {user.name} to {new_role}", "success")
        return redirect(url_for("admin_panel"))

    @app.route("/config", methods=["GET", "POST"])
    @login_required
    def config_page():
        if request.method == "POST":
            flash("Settings saved", "success")
            return redirect(url_for("config_page"))
        return render_template("config.html")

    @app.route("/logout")
    @login_required
    def logout():
        log_action("logout")
        logout_user()
        return redirect(url_for("login"))

    @app.route("/api/scan", methods=["POST"])
    @login_required
    def api_scan():
        data = request.get_json() or {}
        url = data.get("url", "").strip()
        if not url:
            return jsonify({"error": "URL required"}), 400
        result = scan_website(url)
        return jsonify(result)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, host="0.0.0.0", port=5000)
