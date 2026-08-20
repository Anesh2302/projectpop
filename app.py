from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Website, Scan, BlockedIP, Alert, AuditLog
from scanner import scan_website
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
        if request.method == "POST":
            ip = request.form.get("ip", "").strip()
            reason = request.form.get("reason", "").strip()
            if ip:
                existing = BlockedIP.query.filter_by(ip_address=ip, is_active=True).first()
                if existing:
                    flash("IP already blocked", "warning")
                else:
                    block = BlockedIP(ip_address=ip, reason=reason, blocked_by=current_user.id)
                    db.session.add(block)
                    db.session.commit()
                    log_action("ip_blocked", ip, reason)
                    flash(f"Blocked {ip}", "success")
        blocked = BlockedIP.query.filter_by(is_active=True).order_by(BlockedIP.created_at.desc()).all()
        return render_template("ip_blocker.html", blocked_ips=blocked)

    @app.route("/unblock/<int:block_id>", methods=["POST"])
    @login_required
    def unblock(block_id):
        block = BlockedIP.query.get_or_404(block_id)
        block.is_active = False
        db.session.commit()
        log_action("ip_unblocked", block.ip_address)
        flash(f"Unblocked {block.ip_address}", "success")
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
        all_scans = Scan.query.order_by(Scan.created_at.desc()).limit(20).all()
        audit = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(30).all()
        blocked = BlockedIP.query.filter_by(is_active=True).all()
        stats = {
            "total_users": len(users),
            "total_scans": Scan.query.count(),
            "total_websites": Website.query.count(),
            "blocked_ips": len(blocked),
        }
        return render_template("admin.html", users=users, scans=all_scans, audit=audit, stats=stats)

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
