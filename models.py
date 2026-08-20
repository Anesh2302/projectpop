from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default="user")
    otp_secret = db.Column(db.String(32), default="")
    otp_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_otp_secret(self):
        self.otp_secret = pyotp.random_base32()
        self.otp_enabled = True
        return self.otp_secret

    def verify_otp(self, token):
        if not self.otp_secret:
            return False
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(token, valid_window=1)


class Website(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    domain = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="pending")
    last_scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="websites")
    scans = db.relationship("Scan", backref="website", lazy="dynamic", foreign_keys="[Scan.website_id]")


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey("website.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    ssl_valid = db.Column(db.Boolean, default=False)
    ssl_issuer = db.Column(db.String(200), default="")
    ssl_expiry = db.Column(db.String(50), default="")
    ssl_protocol = db.Column(db.String(50), default="")
    security_headers = db.Column(db.Text, default="{}")
    missing_headers = db.Column(db.Text, default="[]")
    dns_resolved = db.Column(db.Boolean, default=False)
    dns_ips = db.Column(db.Text, default="[]")
    open_ports = db.Column(db.Text, default="[]")
    server_header = db.Column(db.String(200), default="")
    response_time = db.Column(db.Float, default=0.0)
    status_code = db.Column(db.Integer, default=0)
    technologies = db.Column(db.Text, default="[]")
    issues = db.Column(db.Text, default="[]")
    score = db.Column(db.Integer, default=0)
    scan_type = db.Column(db.String(20), default="full")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="scans")


class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, unique=True)
    reason = db.Column(db.String(500), default="")
    blocked_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    firewall_applied = db.Column(db.Boolean, default=False)

    blocker = db.relationship("User", backref="blocked_ips")


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    website_id = db.Column(db.Integer, db.ForeignKey("website.id"), nullable=True)
    alert_type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default="info")
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="alerts")
    website = db.relationship("Website", backref="alerts")


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    target = db.Column(db.String(200), default="")
    details = db.Column(db.Text, default="")
    ip_address = db.Column(db.String(45), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="audit_logs")
