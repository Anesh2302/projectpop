import os
import time
import hmac
import hashlib
import struct
import base64
import json
import secrets
from datetime import datetime, timedelta

from .config import load_config
from .notifier import send_otp_email

OTP_SECRETS_FILE = os.path.expanduser("~/.projectpop/otp_secrets.json")


def _load_secrets():
    if os.path.exists(OTP_SECRETS_FILE):
        with open(OTP_SECRETS_FILE) as f:
            return json.load(f)
    return {}


def _save_secrets(data):
    os.makedirs(os.path.dirname(OTP_SECRETS_FILE), exist_ok=True)
    with open(OTP_SECRETS_FILE, "w") as f:
        json.dump(data, f, indent=2)


def generate_secret():
    return base64.b32encode(os.urandom(10)).decode()


def register_user(user_id, email):
    secrets = _load_secrets()
    secret = generate_secret()
    secrets[user_id] = {
        "secret": secret,
        "email": email,
        "created_at": datetime.now().isoformat(),
    }
    _save_secrets(secrets)
    return secret


def _hotp(secret, counter, digits=6):
    key = base64.b32decode(secret, casefold=True)
    counter_bytes = struct.pack(">Q", counter)
    h = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def _totp(secret, digits=6, interval=30):
    return _hotp(secret, int(time.time()) // interval, digits)


def generate_otp(user_id):
    cfg = load_config()
    digits = cfg.get("otp", {}).get("digits", 6)
    secrets = _load_secrets()
    if user_id not in secrets:
        return None

    secret = secrets[user_id]["secret"]
    code = _totp(secret, digits)
    email = secrets[user_id]["email"]
    send_otp_email(code, email)
    return code


def verify_otp(user_id, code):
    cfg = load_config()
    digits = cfg.get("otp", {}).get("digits", 6)
    window = 1

    secrets = _load_secrets()
    if user_id not in secrets:
        return False

    secret = secrets[user_id]["secret"]
    current = int(time.time()) // 30

    for i in range(-window, window + 1):
        expected = _hotp(secret, current + i, digits)
        if hmac.compare_digest(expected, code):
            return True
    return False
