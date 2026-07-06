import json
import os
import getpass

CONFIG_DIR = os.path.expanduser("~/.projectpop")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

DEFAULT_CONFIG = {
    "user": {
        "name": "Simon Peter Chappell",
        "email": "simonpetercys@gmail.com",
    },
    "smtp": {
        "server": "smtp.gmail.com",
        "port": 587,
        "username": "simonpetercys@gmail.com",
        "password": "",
    },
    "github": {
        "username": "simonpeter",
        "token": "",
    },
    "monitor": {
        "log_paths": [],
        "watch_interval": 5,
        "max_failures": 5,
        "block_duration_hours": 24,
        "whitelist_ips": [],
    },
    "otp": {
        "enabled": True,
        "digits": 6,
        "expiry_seconds": 300,
    },
    "notifications": {
        "on_breach": True,
        "on_login": True,
        "on_project_change": True,
        "daily_summary": True,
    },
    "scan": {
        "project_paths": [os.path.abspath("D:\\simonpeter\\talentos")],
        "check_secrets": True,
        "check_dependencies": True,
        "check_git": True,
    },
}


def ensure_config():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)


def load_config():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
    with open(CONFIG_FILE) as f:
        return json.load(f)


def save_config(cfg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def set_smtp_password():
    cfg = load_config()
    cfg["smtp"]["password"] = getpass.getpass("SMTP password: ")
    save_config(cfg)
    print("SMTP password saved securely.")


def set_github_token():
    cfg = load_config()
    cfg["github"]["token"] = getpass.getpass("GitHub personal access token: ")
    save_config(cfg)
    print("GitHub token saved securely.")
