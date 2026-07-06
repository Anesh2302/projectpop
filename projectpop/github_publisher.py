import os
import subprocess
import json
import urllib.request
import urllib.error
import base64
from .config import load_config


def create_github_repo(repo_name, description="", private=False):
    cfg = load_config()
    token = cfg.get("github", {}).get("token")
    username = cfg.get("github", {}).get("username")

    if not token:
        print("GitHub token not configured. Run: projectpop config github-token")
        return None

    url = "https://api.github.com/user/repos"
    data = json.dumps({
        "name": repo_name,
        "description": description,
        "private": private,
        "auto_init": False,
    }).encode()

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")

    try:
        resp = urllib.request.urlopen(req)
        result = json.loads(resp.read())
        clone_url = result["clone_url"]
        print(f"Repository created: {clone_url}")
        return clone_url
    except urllib.error.HTTPError as e:
        print(f"GitHub API error: {e.code} - {e.read().decode()}")
        return None


def push_local_project(local_path, repo_name, commit_message="Initial commit via projectpop"):
    cfg = load_config()
    token = cfg.get("github", {}).get("token")
    username = cfg.get("github", {}).get("username")

    if not token or not username:
        print("GitHub not configured. Run: projectpop config github-token")
        return False

    repo_url = create_github_repo(repo_name, f"Auto-published from {local_path}")
    if not repo_url:
        return False

    authed_url = repo_url.replace("https://", f"https://{username}:{token}@")

    try:
        subprocess.run(["git", "init"], cwd=local_path, capture_output=True, check=True)
        subprocess.run(["git", "add", "-A"], cwd=local_path, capture_output=True, check=True)
        subprocess.run(
            ["git", "commit", "-m", commit_message],
            cwd=local_path, capture_output=True,
        )
        subprocess.run(
            ["git", "remote", "add", "origin", authed_url],
            cwd=local_path, capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "branch", "-M", "main"],
            cwd=local_path, capture_output=True, check=True,
        )
        result = subprocess.run(
            ["git", "push", "-u", "origin", "main"],
            cwd=local_path, capture_output=True, text=True,
        )
        if result.returncode == 0:
            print(f"Successfully pushed to {repo_url}")
            return True
        else:
            print(f"Push failed: {result.stderr}")
            return False

    except subprocess.CalledProcessError as e:
        print(f"Git error: {e}")
        return False
