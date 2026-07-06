import os
import re
import json
import hashlib
from datetime import datetime


def scan_project(project_path):
    results = {
        "project": os.path.basename(project_path),
        "path": project_path,
        "scanned_at": datetime.now().isoformat(),
        "summary": {},
        "issues": [],
        "files": [],
    }

    if not os.path.isdir(project_path):
        results["error"] = "Path does not exist"
        return results

    total_files = 0
    total_lines = 0
    extensions = {}
    secrets_found = []
    large_files = []
    old_files = []

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if not d.startswith((".", "node_modules", "venv", "__pycache__", ".git"))]

        for f in files:
            fpath = os.path.join(root, f)
            ext = os.path.splitext(f)[1] or "(no ext)"
            extensions[ext] = extensions.get(ext, 0) + 1
            total_files += 1

            try:
                size = os.path.getsize(fpath)
                mtime = os.path.getmtime(fpath)

                if size > 500 * 1024:
                    large_files.append({"file": fpath, "size_kb": round(size / 1024)})

                age_days = (datetime.now() - datetime.fromtimestamp(mtime)).days
                if age_days > 365:
                    old_files.append({"file": fpath, "days_since_modified": age_days})

                if size < 500 * 1024:
                    with open(fpath, errors="ignore") as fh:
                        content = fh.read()
                        total_lines += content.count("\n") + 1

                        bad_patterns = [
                            (r'(?i)(password\s*[:=]\s*["\'].+?["\'])', "Hardcoded password"),
                            (r'(?i)(api[_-]?key\s*[:=]\s*["\'].+?["\'])', "API key"),
                            (r'(?i)(secret\s*[:=]\s*["\'].+?["\'])', "Hardcoded secret"),
                            (r'(?i)(token\s*[:=]\s*["\'].+?["\'])', "Hardcoded token"),
                            (r'(?i)(sk-[A-Za-z0-9]{20,})', "OpenAI API key"),
                            (r'(?i)(ghp_[A-Za-z0-9]{36,})', "GitHub token"),
                            (r'(?i)(-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----)', "Private key"),
                        ]
                        for pattern, label in bad_patterns:
                            if re.search(pattern, content):
                                secrets_found.append({"file": fpath, "type": label})

            except (OSError, UnicodeDecodeError):
                pass

    results["summary"] = {
        "total_files": total_files,
        "total_lines": total_lines,
        "file_types": extensions,
        "age_days": None,
    }

    if secrets_found:
        results["issues"].append({
            "severity": "high",
            "type": "secrets_exposed",
            "count": len(secrets_found),
            "details": secrets_found[:20],
        })

    if large_files:
        results["issues"].append({
            "severity": "info",
            "type": "large_files",
            "count": len(large_files),
            "details": large_files[:10],
        })

    if old_files:
        results["issues"].append({
            "severity": "info",
            "type": "unmodified_files",
            "count": len(old_files),
            "details": old_files[:10],
        })

    return results


def scan_all_projects(paths):
    results = {}
    for p in paths:
        if os.path.isdir(p):
            results[os.path.basename(p)] = scan_project(p)
    return results


def generate_report_text(scan_result):
    lines = []
    lines.append(f"Project: {scan_result['project']}")
    lines.append(f"Path: {scan_result['path']}")
    lines.append(f"Scanned: {scan_result['scanned_at']}")
    lines.append(f"Files: {scan_result['summary']['total_files']}")
    lines.append(f"Lines: {scan_result['summary']['total_lines']}")
    lines.append("")

    if scan_result["issues"]:
        lines.append("Issues Found:")
        lines.append("-" * 40)
        for issue in scan_result["issues"]:
            sev = issue["severity"].upper()
            lines.append(f"[{sev}] {issue['type']} ({issue['count']} occurrences)")
            for d in issue["details"][:5]:
                lines.append(f"  - {d}")
        lines.append("")
    else:
        lines.append("No issues found. Project looks clean.")

    return "\n".join(lines)
