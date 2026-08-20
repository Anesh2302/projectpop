import socket
import ssl
import json
import time
import urllib.request
import urllib.error
from datetime import datetime
from urllib.parse import urlparse


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

COMMON_PORTS = [80, 443, 21, 22, 25, 53, 8080, 8443, 3306, 5432, 6379, 27017]


def scan_website(url, scan_type="full"):
    result = {
        "ssl_valid": False, "ssl_issuer": "", "ssl_expiry": "", "ssl_protocol": "",
        "security_headers": {}, "missing_headers": [], "dns_resolved": False,
        "dns_ips": [], "open_ports": [], "server_header": "", "response_time": 0,
        "status_code": 0, "technologies": [], "issues": [], "score": 0,
    }

    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.hostname or ""
    scheme = parsed.scheme

    # DNS
    try:
        ips = socket.getaddrinfo(domain, None)
        result["dns_resolved"] = True
        result["dns_ips"] = list(set(addr[4][0] for addr in ips))
    except Exception:
        result["issues"].append({"severity": "high", "message": f"DNS resolution failed for {domain}"})

    # SSL
    if scheme == "https":
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(10)
                s.connect((domain, 443))
                cert = s.getpeercert()
                result["ssl_valid"] = True
                issuer_parts = dict(x[0] for x in cert.get("issuer", []))
                result["ssl_issuer"] = issuer_parts.get("organizationName", "Unknown")
                not_after = cert.get("notAfter", "")
                if not_after:
                    result["ssl_expiry"] = not_after
                    try:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp - datetime.utcnow()).days
                        if days_left < 30:
                            result["issues"].append({
                                "severity": "critical" if days_left < 7 else "high",
                                "message": f"SSL certificate expires in {days_left} days"
                            })
                    except Exception:
                        pass
                proto = s.version()
                result["ssl_protocol"] = proto or ""
                if proto and "TLSv1.0" in proto or "TLSv1.1" in proto or "SSLv" in proto:
                    result["issues"].append({"severity": "high", "message": f"Outdated TLS protocol: {proto}"})
        except Exception as e:
            result["issues"].append({"severity": "critical", "message": f"SSL connection failed: {str(e)[:100]}"})
    else:
        result["issues"].append({"severity": "high", "message": "Site not using HTTPS"})

    # HTTP Headers
    start = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ProjectPop-SecurityScanner/1.0"})
        resp = urllib.request.urlopen(req, timeout=15)
        result["response_time"] = round((time.time() - start) * 1000)
        result["status_code"] = resp.status
        headers = dict(resp.headers)
        result["server_header"] = headers.get("Server", "")

        for hdr in SECURITY_HEADERS:
            if hdr.lower() in {k.lower() for k in headers}:
                result["security_headers"][hdr] = headers.get(hdr, headers.get(hdr.lower(), ""))
            else:
                result["missing_headers"].append(hdr)

        if result["missing_headers"]:
            result["issues"].append({
                "severity": "medium",
                "message": f"Missing security headers: {', '.join(result['missing_headers'][:5])}"
            })

        server = result["server_header"].lower()
        if "apache" in server:
            result["technologies"].append("Apache")
        elif "nginx" in server:
            result["technologies"].append("Nginx")
        elif "cloudflare" in server:
            result["technologies"].append("Cloudflare")
        elif "iis" in server:
            result["technologies"].append("IIS")

        content_type = headers.get("Content-Type", "")
        if "text/html" in content_type:
            result["technologies"].append("HTML")
        if "application/json" in content_type:
            result["technologies"].append("JSON API")

        body = resp.read(50000).decode("utf-8", errors="ignore")
        tech_signs = {
            "WordPress": ["wp-content", "wp-includes"],
            "React": ["react", "__NEXT_DATA__"],
            "Vue.js": ["vue", "__vue__"],
            "Angular": ["ng-version", "angular"],
            "Bootstrap": ["bootstrap.min"],
            "jQuery": ["jquery"],
            "Google Analytics": ["google-analytics", "gtag"],
            "Vercel": ["vercel", "_vercel"],
            "Netlify": ["netlify"],
            "PHP": [".php"],
            "Laravel": ["laravel"],
            "Django": ["csrfmiddlewaretoken"],
            "Flask": ["flask"],
            "Express": ["express"],
        }
        for tech, signs in tech_signs.items():
            if any(s in body.lower() for s in signs):
                result["technologies"].append(tech)

        if "x-frame-options" not in {k.lower() for k in headers}:
            if "frame" in body.lower() or "iframe" in body.lower():
                result["issues"].append({"severity": "medium", "message": "Frames detected without X-Frame-Options"})

        csp = ""
        for k, v in headers.items():
            if k.lower() == "content-security-policy":
                csp = v
                break
        if csp:
            if "unsafe-inline" in csp:
                result["issues"].append({"severity": "medium", "message": "CSP allows unsafe-inline"})
            if "unsafe-eval" in csp:
                result["issues"].append({"severity": "high", "message": "CSP allows unsafe-eval"})

        if result["response_time"] > 3000:
            result["issues"].append({"severity": "low", "message": f"Slow response time: {result['response_time']}ms"})

    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["response_time"] = round((time.time() - start) * 1000)
        result["issues"].append({"severity": "medium", "message": f"HTTP {e.code} error"})
    except Exception as e:
        result["response_time"] = round((time.time() - start) * 1000)
        result["issues"].append({"severity": "critical", "message": f"Connection failed: {str(e)[:100]}"})

    # Port scan
    if scan_type == "full" and result["dns_ips"]:
        target_ip = result["dns_ips"][0]
        for port in COMMON_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex((target_ip, port)) == 0:
                    result["open_ports"].append(port)
                    if port in [21, 25, 3306, 5432, 6379, 27017]:
                        result["issues"].append({
                            "severity": "high",
                            "message": f"Sensitive port {port} is open ({_port_name(port)})"
                        })
                s.close()
            except Exception:
                pass

    # Score
    score = 100
    for issue in result["issues"]:
        sev = issue.get("severity", "low")
        if sev == "critical":
            score -= 25
        elif sev == "high":
            score -= 15
        elif sev == "medium":
            score -= 8
        elif sev == "low":
            score -= 3
    result["score"] = max(0, min(100, score))

    return result


def _port_name(port):
    names = {21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
             443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
             8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"}
    return names.get(port, "Unknown")
