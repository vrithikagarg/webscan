"""
scanner/checks/dirs.py — Sensitive file and directory enumeration
"""

import time
import requests
from requests.exceptions import RequestException

WORDLIST = [
    ".env", ".git/config", ".git/HEAD", ".htaccess", ".htpasswd",
    "wp-config.php", "config.php", "config.yml", "config.yaml",
    "database.yml", "settings.py", "secrets.py", "credentials.json",
    "admin/", "admin/login", "administrator/", "phpmyadmin/",
    "backup/", "backup.zip", "backup.tar.gz", "db.sql", "dump.sql",
    "api/v1/", "api/v2/", "swagger/", "swagger-ui.html", "openapi.json",
    "api-docs/", "graphql", "robots.txt", "sitemap.xml",
    "server-status", "server-info", ".DS_Store",
    "README.md", "CHANGELOG.md", "composer.json", "package.json",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "logs/", "log/", "error.log", "access.log",
    "uploads/", "files/", "static/", "assets/",
    "wp-admin/", "wp-login.php", "xmlrpc.php",
    "console", "debug", "metrics", "health", "status",
]

HIGH_VALUE = {".env", "wp-config.php", "config.php", ".git/config", ".htpasswd",
              "database.yml", "secrets.py", "credentials.json", "db.sql", "dump.sql"}


def check_dirs(target, timeout=10, delay=0.3, **kwargs):
    findings = []
    label = "Dirs"
    found_count = 0

    print(f"  [~] Dirs: probing {len(WORDLIST)} paths...")

    for path in WORDLIST:
        url = f"{target}/{path}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=False,
                                headers={"User-Agent": "WebScan/1.0"})

            if resp.status_code in (200, 301, 302, 403):
                is_high = any(hw in path for hw in HIGH_VALUE)
                severity = "HIGH" if is_high else ("MEDIUM" if resp.status_code == 200 else "LOW")

                status_label = {200: "accessible", 403: "forbidden (exists)", 301: "redirect", 302: "redirect"}
                findings.append({
                    "check": label,
                    "severity": severity,
                    "title": f"Exposed path ({resp.status_code}): /{path}",
                    "description": (
                        f"Sensitive path is {status_label.get(resp.status_code, 'reachable')}. "
                        f"{'High-value file — may contain credentials or secrets.' if is_high else ''}"
                    ),
                    "recommendation": (
                        "Remove or restrict access to sensitive files. "
                        "Use web server rules to block access to dotfiles, backups, and config files."
                    ),
                    "evidence": f"GET /{path} → HTTP {resp.status_code}"
                })
                found_count += 1
                print(f"  [!] Found ({resp.status_code}): /{path}")

            time.sleep(delay)
        except RequestException:
            pass

    if found_count == 0:
        findings.append({
            "check": label,
            "severity": "PASS",
            "title": "No sensitive paths found",
            "description": f"None of the {len(WORDLIST)} probed paths returned a positive response.",
            "recommendation": "",
            "evidence": f"Probed {len(WORDLIST)} paths"
        })

    return findings
