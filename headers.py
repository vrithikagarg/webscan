"""
scanner/checks/headers.py — Security header analysis
"""

import requests
from requests.exceptions import RequestException

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "HSTS missing. Browser connections can be downgraded to HTTP.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "CSP missing. XSS and data injection attacks are not mitigated.",
        "recommendation": "Define a CSP policy appropriate for your application."
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "X-Frame-Options missing. Page may be embeddable (clickjacking risk).",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "X-Content-Type-Options missing. MIME sniffing attacks possible.",
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Referrer-Policy missing. Sensitive URLs may leak via Referer header.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Permissions-Policy missing. Browser features (camera, mic) are unrestricted.",
        "recommendation": "Add a Permissions-Policy header to restrict unused browser features."
    },
}

UNSAFE_HEADERS = {
    "Server": {
        "severity": "INFO",
        "description": "Server header exposes web server software and version.",
        "recommendation": "Suppress or genericize the Server header in your web server config."
    },
    "X-Powered-By": {
        "severity": "INFO",
        "description": "X-Powered-By header exposes backend technology stack.",
        "recommendation": "Remove X-Powered-By from response headers."
    },
    "X-AspNet-Version": {
        "severity": "INFO",
        "description": "X-AspNet-Version exposes ASP.NET framework version.",
        "recommendation": "Disable in web.config: <httpRuntime enableVersionHeader='false'/>"
    },
}


def check_headers(target, timeout=10, **kwargs):
    findings = []
    label = "Headers"

    try:
        resp = requests.get(target, timeout=timeout, allow_redirects=True,
                            headers={"User-Agent": "WebScan/1.0"})
        headers = {k.lower(): v for k, v in resp.headers.items()}

        print(f"  [~] {label}: checking {len(SECURITY_HEADERS)} required headers...")

        for header, meta in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                findings.append({
                    "check": label,
                    "severity": meta["severity"],
                    "title": f"Missing header: {header}",
                    "description": meta["description"],
                    "recommendation": meta["recommendation"],
                    "evidence": f"Header '{header}' not present in response"
                })
                print(f"  [{_sev_char(meta['severity'])}] MISSING: {header}")
            else:
                findings.append({
                    "check": label,
                    "severity": "PASS",
                    "title": f"Present: {header}",
                    "description": f"Header is present with value: {headers[header.lower()]}",
                    "recommendation": "",
                    "evidence": f"{header}: {headers[header.lower()]}"
                })

        for header, meta in UNSAFE_HEADERS.items():
            if header.lower() in headers:
                findings.append({
                    "check": label,
                    "severity": meta["severity"],
                    "title": f"Information disclosure: {header}",
                    "description": meta["description"],
                    "recommendation": meta["recommendation"],
                    "evidence": f"{header}: {headers[header.lower()]}"
                })
                print(f"  [i] DISCLOSURE: {header}: {headers[header.lower()]}")

    except RequestException as e:
        findings.append({
            "check": label,
            "severity": "INFO",
            "title": "Request failed",
            "description": str(e),
            "recommendation": "Verify the target URL is accessible.",
            "evidence": str(e)
        })

    return findings


def _sev_char(sev):
    return {"CRITICAL": "!", "HIGH": "!", "MEDIUM": "-", "LOW": "?", "INFO": "i"}.get(sev, "?")
