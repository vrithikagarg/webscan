"""
scanner/checks/xss.py — Reflected XSS probing
Injects payloads into query parameters and checks if they are reflected unescaped.
"""

import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from requests.exceptions import RequestException

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    '"><img src=x onerror=alert(1)>',
    "<body onload=alert(1)>",
    '\'"><iframe src="javascript:alert(1)">',
    "<script>alert(String.fromCharCode(88,83,83))</script>",
]


def check_xss(target, timeout=10, delay=0.3, **kwargs):
    findings = []
    label = "XSS"
    parsed = urlparse(target)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        findings.append({
            "check": label,
            "severity": "INFO",
            "title": "No query parameters found",
            "description": "No URL query parameters detected to test for reflected XSS.",
            "recommendation": "Test POST endpoints and forms manually.",
            "evidence": target
        })
        print(f"  [i] XSS: no query params found in URL")
        return findings

    print(f"  [~] XSS: testing {len(params)} param(s) with {len(XSS_PAYLOADS)} payloads...")
    reported = set()

    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = dict(params)
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = requests.get(test_url, timeout=timeout,
                                    headers={"User-Agent": "WebScan/1.0"})
                # Check for unescaped payload reflection
                if payload in resp.text and param not in reported:
                    reported.add(param)
                    findings.append({
                        "check": label,
                        "severity": "HIGH",
                        "title": f"Reflected XSS candidate in parameter '{param}'",
                        "description": (
                            f"Payload was reflected unescaped in the response body."
                        ),
                        "recommendation": (
                            "HTML-encode all user-supplied output. "
                            "Use a Content-Security-Policy to reduce exploitability."
                        ),
                        "evidence": f"Payload: {payload!r} reflected in response"
                    })
                    print(f"  [!] XSS candidate: param='{param}' payload={payload!r}")
                time.sleep(delay)
            except RequestException:
                pass

    if not any(f["severity"] in ("HIGH", "CRITICAL") for f in findings):
        findings.append({
            "check": label,
            "severity": "PASS",
            "title": "No reflected XSS detected",
            "description": "Payloads were not reflected unescaped in any tested parameter.",
            "recommendation": "",
            "evidence": f"Tested {len(params)} param(s)"
        })

    return findings
