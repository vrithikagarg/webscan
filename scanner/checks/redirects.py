"""
scanner/checks/redirects.py — Open redirect probing
"""

import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from requests.exceptions import RequestException

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "https:evil.com",
    "/\\evil.com",
    "//evil.com/%2F..",
    "https://evil.com?",
    "%09//evil.com",
    "%0d%0aLocation: https://evil.com",
]

REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirect_url", "url", "next", "return",
    "returnUrl", "return_url", "goto", "go", "destination", "dest",
    "forward", "location", "redir", "back", "continue", "target",
    "link", "out", "exit", "ref", "referer", "referrer", "site",
    "from", "callback", "success", "failure",
]


def check_redirects(target, timeout=10, delay=0.3, **kwargs):
    findings = []
    label = "Redirects"
    parsed = urlparse(target)
    existing_params = parse_qs(parsed.query, keep_blank_values=True)
    tested = set()
    found = 0

    all_params = list(existing_params.keys()) + REDIRECT_PARAMS

    print(f"  [~] Redirects: testing {len(all_params)} param candidates...")

    for param in all_params:
        if param in tested:
            continue
        tested.add(param)

        for payload in REDIRECT_PAYLOADS:
            test_params = dict(existing_params)
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = requests.get(test_url, timeout=timeout, allow_redirects=False,
                                    headers={"User-Agent": "WebScan/1.0"})

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location or location.startswith("//"):
                        if param not in {f["evidence"].split("'")[1] for f in findings if "param" in f.get("evidence", "")}:
                            findings.append({
                                "check": label,
                                "severity": "MEDIUM",
                                "title": f"Open redirect via parameter '{param}'",
                                "description": (
                                    f"Server redirected to attacker-controlled domain. "
                                    f"Can be used in phishing attacks."
                                ),
                                "recommendation": (
                                    "Validate redirect destinations against an allowlist of known-good domains. "
                                    "Never redirect to user-supplied arbitrary URLs."
                                ),
                                "evidence": f"param='{param}' payload={payload!r} → Location: {location}"
                            })
                            found += 1
                            print(f"  [!] Open redirect: param='{param}' → {location}")
                        break

                time.sleep(delay)
            except RequestException:
                pass

    if found == 0:
        findings.append({
            "check": label,
            "severity": "PASS",
            "title": "No open redirects detected",
            "description": "Redirect payloads did not produce external redirections.",
            "recommendation": "",
            "evidence": f"Tested {len(tested)} param(s)"
        })

    return findings
