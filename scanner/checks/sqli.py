"""
scanner/checks/sqli.py — SQL injection probing
Sends payloads to URL query parameters and checks for error signatures.
"""

import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from requests.exceptions import RequestException

SQLI_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "\\",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1 UNION SELECT NULL--",
    "' AND SLEEP(2)--",
    "'; WAITFOR DELAY '0:0:2'--",
]

DB_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error",
    "ora-",
    "pg::syntaxerror",
    "sqlite3::exception",
    "sqlstate",
    "microsoft ole db provider for odbc drivers",
    "odbc sql server driver",
    "jdbc driver",
    "[mysql]",
    "supplied argument is not a valid mysql",
    "invalid query",
]


def check_sqli(target, timeout=10, delay=0.3, **kwargs):
    findings = []
    label = "SQLi"
    parsed = urlparse(target)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        findings.append({
            "check": label,
            "severity": "INFO",
            "title": "No query parameters found",
            "description": "No URL query parameters detected to test for SQL injection.",
            "recommendation": "Test forms and POST endpoints manually or provide a URL with parameters.",
            "evidence": target
        })
        print(f"  [i] SQLi: no query params found in URL")
        return findings

    print(f"  [~] SQLi: testing {len(params)} param(s) with {len(SQLI_PAYLOADS)} payloads...")
    tested = set()

    for param in params:
        for payload in SQLI_PAYLOADS:
            test_params = dict(params)
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = requests.get(test_url, timeout=timeout,
                                    headers={"User-Agent": "WebScan/1.0"})
                body_lower = resp.text.lower()
                for sig in DB_ERROR_SIGNATURES:
                    if sig in body_lower and (param, sig) not in tested:
                        tested.add((param, sig))
                        findings.append({
                            "check": label,
                            "severity": "HIGH",
                            "title": f"Possible SQL injection in parameter '{param}'",
                            "description": f"DB error signature detected: '{sig}'",
                            "recommendation": (
                                "Use parameterized queries / prepared statements. "
                                "Never interpolate user input into SQL strings."
                            ),
                            "evidence": f"Payload: {payload!r} → matched: '{sig}'"
                        })
                        print(f"  [!] SQLi candidate: param='{param}' payload={payload!r}")
                        break
                time.sleep(delay)
            except RequestException:
                pass

    if not any(f["severity"] in ("HIGH", "CRITICAL") for f in findings):
        findings.append({
            "check": label,
            "severity": "PASS",
            "title": "No SQL injection signatures detected",
            "description": "Error-based SQLi probes returned no known DB error strings.",
            "recommendation": "",
            "evidence": f"Tested {len(params)} param(s)"
        })

    return findings
