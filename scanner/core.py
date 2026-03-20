"""
scanner/core.py — Orchestrates all scan modules
"""

import threading
import queue
from scanner.checks.headers import check_headers
from scanner.checks.sqli import check_sqli
from scanner.checks.xss import check_xss
from scanner.checks.dirs import check_dirs
from scanner.checks.redirects import check_redirects


CHECK_MAP = {
    "headers": check_headers,
    "sqli": check_sqli,
    "xss": check_xss,
    "dirs": check_dirs,
    "redirects": check_redirects,
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "PASS": 5}


class Scanner:
    def __init__(self, target, checks, timeout=10, delay=0.3, threads=5, verbose=False):
        self.target = target.rstrip("/")
        self.checks = checks
        self.timeout = timeout
        self.delay = delay
        self.threads = threads
        self.verbose = verbose
        self.results = []
        self._lock = threading.Lock()

    def _run_check(self, name):
        fn = CHECK_MAP.get(name)
        if not fn:
            return
        findings = fn(self.target, timeout=self.timeout, delay=self.delay)
        with self._lock:
            self.results.extend(findings)

    def run(self):
        threads = []
        for check in self.checks:
            t = threading.Thread(target=self._run_check, args=(check,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.results.sort(key=lambda r: SEVERITY_ORDER.get(r.get("severity", "INFO"), 99))
        return self.results
