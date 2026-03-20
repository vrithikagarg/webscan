#!/usr/bin/env python3
"""
WebScan - Web Vulnerability Scanner
Author: Your Name
Description: CLI tool to scan web targets for common vulnerabilities.
             For authorized use only. Never scan targets you don't own or have permission to test.
"""

import argparse
import sys
import time
from scanner.core import Scanner
from scanner.report import generate_report


def banner():
    print(r"""
  _    _     _     ___   ___   ___   ___  _  _
 | |  | |   /_\   / __| / __| / __| / _ \| \| |
 | |__| |__/ _ \  \__ \| (__ | (__ | (_) | .` |
 |____|____/_/ \_\ |___/ \___| \___| \___/|_|\_|

  Web Vulnerability Scanner | Use Responsibly
""")


def main():
    banner()
    parser = argparse.ArgumentParser(
        description="WebScan - Web Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", help="Target URL (e.g. https://example.com)")
    parser.add_argument(
        "--checks",
        nargs="+",
        choices=["headers", "sqli", "xss", "dirs", "redirects", "all"],
        default=["all"],
        help=(
            "Which checks to run:\n"
            "  headers   - Missing/misconfigured security headers\n"
            "  sqli      - SQL injection probes\n"
            "  xss       - Reflected XSS probes\n"
            "  dirs      - Common sensitive directory/file enumeration\n"
            "  redirects - Open redirect probes\n"
            "  all       - Run everything (default)\n"
        )
    )
    parser.add_argument("--output", choices=["terminal", "json", "html"], default="terminal",
                        help="Output format (default: terminal)")
    parser.add_argument("--outfile", default=None,
                        help="Save report to file (e.g. report.json or report.html)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--delay", type=float, default=0.3,
                        help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("--threads", type=int, default=5,
                        help="Number of concurrent threads (default: 5)")
    parser.add_argument("--verbose", action="store_true",
                        help="Show detailed output including passing checks")

    args = parser.parse_args()

    checks = args.checks
    if "all" in checks:
        checks = ["headers", "sqli", "xss", "dirs", "redirects"]

    print(f"  [*] Target  : {args.target}")
    print(f"  [*] Checks  : {', '.join(checks)}")
    print(f"  [*] Output  : {args.output}")
    print(f"  [*] Threads : {args.threads}")
    print()

    scanner = Scanner(
        target=args.target,
        checks=checks,
        timeout=args.timeout,
        delay=args.delay,
        threads=args.threads,
        verbose=args.verbose
    )

    start = time.time()
    results = scanner.run()
    elapsed = round(time.time() - start, 2)

    generate_report(results, args.output, args.outfile, elapsed, args.target, args.verbose)


if __name__ == "__main__":
    main()
