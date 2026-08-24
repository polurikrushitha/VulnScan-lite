"""
VulnScan Lite — Local Scanner CLI Runner

Run passive security scans from the terminal without requiring database or web server setup.

Usage:
    python -m scanner.cli https://example.com
    python run_scanner_test.py https://example.com
"""
import json
import sys
from scanner.engine import run_scan


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python -m scanner.cli <target_url>")
        print("Example: python -m scanner.cli https://example.com")
        sys.exit(1)

    target_url = sys.argv[1]
    print(f"[*] Starting VulnScan Lite passive scan for: {target_url}\n")

    result = run_scan(target_url)
    result_dict = result.to_dict()

    print(json.dumps(result_dict, indent=2))

    if not result.scan_successful:
        print(f"\n[!] Scan failed: {result.error_type} - {result.error}")
        sys.exit(2)
    else:
        print(f"\n[+] Scan completed successfully!")
        print(f"[+] Final Score: {result.score}/100 (Grade: {result.grade})")
        print(f"[+] Security Checks: {len(result.security_checks)}")
        print(f"[+] Findings: {len(result.findings)}")


if __name__ == "__main__":
    main()
