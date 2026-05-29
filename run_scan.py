# ============================================================
#  CloudScan – Command Line Entry Point
#  File: run_scan.py
#
#  Usage:
#    python run_scan.py <target_url> [depth]
#
#  Examples:
#    python run_scan.py http://localhost/dvwa
#    python run_scan.py http://testsite.com 2
# ============================================================

import sys
import os

def main():
    print('\n' + '='*60)
    print('  🔍 CloudScan — Web Application Vulnerability Scanner')
    print('  Final Year Cybersecurity Project')
    print('='*60)

    # ── Parse arguments ───────────────────────────────────────
    if len(sys.argv) < 2:
        print('\n  Usage:   python run_scan.py <target_url> [depth]')
        print('  Example: python run_scan.py http://localhost/dvwa 2')
        print('  Example: python run_scan.py http://httpbin.org 1\n')
        sys.exit(1)

    target_url = sys.argv[1]
    scan_depth = int(sys.argv[2]) if len(sys.argv) > 2 else 2

    # Basic URL validation
    if not target_url.startswith(('http://', 'https://')):
        print(f'\n  ❌ Invalid URL: {target_url}')
        print('  URL must start with http:// or https://')
        sys.exit(1)

    # Warn if scanning external sites
    if 'localhost' not in target_url and '127.0.0.1' not in target_url:
        print(f'\n  ⚠️  WARNING: You are about to scan: {target_url}')
        print('  Only scan websites you own or have written permission to test.')
        print('  Scanning without permission is illegal.\n')
        confirm = input('  Type YES to continue: ').strip()
        if confirm != 'YES':
            print('  Scan cancelled.')
            sys.exit(0)

    # ── Run the scan ──────────────────────────────────────────
    from scanner.main_scanner import MainScanner

    scanner = MainScanner()
    result  = scanner.scan(target_url, scan_depth=scan_depth)

    # ── Exit code based on findings ───────────────────────────
    # 0 = no vulnerabilities
    # 1 = vulnerabilities found
    # 2 = scan failed
    if not result['success']:
        sys.exit(2)
    elif result['stats']['total'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()