# ============================================================
#  CloudScan – Security Headers Checker
#  File: scanner/header_checker.py
#
#  Checks HTTP response headers for security misconfigurations.
#  Missing security headers are a common OWASP finding.
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorama import Fore, Style, init
from scanner.http_engine import HTTPEngine

init(autoreset=True)


class HeaderChecker:

    # ── Security headers to check ─────────────────────────────
    # Format: header_name: {details}
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity'      : 'high',
            'description'   : (
                'HTTP Strict Transport Security (HSTS) is missing. '
                'This header forces browsers to use HTTPS only, '
                'preventing protocol downgrade attacks and cookie hijacking.'
            ),
            'recommendation': (
                'Add header: Strict-Transport-Security: '
                'max-age=31536000; includeSubDomains; preload'
            ),
            'cvss'          : 7.4,
            'owasp'         : 'A02:2021 - Cryptographic Failures',
        },
        'Content-Security-Policy': {
            'severity'      : 'high',
            'description'   : (
                'Content Security Policy (CSP) is missing. '
                'CSP prevents XSS attacks by controlling which '
                'resources the browser is allowed to load.'
            ),
            'recommendation': (
                "Add header: Content-Security-Policy: "
                "default-src 'self'; script-src 'self'; style-src 'self'"
            ),
            'cvss'          : 6.9,
            'owasp'         : 'A05:2021 - Security Misconfiguration',
        },
        'X-Frame-Options': {
            'severity'      : 'medium',
            'description'   : (
                'X-Frame-Options header is missing. '
                'Without this header, the page can be embedded in an '
                'iframe on a malicious site, enabling Clickjacking attacks.'
            ),
            'recommendation': 'Add header: X-Frame-Options: DENY',
            'cvss'          : 6.1,
            'owasp'         : 'A05:2021 - Security Misconfiguration',
        },
        'X-Content-Type-Options': {
            'severity'      : 'medium',
            'description'   : (
                'X-Content-Type-Options header is missing. '
                'Without this, browsers may MIME-sniff responses '
                'and execute files as a different content type.'
            ),
            'recommendation': 'Add header: X-Content-Type-Options: nosniff',
            'cvss'          : 5.3,
            'owasp'         : 'A05:2021 - Security Misconfiguration',
        },
        'Referrer-Policy': {
            'severity'      : 'low',
            'description'   : (
                'Referrer-Policy header is missing. '
                'Without it, the full URL including sensitive parameters '
                'may be leaked to third-party sites via the Referer header.'
            ),
            'recommendation': 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
            'cvss'          : 3.7,
            'owasp'         : 'A05:2021 - Security Misconfiguration',
        },
        'Permissions-Policy': {
            'severity'      : 'low',
            'description'   : (
                'Permissions-Policy header is missing. '
                'This header controls access to browser features '
                'like camera, microphone and geolocation.'
            ),
            'recommendation': (
                'Add header: Permissions-Policy: '
                'camera=(), microphone=(), geolocation=()'
            ),
            'cvss'          : 3.1,
            'owasp'         : 'A05:2021 - Security Misconfiguration',
        },
    }

    # ── Headers that should NOT be present ────────────────────
    DANGEROUS_HEADERS = {
        'Server': {
            'severity'      : 'info',
            'description'   : (
                'The Server header reveals the web server software '
                'and version, helping attackers identify known vulnerabilities.'
            ),
            'recommendation': 'Remove or mask the Server header in server config.',
            'cvss'          : 2.6,
            'owasp'         : 'A05:2021 - Security Misconfiguration',
        },
        'X-Powered-By': {
            'severity'      : 'info',
            'description'   : (
                'X-Powered-By header reveals the technology stack '
                '(e.g. PHP/7.4, ASP.NET). This aids attackers in '
                'targeting known vulnerabilities.'
            ),
            'recommendation': 'Remove the X-Powered-By header from server config.',
            'cvss'          : 2.6,
            'owasp'         : 'A05:2021 - Security Misconfiguration',
        },
    }

    def __init__(self, http_engine: HTTPEngine = None):
        self.http     = http_engine or HTTPEngine()
        self.findings = []

    # ── Main scan ─────────────────────────────────────────────
    def scan(self, pages: list, forms: list = None) -> list:
        """Check security headers on all discovered pages."""
        self.findings = []

        print(f'\n{Fore.CYAN}{"="*55}')
        print(f'  🛡️  Security Headers Checker Starting')
        print(f'  Checking {len(pages)} pages')
        print(f'{"="*55}{Style.RESET_ALL}\n')

        # Check each unique page
        checked_urls = set()
        for page in pages:
            url = page['url']
            if url not in checked_urls:
                checked_urls.add(url)
                self._check_url(url, page.get('headers', {}))

        print(f'\n{Fore.CYAN}{"="*55}')
        print(f'  🛡️  Headers Check Complete')
        print(f'  Found: {len(self.findings)} issue(s)')
        print(f'{"="*55}{Style.RESET_ALL}\n')

        return self.findings

    # ── Check headers for one URL ─────────────────────────────
    def _check_url(self, url: str, existing_headers: dict = None):
        """Check all security headers for a given URL."""

        # Use existing headers from crawler if available
        # otherwise make a fresh request
        if existing_headers:
            headers = {k.lower(): v for k, v in existing_headers.items()}
        else:
            raw_headers = self.http.get_headers(url)
            if not raw_headers:
                return
            headers = {k.lower(): v for k, v in raw_headers.items()}

        print(f'{Fore.WHITE}  Checking: {url[:70]}{Style.RESET_ALL}')

        present  = []
        missing  = []
        warnings = []

        # Check required security headers
        for header_name, details in self.SECURITY_HEADERS.items():
            if header_name.lower() in headers:
                present.append(header_name)
                print(f'  {Fore.GREEN}  ✅ {header_name}{Style.RESET_ALL}')
            else:
                missing.append(header_name)
                print(f'  {Fore.YELLOW}  ⚠️  Missing: {header_name}{Style.RESET_ALL}')

                self.findings.append({
                    'type'          : f'Missing Security Header: {header_name}',
                    'severity'      : details['severity'],
                    'url'           : url,
                    'parameter'     : f'HTTP Header: {header_name}',
                    'payload'       : 'N/A',
                    'evidence'      : f'Header "{header_name}" not present in response',
                    'description'   : details['description'],
                    'recommendation': details['recommendation'],
                    'cvss'          : details['cvss'],
                    'owasp'         : details['owasp'],
                })

        # Check for dangerous headers that should be removed
        for header_name, details in self.DANGEROUS_HEADERS.items():
            if header_name.lower() in headers:
                value = headers[header_name.lower()]
                warnings.append(header_name)
                print(f'  {Fore.YELLOW}  ⚠️  Exposed: {header_name}: {value}{Style.RESET_ALL}')

                self.findings.append({
                    'type'          : f'Information Disclosure: {header_name} Header',
                    'severity'      : details['severity'],
                    'url'           : url,
                    'parameter'     : f'HTTP Header: {header_name}',
                    'payload'       : 'N/A',
                    'evidence'      : f'{header_name}: {value}',
                    'description'   : details['description'],
                    'recommendation': details['recommendation'],
                    'cvss'          : details['cvss'],
                    'owasp'         : details['owasp'],
                })

        print(f'  {Fore.CYAN}  → {len(present)} present | {len(missing)} missing | {len(warnings)} warnings{Style.RESET_ALL}')


# ── Standalone test ───────────────────────────────────────────
if __name__ == '__main__':
    print(f'\n{"="*55}')
    print('  🛡️  Testing Security Headers Checker')
    print(f'{"="*55}\n')

    checker  = HeaderChecker()
    findings = checker.scan(pages=[
        {'url': 'http://httpbin.org', 'headers': {}},
    ])

    print(f'📊 Results for httpbin.org:')
    print(f'   Findings: {len(findings)}\n')

    severity_count = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in findings:
        sev = f['severity']
        severity_count[sev] = severity_count.get(sev, 0) + 1
        icon = {'high': '🔴', 'medium': '🟡', 'low': '🟢', 'info': 'ℹ️'}.get(sev, '⚪')
        print(f'   {icon} [{sev.upper()}] {f["type"]}')

    print(f'\n   Summary:')
    for sev, count in severity_count.items():
        if count > 0:
            print(f'   {sev.capitalize()}: {count}')

    print(f'\n{"="*55}')
    print('  ✅ Headers Checker test complete!')
    print(f'{"="*55}\n')