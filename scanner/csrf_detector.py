# ============================================================
#  CloudScan – CSRF Detector
#  File: scanner/csrf_detector.py
#
#  Detects Cross-Site Request Forgery vulnerabilities.
#  Checks forms for missing CSRF tokens and insecure cookies.
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorama import Fore, Style, init
from scanner.http_engine import HTTPEngine

init(autoreset=True)


class CSRFDetector:

    # ── Known CSRF token field names ──────────────────────────
    CSRF_TOKEN_NAMES = [
        'csrf_token', 'csrf', '_token', 'token',
        'authenticity_token', '_csrf_token',
        'csrfmiddlewaretoken', 'csrf_nonce',
        '__requestverificationtoken', 'xsrf_token',
        '_csrf', 'nonce',
    ]

    def __init__(self, http_engine: HTTPEngine = None):
        self.http     = http_engine or HTTPEngine()
        self.findings = []

    # ── Main scan ─────────────────────────────────────────────
    def scan(self, pages: list, forms: list) -> list:
        """Check all forms for CSRF vulnerabilities."""
        self.findings = []

        print(f'\n{Fore.CYAN}{"="*55}')
        print(f'  🔒 CSRF Scanner Starting')
        print(f'  Checking {len(forms)} forms')
        print(f'{"="*55}{Style.RESET_ALL}\n')

        for form in forms:
            self._check_form(form)

        # Check cookie security
        for page in pages[:3]:
            self._check_cookies(page)

        print(f'\n{Fore.CYAN}{"="*55}')
        print(f'  🔒 CSRF Scan Complete')
        print(f'  Found: {len(self.findings)} issue(s)')
        print(f'{"="*55}{Style.RESET_ALL}\n')

        return self.findings

    # ── Check a form for CSRF token ───────────────────────────
    def _check_form(self, form: dict):
        """Check if a state-changing form has a CSRF token."""
        method = form.get('method', 'get').lower()
        action = form.get('action', '')
        inputs = form.get('inputs', [])

        # Only POST forms are vulnerable to CSRF
        if method != 'post':
            return

        print(f'{Fore.WHITE}  Checking form: [POST] {action[:60]}{Style.RESET_ALL}')

        # Check if any input field is a CSRF token
        has_token = False
        for field in inputs:
            field_name = field.get('name', '').lower()
            if field_name in self.CSRF_TOKEN_NAMES:
                has_token = True
                print(f'  {Fore.GREEN}  ✅ CSRF token found: "{field["name"]}"{Style.RESET_ALL}')
                break

        if not has_token:
            finding = {
                'type'          : 'Cross-Site Request Forgery (CSRF)',
                'severity'      : 'medium',
                'url'           : action,
                'parameter'     : 'N/A — missing token',
                'payload'       : 'N/A',
                'evidence'      : (
                    f'POST form at {action} has no CSRF token. '
                    f'Fields: {[f["name"] for f in inputs]}'
                ),
                'description'   : (
                    f'The POST form at "{action}" does not include a CSRF token. '
                    f'This allows attackers to trick authenticated users into '
                    f'submitting the form unknowingly from a malicious website.'
                ),
                'recommendation': (
                    '1. Add a unique, unpredictable CSRF token to every form.\n'
                    '2. Validate the token on the server for every POST request.\n'
                    '3. Use the SameSite=Strict cookie attribute.\n'
                    '4. Check the Origin and Referer headers on the server.\n'
                    '5. Use modern frameworks with built-in CSRF protection.'
                ),
                'cvss'  : 6.5,
                'owasp' : 'A01:2021 - Broken Access Control',
            }
            self.findings.append(finding)
            print(f'  {Fore.YELLOW}⚠️  MEDIUM: No CSRF token in form → {action[:50]}{Style.RESET_ALL}')

    # ── Check cookie security ─────────────────────────────────
    def _check_cookies(self, page: dict):
        """Check if session cookies have security flags."""
        response = page.get('response')
        if not response:
            return

        cookies = response.cookies
        for cookie in cookies:
            issues = []

            if not cookie.secure:
                issues.append('Missing Secure flag')
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append('Missing HttpOnly flag')

            samesite = cookie.get_nonstandard_attr('SameSite', '')
            if not samesite:
                issues.append('Missing SameSite attribute')

            if issues and cookie.name.lower() in (
                'session', 'sessionid', 'phpsessid',
                'jsessionid', 'sid', 'auth', 'token'
            ):
                finding = {
                    'type'          : 'Insecure Cookie Configuration',
                    'severity'      : 'medium',
                    'url'           : page['url'],
                    'parameter'     : f'Cookie: {cookie.name}',
                    'payload'       : 'N/A',
                    'evidence'      : f'Cookie issues: {", ".join(issues)}',
                    'description'   : (
                        f'The session cookie "{cookie.name}" is missing '
                        f'security attributes: {", ".join(issues)}.'
                    ),
                    'recommendation': (
                        '1. Set Secure flag — cookie only sent over HTTPS.\n'
                        '2. Set HttpOnly flag — prevents JavaScript access.\n'
                        '3. Set SameSite=Strict — prevents CSRF attacks.\n'
                        '4. Set appropriate expiry time.'
                    ),
                    'cvss'  : 5.3,
                    'owasp' : 'A02:2021 - Cryptographic Failures',
                }
                self.findings.append(finding)
                print(f'  {Fore.YELLOW}⚠️  Cookie issue: {cookie.name} — {", ".join(issues)}{Style.RESET_ALL}')


# ── Standalone test ───────────────────────────────────────────
if __name__ == '__main__':
    print(f'\n{"="*55}')
    print('  🔒 Testing CSRF Detector')
    print(f'{"="*55}\n')

    # Form WITH csrf token — should pass
    form_safe = {
        'action'   : 'http://testsite.local/login',
        'method'   : 'post',
        'found_on' : 'http://testsite.local/',
        'inputs'   : [
            {'name': 'username',   'type': 'text',     'value': ''},
            {'name': 'password',   'type': 'password', 'value': ''},
            {'name': 'csrf_token', 'type': 'hidden',   'value': 'abc123'},
        ],
    }

    # Form WITHOUT csrf token — should flag
    form_vulnerable = {
        'action'   : 'http://testsite.local/transfer',
        'method'   : 'post',
        'found_on' : 'http://testsite.local/',
        'inputs'   : [
            {'name': 'amount',    'type': 'text', 'value': ''},
            {'name': 'recipient', 'type': 'text', 'value': ''},
        ],
    }

    # GET form — should be ignored
    form_get = {
        'action'   : 'http://testsite.local/search',
        'method'   : 'get',
        'found_on' : 'http://testsite.local/',
        'inputs'   : [
            {'name': 'q', 'type': 'text', 'value': ''},
        ],
    }

    detector = CSRFDetector()
    findings = detector.scan(
        pages = [],
        forms = [form_safe, form_vulnerable, form_get]
    )

    print(f'📊 Results:')
    print(f'   Findings: {len(findings)} (expected: 1)')

    for f in findings:
        print(f'\n   ⚠️  [{f["severity"].upper()}] {f["type"]}')
        print(f'   URL:      {f["url"]}')
        print(f'   Evidence: {f["evidence"][:80]}')

    if len(findings) == 1:
        print(f'\n   {Fore.GREEN}✅ CSRF Detector working correctly!{Style.RESET_ALL}')

    print(f'\n{"="*55}')
    print('  ✅ CSRF Detector test complete!')
    print(f'{"="*55}\n')