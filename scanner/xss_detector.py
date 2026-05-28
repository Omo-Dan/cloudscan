# ============================================================
#  CloudScan – XSS Detector
#  File: scanner/xss_detector.py
#
#  Detects Cross-Site Scripting (XSS) vulnerabilities.
#  Tests for Reflected XSS in forms and URL parameters.
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorama import Fore, Style, init
from scanner.http_engine import HTTPEngine

init(autoreset=True)


class XSSDetector:

    # ── XSS Payloads ──────────────────────────────────────────
    PAYLOADS = [
        # Basic script injection
        '<script>alert(1)</script>',
        '<script>alert("XSS")</script>',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",

        # Event handler injection
        '<img src=x onerror=alert(1)>',
        '<img src=x onerror=alert("XSS")>',
        '"><img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',

        # Attribute injection
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)",
        '" onfocus="alert(1)" autofocus="',

        # Filter bypass attempts
        '<ScRiPt>alert(1)</ScRiPt>',
        '<script >alert(1)</script >',
        '<<script>alert(1)//<</script>',
        '<script/src=data:,alert(1)>',

        # HTML5 vectors
        '<details open ontoggle=alert(1)>',
        '<input autofocus onfocus=alert(1)>',
        '<select autofocus onfocus=alert(1)>',
    ]

    # ── Signatures to detect in response ─────────────────────
    # If our payload appears unescaped in the response
    # the application is vulnerable to reflected XSS
    REFLECTION_MARKERS = [
        '<script>alert(1)</script>',
        '<script>alert("xss")</script>',
        'onerror=alert(1)',
        'onerror=alert("xss")',
        '<svg onload=alert(1)>',
        'onmouseover="alert(1)',
        "onmouseover='alert(1)",
        '<scr\nipt>alert(1)</script>',
    ]

    def __init__(self, http_engine: HTTPEngine = None):
        self.http     = http_engine or HTTPEngine()
        self.findings = []

    # ── Main scan ─────────────────────────────────────────────
    def scan(self, pages: list, forms: list) -> list:
        """Scan all forms and URL parameters for XSS."""
        self.findings = []

        print(f'\n{Fore.CYAN}{"="*55}')
        print(f'  🔥 XSS Scanner Starting')
        print(f'  Scanning {len(forms)} forms across {len(pages)} pages')
        print(f'{"="*55}{Style.RESET_ALL}\n')

        for form in forms:
            self._scan_form(form)

        for page in pages:
            if '?' in page['url']:
                self._scan_url_params(page['url'])

        print(f'\n{Fore.CYAN}{"="*55}')
        print(f'  🔥 XSS Scan Complete')
        print(f'  Found: {len(self.findings)} vulnerability/ies')
        print(f'{"="*55}{Style.RESET_ALL}\n')

        return self.findings

    # ── Scan a form ───────────────────────────────────────────
    def _scan_form(self, form: dict):
        url    = form['action']
        method = form['method']
        inputs = form['inputs']

        if not inputs:
            return

        print(f'{Fore.WHITE}  Testing form: [{method.upper()}] {url[:60]}{Style.RESET_ALL}')

        for field in inputs:
            if field['type'] in ('submit', 'button', 'file', 'image'):
                continue

            finding = self._test_field(url, method, inputs, field['name'])
            if finding:
                self.findings.append(finding)
                print(f'  {Fore.RED}🚨 HIGH: Reflected XSS in "{field["name"]}"{Style.RESET_ALL}')

    # ── Test a single field ───────────────────────────────────
    def _test_field(self, url: str, method: str,
                    inputs: list, target_field: str) -> dict | None:
        """Inject XSS payloads and check if they reflect in HTML context."""

        for payload in self.PAYLOADS:
            data = self._build_data(inputs, target_field, payload)

            if method == 'post':
                response = self.http.post(url, data=data)
            else:
                response = self.http.get(url, params=data)

            if not response:
                continue

            # ── Improved check — must be HTML response ────────
            content_type = response.headers.get('Content-Type', '').lower()

            # Skip JSON, XML and plain text responses
            # XSS only executes in HTML context
            if 'text/html' not in content_type:
                continue

            response_lower = response.text.lower()

            # Check if our payload appears unescaped in HTML response
            for marker in self.REFLECTION_MARKERS:
                if marker.lower() in response_lower:
                    return {
                        'type'          : 'Reflected Cross-Site Scripting (XSS)',
                        'severity'      : 'high',
                        'url'           : url,
                        'parameter'     : target_field,
                        'payload'       : payload,
                        'evidence'      : f'Payload reflected unescaped in HTML: {marker[:50]}',
                        'description'   : (
                            f'A Reflected XSS vulnerability was found in the '
                            f'"{target_field}" parameter. User-supplied input is '
                            f'returned in the HTML response without proper encoding, '
                            f'allowing attackers to inject malicious scripts.'
                        ),
                        'recommendation': (
                            '1. Encode all output using HTML entity encoding.\n'
                            '2. Implement Content Security Policy (CSP) headers.\n'
                            '3. Use modern frameworks that auto-escape output.\n'
                            '4. Validate and sanitize all user input.\n'
                            '5. Use HTTPOnly and Secure flags on cookies.'
                        ),
                        'cvss'  : 7.4,
                        'owasp' : 'A03:2021 - Injection',
                    }
        return None

    # ── Scan URL parameters ───────────────────────────────────
    def _scan_url_params(self, url: str):
        """Test URL query parameters for reflected XSS."""
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name in params:
            for payload in self.PAYLOADS[:5]:
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = parsed._replace(
                    query=urlencode(test_params, doseq=True)
                ).geturl()

                response = self.http.get(test_url)
                if not response:
                    continue

                # Only check HTML responses
                content_type = response.headers.get('Content-Type', '').lower()
                if 'text/html' not in content_type:
                    continue

                for marker in self.REFLECTION_MARKERS:
                    if marker.lower() in response.text.lower():
                        finding = {
                            'type'          : 'Reflected XSS (URL Parameter)',
                            'severity'      : 'high',
                            'url'           : url,
                            'parameter'     : param_name,
                            'payload'       : payload,
                            'evidence'      : f'Payload reflected in HTML: {marker[:50]}',
                            'description'   : (
                                f'XSS found in URL parameter "{param_name}".'
                            ),
                            'recommendation': 'Encode all output. Implement CSP.',
                            'cvss'          : 7.4,
                            'owasp'         : 'A03:2021 - Injection',
                        }
                        self.findings.append(finding)
                        print(f'  {Fore.RED}🚨 XSS in URL param "{param_name}"{Style.RESET_ALL}')
                        return

    # ── Build form data ───────────────────────────────────────
    def _build_data(self, inputs: list,
                    target: str, payload: str) -> dict:
        data = {}
        for field in inputs:
            name = field['name']
            if name == target:
                data[name] = payload
            else:
                ftype = field.get('type', 'text')
                if ftype == 'email':
                    data[name] = 'test@test.com'
                elif ftype == 'number':
                    data[name] = '1'
                elif ftype == 'password':
                    data[name] = 'Password123'
                else:
                    data[name] = 'test'
        return data


# ── Standalone test ───────────────────────────────────────────
if __name__ == '__main__':
    print(f'\n{"="*55}')
    print('  🔥 Testing XSS Detector')
    print(f'{"="*55}\n')

    test_forms = [{
        'action'   : 'http://httpbin.org/post',
        'method'   : 'post',
        'found_on' : 'http://httpbin.org/forms/post',
        'inputs'   : [
            {'name': 'custname', 'type': 'text', 'value': ''},
            {'name': 'comments', 'type': 'text', 'value': ''},
        ],
    }]

    test_pages = [
        {'url': 'http://httpbin.org/forms/post'},
    ]

    detector = XSSDetector()
    findings = detector.scan(pages=test_pages, forms=test_forms)

    print(f'📊 Results:')
    print(f'   Findings: {len(findings)}')
    if not findings:
        print(f'\n   {Fore.GREEN}✅ No XSS found on httpbin.org (expected){Style.RESET_ALL}')
        print(f'   Real XSS will be found when testing against DVWA.')

    print(f'\n{"="*55}')
    print(f'  ✅ XSS Detector test complete!')
    print(f'{"="*55}\n')