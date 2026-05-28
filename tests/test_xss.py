# ============================================================
#  CloudScan – XSS and CSRF Unit Tests
#  File: tests/test_xss.py
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import MagicMock
from scanner.xss_detector  import XSSDetector
from scanner.csrf_detector  import CSRFDetector
from scanner.header_checker import HeaderChecker


class TestXSSDetector:

    def setup_method(self):
        self.detector = XSSDetector()

    def test_initializes_correctly(self):
        assert self.detector is not None
        assert len(self.detector.PAYLOADS) >= 10
        assert self.detector.findings == []

    def test_detects_reflected_xss(self):
        """Test XSS detected when payload reflects in HTML response."""
        mock_http     = MagicMock()
        mock_response = MagicMock()
        mock_response.text = '<html><body><script>alert(1)</script></body></html>'

        # Tell the mock to return text/html content type
        # This is what our improved detector now checks for
        mock_response.headers = {'Content-Type': 'text/html; charset=utf-8'}

        mock_http.post.return_value = mock_response
        mock_http.get.return_value  = mock_response

        detector = XSSDetector(http_engine=mock_http)
        inputs   = [{'name': 'search', 'type': 'text', 'value': ''}]
        finding  = detector._test_field(
            'http://test.com/search', 'get', inputs, 'search'
        )
        assert finding is not None
        assert finding['severity'] == 'high'
        assert 'XSS' in finding['type']

    def test_no_xss_on_clean_response(self):
        """No finding when response properly encodes output."""
        mock_http     = MagicMock()
        mock_response = MagicMock()
        mock_response.text = '<html><body>Welcome!</body></html>'
        mock_http.post.return_value = mock_response
        mock_http.get.return_value  = mock_response

        detector = XSSDetector(http_engine=mock_http)
        inputs   = [{'name': 'name', 'type': 'text', 'value': ''}]
        finding  = detector._test_field(
            'http://test.com/', 'post', inputs, 'name'
        )
        assert finding is None

    def test_scan_returns_list(self):
        result = self.detector.scan(pages=[], forms=[])
        assert isinstance(result, list)


class TestCSRFDetector:

    def setup_method(self):
        self.detector = CSRFDetector()

    def test_flags_form_without_csrf_token(self):
        """Form with no CSRF token should be flagged."""
        form = {
            'action'   : 'http://test.com/transfer',
            'method'   : 'post',
            'found_on' : 'http://test.com/',
            'inputs'   : [
                {'name': 'amount',    'type': 'text', 'value': ''},
                {'name': 'recipient', 'type': 'text', 'value': ''},
            ],
        }
        findings = self.detector.scan(pages=[], forms=[form])
        assert len(findings) == 1
        assert findings[0]['severity'] == 'medium'
        assert 'CSRF' in findings[0]['type']

    def test_passes_form_with_csrf_token(self):
        """Form with CSRF token should not be flagged."""
        form = {
            'action'   : 'http://test.com/login',
            'method'   : 'post',
            'found_on' : 'http://test.com/',
            'inputs'   : [
                {'name': 'username',   'type': 'text',     'value': ''},
                {'name': 'csrf_token', 'type': 'hidden',   'value': 'abc'},
            ],
        }
        findings = self.detector.scan(pages=[], forms=[form])
        assert len(findings) == 0

    def test_ignores_get_forms(self):
        """GET forms are not vulnerable to CSRF."""
        form = {
            'action'   : 'http://test.com/search',
            'method'   : 'get',
            'found_on' : 'http://test.com/',
            'inputs'   : [{'name': 'q', 'type': 'text', 'value': ''}],
        }
        findings = self.detector.scan(pages=[], forms=[form])
        assert len(findings) == 0

    def test_recognises_all_token_names(self):
        """Test all known CSRF token field names are recognised."""
        for token_name in ['csrf_token', '_token', 'csrfmiddlewaretoken']:
            form = {
                'action'   : 'http://test.com/action',
                'method'   : 'post',
                'found_on' : 'http://test.com/',
                'inputs'   : [
                    {'name': 'data',     'type': 'text',   'value': ''},
                    {'name': token_name, 'type': 'hidden', 'value': 'xyz'},
                ],
            }
            findings = self.detector.scan(pages=[], forms=[form])
            assert len(findings) == 0, f'Token "{token_name}" not recognised'


class TestHeaderChecker:

    def setup_method(self):
        self.checker = HeaderChecker()

    def test_flags_missing_security_headers(self):
        """Missing security headers should create findings."""
        mock_http     = MagicMock()
        mock_response = MagicMock()
        mock_response.headers = {
            'Content-Type': 'text/html',
        }
        mock_http.get.return_value = mock_response

        checker  = HeaderChecker(http_engine=mock_http)
        findings = checker.scan(pages=[{'url': 'http://test.com', 'headers': {}}])
        assert len(findings) > 0

    def test_no_findings_when_all_headers_present(self):
        """No findings when all security headers are configured."""
        all_secure_headers = {
            'strict-transport-security' : 'max-age=31536000',
            'content-security-policy'   : "default-src 'self'",
            'x-frame-options'           : 'DENY',
            'x-content-type-options'    : 'nosniff',
            'referrer-policy'           : 'strict-origin-when-cross-origin',
            'permissions-policy'        : 'camera=()',
        }
        checker  = HeaderChecker()
        checker._check_url('http://test.com', all_secure_headers)
        header_findings = [
            f for f in checker.findings
            if 'Missing Security Header' in f['type']
        ]
        assert len(header_findings) == 0

    def test_flags_server_header_exposure(self):
        """Server header exposing version info should be flagged."""
        headers = {
            'server'                    : 'Apache/2.4.41 (Ubuntu)',
            'strict-transport-security' : 'max-age=31536000',
            'content-security-policy'   : "default-src 'self'",
            'x-frame-options'           : 'DENY',
            'x-content-type-options'    : 'nosniff',
            'referrer-policy'           : 'no-referrer',
            'permissions-policy'        : 'camera=()',
        }
        checker = HeaderChecker()
        checker._check_url('http://test.com', headers)
        server_findings = [
            f for f in checker.findings
            if 'Server' in f['type']
        ]
        assert len(server_findings) == 1

    def test_scan_returns_list(self):
        result = self.checker.scan(pages=[], forms=[])
        assert isinstance(result, list)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])