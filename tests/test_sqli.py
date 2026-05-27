# ============================================================
#  CloudScan – SQL Injection Unit Tests
#  File: tests/test_sqli.py
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import MagicMock, patch
from scanner.sqli_detector import SQLiDetector


class TestSQLiDetector:

    def setup_method(self):
        """Set up fresh detector before each test."""
        self.detector = SQLiDetector()

    def test_detector_initializes(self):
        """Test SQLiDetector initializes correctly."""
        assert self.detector is not None
        assert self.detector.findings == []
        assert len(self.detector.ERROR_PAYLOADS) > 0
        assert len(self.detector.ERROR_SIGNATURES) > 0

    def test_build_form_data_injects_payload(self):
        """Test that payload is injected into target field."""
        inputs = [
            {'name': 'username', 'type': 'text',     'value': ''},
            {'name': 'password', 'type': 'password', 'value': ''},
        ]
        data = self.detector._build_form_data(inputs, 'username', "' OR 1=1--")
        assert data['username'] == "' OR 1=1--"
        assert data['password'] == 'Password123'

    def test_build_form_data_fills_other_fields(self):
        """Test that non-target fields get safe dummy values."""
        inputs = [
            {'name': 'email',   'type': 'email',  'value': ''},
            {'name': 'age',     'type': 'number', 'value': ''},
            {'name': 'comment', 'type': 'text',   'value': ''},
        ]
        data = self.detector._build_form_data(inputs, 'comment', 'payload')
        assert data['email']   == 'test@test.com'
        assert data['age']     == '1'
        assert data['comment'] == 'payload'

    def test_build_finding_structure(self):
        """Test finding dict has all required keys."""
        finding = self.detector._build_finding(
            detection_type = 'Error-based SQL Injection',
            severity       = 'critical',
            url            = 'http://test.com/login',
            parameter      = 'username',
            payload        = "' OR 1=1--",
            evidence       = 'MySQL error detected',
            cvss           = 9.8,
        )
        required_keys = [
            'type', 'severity', 'url', 'parameter',
            'payload', 'evidence', 'description',
            'recommendation', 'cvss', 'owasp'
        ]
        for key in required_keys:
            assert key in finding, f'Missing key: {key}'

        assert finding['severity']  == 'critical'
        assert finding['cvss']      == 9.8
        assert finding['owasp']     == 'A03:2021 - Injection'

    def test_error_signatures_list_not_empty(self):
        """Test that error signatures list is populated."""
        assert len(self.detector.ERROR_SIGNATURES) >= 20

    def test_payloads_list_not_empty(self):
        """Test that payload lists are populated."""
        assert len(self.detector.ERROR_PAYLOADS)  >= 10
        assert len(self.detector.BOOLEAN_TRUE)     >= 3
        assert len(self.detector.TIME_PAYLOADS)    >= 3

    def test_error_based_detects_mysql_error(self):
        """Test error-based detection catches MySQL error response."""
        mock_http = MagicMock()
        mock_response = MagicMock()
        mock_response.text = (
            "Warning: mysql_fetch_array() expects parameter"
            "You have an error in your SQL syntax near ''"
        )
        mock_http.post.return_value = mock_response
        mock_http.get.return_value  = mock_response

        detector  = SQLiDetector(http_engine=mock_http)
        inputs    = [{'name': 'id', 'type': 'text', 'value': ''}]
        finding   = detector._test_error_based(
            'http://test.com/page', 'post', inputs, 'id'
        )

        assert finding is not None
        assert finding['severity'] == 'critical'
        assert 'SQL Injection' in finding['type']

    def test_no_finding_on_clean_response(self):
        """Test no finding returned for clean response."""
        mock_http     = MagicMock()
        mock_response = MagicMock()
        mock_response.text = '<html><body>Welcome back!</body></html>'
        mock_http.post.return_value = mock_response
        mock_http.get.return_value  = mock_response

        detector = SQLiDetector(http_engine=mock_http)
        inputs   = [{'name': 'username', 'type': 'text', 'value': ''}]
        finding  = detector._test_error_based(
            'http://test.com/login', 'post', inputs, 'username'
        )
        assert finding is None

    def test_scan_returns_list(self):
        """Test that scan() always returns a list."""
        detector = SQLiDetector()
        result   = detector.scan(pages=[], forms=[])
        assert isinstance(result, list)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])