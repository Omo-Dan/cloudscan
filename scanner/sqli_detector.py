# ============================================================
#  CloudScan – SQL Injection Detector
#  File: scanner/sqli_detector.py
#
#  Detects SQL Injection vulnerabilities using three methods:
#  1. Error-based   — database errors in response
#  2. Boolean-based — different responses for true/false
#  3. Time-based    — SLEEP() delays in response time
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from colorama import Fore, Style, init
from scanner.http_engine import HTTPEngine

init(autoreset=True)


class SQLiDetector:

    # ── Payloads ──────────────────────────────────────────────
    # Error-based payloads — trigger database errors
    ERROR_PAYLOADS = [
        "'",
        '"',
        "''",
        "`",
        "' OR '1'='1",
        '" OR "1"="1',
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR ('1'='1",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "1 ORDER BY 1--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "'; SELECT SLEEP(0)--",
    ]

    # Boolean-based payloads — TRUE condition
    BOOLEAN_TRUE = [
        "' OR '1'='1'--",
        "' OR 1=1--",
        "1' OR '1'='1",
        "admin'--",
        "' OR 'x'='x",
    ]

    # Boolean-based payloads — FALSE condition
    BOOLEAN_FALSE = [
        "' OR '1'='2'--",
        "' OR 1=2--",
        "1' OR '1'='2",
        "' OR 'x'='y",
    ]

    # Time-based payloads — cause database to sleep
    TIME_PAYLOADS = [
        "'; SLEEP(3)--",
        "1; SLEEP(3)--",
        "' AND SLEEP(3)--",
        "1' AND SLEEP(3)--",
        "'; WAITFOR DELAY '0:0:3'--",     # SQL Server
        "1; WAITFOR DELAY '0:0:3'--",
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",  # Oracle
    ]

    # ── Database error signatures ─────────────────────────────
    ERROR_SIGNATURES = [
        # MySQL
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysql_fetch",
        "mysql_num_rows",
        "mysql_query",
        "mysqli_fetch",
        "mysqli_query",
        "supplied argument is not a valid mysql",
        # SQL Server
        "microsoft ole db provider for sql server",
        "odbc sql server driver",
        "sqlserver jdbc driver",
        "unclosed quotation mark",
        "incorrect syntax near",
        "mssql_query",
        # Oracle
        "ora-01756",
        "ora-00907",
        "oracle error",
        # SQLite
        "sqlite/jdbcdriver",
        "sqlite3::query",
        "sqlite_step",
        # PostgreSQL
        "postgresql",
        "pg_query",
        "pg_exec",
        # General
        "sqlstate",
        "sql syntax",
        "sql error",
        "database error",
        "invalid query",
        "syntax error",
        "db_query",
        "db error",
        "mysql error",
    ]

    def __init__(self, http_engine: HTTPEngine = None):
        self.http     = http_engine or HTTPEngine()
        self.findings = []

    # ── Main scan method ──────────────────────────────────────
    def scan(self, pages: list, forms: list) -> list:
        """
        Scan all pages and forms for SQL Injection.
        Returns list of findings.
        """
        self.findings = []

        print(f'\n{Fore.CYAN}{"="*55}')
        print(f'  💉 SQL Injection Scanner Starting')
        print(f'  Scanning {len(forms)} forms across {len(pages)} pages')
        print(f'{"="*55}{Style.RESET_ALL}\n')

        # Scan all forms
        for form in forms:
            self._scan_form(form)

        # Scan URL parameters in pages
        for page in pages:
            url = page['url']
            if '?' in url:
                self._scan_url_params(url)

        print(f'\n{Fore.CYAN}{"="*55}')
        print(f'  💉 SQL Injection Scan Complete')
        print(f'  Found: {len(self.findings)} vulnerability/ies')
        print(f'{"="*55}{Style.RESET_ALL}\n')

        return self.findings

    # ── Scan a form ───────────────────────────────────────────
    def _scan_form(self, form: dict):
        """Test all inputs in a form for SQL Injection."""
        url    = form.get('found_on', form['action'])
        action = form['action']
        method = form['method']
        inputs = form['inputs']

        if not inputs:
            return

        print(f'{Fore.WHITE}  Testing form: [{method.upper()}] {action[:60]}{Style.RESET_ALL}')

        for input_field in inputs:
            field_name = input_field['name']

            # Skip submit buttons, checkboxes, hidden fields
            if input_field['type'] in ('submit', 'button', 'image', 'file'):
                continue

            # Test 1 — Error-based SQLi
            finding = self._test_error_based(
                action, method, inputs, field_name
            )
            if finding:
                self.findings.append(finding)
                print(f'  {Fore.RED}🚨 CRITICAL: Error-based SQLi in "{field_name}"{Style.RESET_ALL}')
                continue  # Found vuln in this field, move to next

            # Test 2 — Boolean-based SQLi
            finding = self._test_boolean_based(
                action, method, inputs, field_name
            )
            if finding:
                self.findings.append(finding)
                print(f'  {Fore.RED}🚨 HIGH: Boolean-based SQLi in "{field_name}"{Style.RESET_ALL}')
                continue

            # Test 3 — Time-based SQLi
            finding = self._test_time_based(
                action, method, inputs, field_name
            )
            if finding:
                self.findings.append(finding)
                print(f'  {Fore.RED}🚨 HIGH: Time-based SQLi in "{field_name}"{Style.RESET_ALL}')

    # ── Test 1: Error-based SQLi ──────────────────────────────
    def _test_error_based(self, url: str, method: str,
                          inputs: list, target_field: str) -> dict | None:
        """
        Inject SQL payloads and look for database errors
        in the response.
        """
        for payload in self.ERROR_PAYLOADS:
            data = self._build_form_data(inputs, target_field, payload)

            if method == 'post':
                response = self.http.post(url, data=data)
            else:
                response = self.http.get(url, params=data)

            if not response:
                continue

            response_lower = response.text.lower()

            for signature in self.ERROR_SIGNATURES:
                if signature.lower() in response_lower:
                    return self._build_finding(
                        detection_type = 'Error-based SQL Injection',
                        severity       = 'critical',
                        url            = url,
                        parameter      = target_field,
                        payload        = payload,
                        evidence       = f'Database error detected: "{signature}"',
                        cvss           = 9.8,
                    )
        return None

    # ── Test 2: Boolean-based SQLi ────────────────────────────
    def _test_boolean_based(self, url: str, method: str,
                             inputs: list, target_field: str) -> dict | None:
        """
        Send TRUE and FALSE boolean payloads and compare responses.
        Different response lengths indicate vulnerability.
        """
        # Get baseline response with normal value
        normal_data   = self._build_form_data(inputs, target_field, 'test')
        if method == 'post':
            baseline = self.http.post(url, data=normal_data)
        else:
            baseline = self.http.get(url, params=normal_data)

        if not baseline:
            return None

        baseline_len = len(baseline.text)

        # Test TRUE payload
        for true_payload in self.BOOLEAN_TRUE[:2]:
            true_data = self._build_form_data(inputs, target_field, true_payload)
            if method == 'post':
                true_resp = self.http.post(url, data=true_data)
            else:
                true_resp = self.http.get(url, params=true_data)

            if not true_resp:
                continue

            # Test FALSE payload
            for false_payload in self.BOOLEAN_FALSE[:2]:
                false_data = self._build_form_data(inputs, target_field, false_payload)
                if method == 'post':
                    false_resp = self.http.post(url, data=false_data)
                else:
                    false_resp = self.http.get(url, params=false_data)

                if not false_resp:
                    continue

                true_len  = len(true_resp.text)
                false_len = len(false_resp.text)

                # If TRUE and FALSE give significantly different responses
                # — the input is being evaluated as SQL
                difference = abs(true_len - false_len)
                if difference > 50 and true_len != baseline_len:
                    return self._build_finding(
                        detection_type = 'Boolean-based SQL Injection',
                        severity       = 'high',
                        url            = url,
                        parameter      = target_field,
                        payload        = f'TRUE: {true_payload} | FALSE: {false_payload}',
                        evidence       = (
                            f'Response length difference: {difference} chars '
                            f'(TRUE={true_len}, FALSE={false_len})'
                        ),
                        cvss = 8.1,
                    )
        return None

    # ── Test 3: Time-based SQLi ───────────────────────────────
    def _test_time_based(self, url: str, method: str,
                         inputs: list, target_field: str) -> dict | None:
        """
        Inject SLEEP() payloads and measure response time.
        If response is significantly delayed, the DB executed our SQL.
        """
        # Baseline request time
        normal_data = self._build_form_data(inputs, target_field, 'test')
        start = time.time()
        if method == 'post':
            self.http.post(url, data=normal_data)
        else:
            self.http.get(url, params=normal_data)
        baseline_time = time.time() - start

        # Test time-based payloads
        for payload in self.TIME_PAYLOADS[:3]:
            data  = self._build_form_data(inputs, target_field, payload)
            start = time.time()

            if method == 'post':
                response = self.http.post(url, data=data)
            else:
                response = self.http.get(url, params=data)

            elapsed = time.time() - start

            # If response took 2.5+ seconds more than baseline — vulnerable
            if elapsed > (baseline_time + 2.5):
                return self._build_finding(
                    detection_type = 'Time-based Blind SQL Injection',
                    severity       = 'high',
                    url            = url,
                    parameter      = target_field,
                    payload        = payload,
                    evidence       = (
                        f'Response delayed by {elapsed:.1f}s '
                        f'(baseline: {baseline_time:.1f}s)'
                    ),
                    cvss = 7.5,
                )
        return None

    # ── Scan URL parameters ───────────────────────────────────
    def _scan_url_params(self, url: str):
        """Test URL query parameters for SQL Injection."""
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return

        print(f'{Fore.WHITE}  Testing URL params: {url[:60]}{Style.RESET_ALL}')

        for param_name in params:
            for payload in self.ERROR_PAYLOADS[:5]:
                test_params          = dict(params)
                test_params[param_name] = [payload]

                test_url = parsed._replace(
                    query=urlencode(test_params, doseq=True)
                ).geturl()

                response = self.http.get(test_url)
                if not response:
                    continue

                response_lower = response.text.lower()
                for signature in self.ERROR_SIGNATURES:
                    if signature.lower() in response_lower:
                        finding = self._build_finding(
                            detection_type = 'Error-based SQL Injection (URL Parameter)',
                            severity       = 'critical',
                            url            = url,
                            parameter      = param_name,
                            payload        = payload,
                            evidence       = f'DB error: "{signature}"',
                            cvss           = 9.8,
                        )
                        self.findings.append(finding)
                        print(f'  {Fore.RED}🚨 SQLi in URL param "{param_name}"{Style.RESET_ALL}')
                        return

    # ── Build form data with injected payload ─────────────────
    def _build_form_data(self, inputs: list,
                         target_field: str, payload: str) -> dict:
        """Build a form data dict with payload in the target field."""
        data = {}
        for field in inputs:
            name = field['name']
            if name == target_field:
                data[name] = payload
            else:
                # Fill other fields with safe dummy values
                field_type = field.get('type', 'text')
                if field_type == 'email':
                    data[name] = 'test@test.com'
                elif field_type == 'number':
                    data[name] = '1'
                elif field_type == 'password':
                    data[name] = 'Password123'
                elif field_type in ('radio', 'checkbox'):
                    data[name] = field.get('value', 'on')
                else:
                    data[name] = 'test'
        return data

    # ── Build finding dict ────────────────────────────────────
    def _build_finding(self, detection_type: str, severity: str,
                       url: str, parameter: str, payload: str,
                       evidence: str, cvss: float) -> dict:
        """Build a standardised finding dictionary."""
        return {
            'type'          : detection_type,
            'severity'      : severity,
            'url'           : url,
            'parameter'     : parameter,
            'payload'       : payload,
            'evidence'      : evidence,
            'description'   : (
                f'A SQL Injection vulnerability was detected in the '
                f'"{parameter}" parameter using {detection_type}. '
                f'An attacker could manipulate database queries to '
                f'bypass authentication, extract data, or destroy the database.'
            ),
            'recommendation': (
                '1. Use prepared statements with parameterized queries.\n'
                '2. Never concatenate user input directly into SQL strings.\n'
                '3. Apply input validation and whitelist allowed characters.\n'
                '4. Use an ORM (Object Relational Mapper) where possible.\n'
                '5. Apply principle of least privilege to database accounts.'
            ),
            'cvss'          : cvss,
            'owasp'         : 'A03:2021 - Injection',
        }


# ── Standalone test ───────────────────────────────────────────
if __name__ == '__main__':
    print(f'\n{"="*55}')
    print('  💉 Testing SQL Injection Detector')
    print(f'{"="*55}\n')

    # Simulate forms that the crawler would have found
    # We test with httpbin.org which is NOT vulnerable
    # (we expect 0 findings — that is the correct result)
    # When DVWA is set up we will find real vulnerabilities

    test_forms = [
        {
            'action'   : 'http://httpbin.org/post',
            'method'   : 'post',
            'found_on' : 'http://httpbin.org/forms/post',
            'inputs'   : [
                {'name': 'custname', 'type': 'text',  'value': ''},
                {'name': 'custtel',  'type': 'tel',   'value': ''},
                {'name': 'comments', 'type': 'text',  'value': ''},
            ],
        }
    ]

    test_pages = [
        {'url': 'http://httpbin.org/forms/post'},
        {'url': 'http://httpbin.org/get?id=1&name=test'},
    ]

    detector = SQLiDetector()
    findings = detector.scan(
        pages = test_pages,
        forms = test_forms
    )

    print(f'📊 Results:')
    print(f'   Findings: {len(findings)}')

    if findings:
        for f in findings:
            print(f'\n   🚨 [{f["severity"].upper()}] {f["type"]}')
            print(f'   Parameter: {f["parameter"]}')
            print(f'   Payload:   {f["payload"]}')
            print(f'   Evidence:  {f["evidence"]}')
            print(f'   CVSS:      {f["cvss"]}')
    else:
        print(f'\n   {Fore.GREEN}✅ No SQLi found on httpbin.org')
        print(f'   (Expected — httpbin.org is not vulnerable)')
        print(f'   When we test against DVWA we will find real findings.{Style.RESET_ALL}')

    print(f'\n{"="*55}')
    print('  ✅ SQLi Detector test complete!')
    print(f'{"="*55}\n')