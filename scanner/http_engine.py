# ============================================================
#  CloudScan – HTTP Engine
#  File: scanner/http_engine.py
#
#  Handles all HTTP requests made by the scanner.
#  Every other module uses this to communicate with targets.
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import time
import urllib3
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, init
from config.config import (
    SCAN_TIMEOUT,
    SCAN_RATE_LIMIT,
    SCAN_USER_AGENT
)

# Disable SSL warnings for testing against local apps
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama for colored terminal output
init(autoreset=True)


class HTTPEngine:

    def __init__(self, timeout: int = None, rate_limit: float = None):
        self.timeout     = timeout    or SCAN_TIMEOUT
        self.rate_limit  = rate_limit or SCAN_RATE_LIMIT
        self.last_request_time = 0

        # Session maintains cookies across requests
        # (important for authenticated scanning)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent'      : SCAN_USER_AGENT,
            'Accept'          : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language' : 'en-US,en;q=0.5',
            'Accept-Encoding' : 'gzip, deflate',
            'Connection'      : 'keep-alive',
        })

        # Track all requests made during a scan
        self.request_count = 0
        self.error_count   = 0

    # ── Rate Limiting ─────────────────────────────────────────
    def _wait(self):
        """Enforce rate limiting between requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self.last_request_time = time.time()

    # ── GET Request ───────────────────────────────────────────
    def get(self, url: str, params: dict = None,
            allow_redirects: bool = True) -> requests.Response | None:
        """Send a GET request to the target URL."""
        self._wait()
        try:
            response = self.session.get(
                url,
                params          = params,
                timeout         = self.timeout,
                verify          = False,
                allow_redirects = allow_redirects,
            )
            self.request_count += 1
            self._log_request('GET', url, response.status_code)
            return response

        except requests.exceptions.ConnectionError:
            self._log_error('GET', url, 'Connection refused or host unreachable')
        except requests.exceptions.Timeout:
            self._log_error('GET', url, f'Timed out after {self.timeout}s')
        except requests.exceptions.TooManyRedirects:
            self._log_error('GET', url, 'Too many redirects')
        except requests.exceptions.RequestException as e:
            self._log_error('GET', url, str(e))

        self.error_count += 1
        return None

    # ── POST Request ──────────────────────────────────────────
    def post(self, url: str, data: dict = None,
             json: dict = None) -> requests.Response | None:
        """Send a POST request with form data or JSON."""
        self._wait()
        try:
            response = self.session.post(
                url,
                data    = data,
                json    = json,
                timeout = self.timeout,
                verify  = False,
            )
            self.request_count += 1
            self._log_request('POST', url, response.status_code)
            return response

        except requests.exceptions.ConnectionError:
            self._log_error('POST', url, 'Connection refused')
        except requests.exceptions.Timeout:
            self._log_error('POST', url, f'Timed out after {self.timeout}s')
        except requests.exceptions.RequestException as e:
            self._log_error('POST', url, str(e))

        self.error_count += 1
        return None

    # ── GET with custom payload ───────────────────────────────
    def get_with_payload(self, url: str,
                         param: str, payload: str) -> requests.Response | None:
        """Send GET request with a specific parameter payload.
        Used by SQLi and XSS detectors to inject into URL parameters."""
        params = {param: payload}
        return self.get(url, params=params)

    # ── Check if URL is reachable ─────────────────────────────
    def is_reachable(self, url: str) -> bool:
        """Check if a target URL is reachable before scanning."""
        print(f'\n{Fore.CYAN}🔍 Checking target reachability: {url}{Style.RESET_ALL}')
        response = self.get(url)
        if response and response.status_code < 500:
            print(f'{Fore.GREEN}✅ Target is reachable — HTTP {response.status_code}{Style.RESET_ALL}')
            return True
        print(f'{Fore.RED}❌ Target is not reachable{Style.RESET_ALL}')
        return False

    # ── Get response headers ──────────────────────────────────
    def get_headers(self, url: str) -> dict | None:
        """Get only the response headers from a URL.
        Used by the security header checker."""
        response = self.get(url, allow_redirects=True)
        if response:
            return dict(response.headers)
        return None

    # ── Set authentication cookies ────────────────────────────
    def set_cookies(self, cookies: dict):
        """Set session cookies for authenticated scanning."""
        self.session.cookies.update(cookies)
        print(f'{Fore.CYAN}🍪 Session cookies set{Style.RESET_ALL}')

    # ── Set custom headers ────────────────────────────────────
    def set_headers(self, headers: dict):
        """Add custom headers to all requests."""
        self.session.headers.update(headers)

    # ── Reset session ─────────────────────────────────────────
    def reset_session(self):
        """Clear all cookies and start a fresh session."""
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': SCAN_USER_AGENT})

    # ── Statistics ────────────────────────────────────────────
    def get_stats(self) -> dict:
        return {
            'total_requests' : self.request_count,
            'total_errors'   : self.error_count,
            'success_rate'   : (
                round(
                    (self.request_count - self.error_count)
                    / max(self.request_count, 1) * 100, 1
                )
            ),
        }

    # ── Logging ───────────────────────────────────────────────
    def _log_request(self, method: str, url: str, status: int):
        color = Fore.GREEN if status < 400 else Fore.YELLOW if status < 500 else Fore.RED
        print(f'  {color}[{method}] {status} {url[:80]}{Style.RESET_ALL}')

    def _log_error(self, method: str, url: str, error: str):
        print(f'  {Fore.RED}[{method}] ERROR {url[:80]} — {error}{Style.RESET_ALL}')


# ── Standalone test ───────────────────────────────────────────
if __name__ == '__main__':
    print(f'\n{"="*55}')
    print('  🔍 Testing HTTP Engine')
    print(f'{"="*55}\n')

    http = HTTPEngine(timeout=10, rate_limit=0.5)

    # Test 1 — Check a known reachable site
    print('📡 Test 1: Checking reachability...')
    reachable = http.is_reachable('http://httpbin.org')
    print(f'   Result: {"✅ Reachable" if reachable else "❌ Not reachable"}')

    # Test 2 — GET request
    print('\n📡 Test 2: GET request...')
    response = http.get('http://httpbin.org/get')
    if response:
        print(f'   Status: {response.status_code}')
        print(f'   Content length: {len(response.text)} chars')

    # Test 3 — POST request
    print('\n📡 Test 3: POST request...')
    response = http.post(
        'http://httpbin.org/post',
        data={'username': 'testuser', 'password': 'testpass'}
    )
    if response:
        print(f'   Status: {response.status_code}')

    # Test 4 — Get headers
    print('\n📡 Test 4: Get response headers...')
    headers = http.get_headers('http://httpbin.org')
    if headers:
        print(f'   Headers received: {len(headers)} headers')
        for key in list(headers.keys())[:3]:
            print(f'   {key}: {headers[key]}')

    # Test 5 — Rate limiting
    print('\n📡 Test 5: Rate limiting (3 requests)...')
    start = time.time()
    for i in range(3):
        http.get('http://httpbin.org/get')
    elapsed = time.time() - start
    print(f'   3 requests took {elapsed:.1f}s (rate limit working)')

    # Stats
    stats = http.get_stats()
    print(f'\n📊 Stats:')
    print(f'   Total requests: {stats["total_requests"]}')
    print(f'   Total errors:   {stats["total_errors"]}')
    print(f'   Success rate:   {stats["success_rate"]}%')

    print(f'\n{"="*55}')
    print('  ✅ HTTP Engine tests complete!')
    print(f'{"="*55}\n')