# ============================================================
#  CloudScan – Web Crawler
#  File: scanner/crawler.py
#
#  Crawls a target website, discovers all pages and forms.
#  This feeds all vulnerability detection modules.
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from urllib.parse import urlparse
from colorama import Fore, Style, init
from scanner.http_engine import HTTPEngine
from scanner.parser import HTMLParser
from config.config import SCAN_MAX_DEPTH, SCAN_MAX_URLS

init(autoreset=True)


class Crawler:

    def __init__(self, http_engine: HTTPEngine = None):
        self.http      = http_engine or HTTPEngine()
        self.visited   = set()
        self.pages     = []
        self.forms     = []
        self.errors    = []
        self.parser    = None
        self.start_time = None

    # ── Main crawl method ─────────────────────────────────────
    def crawl(self, target_url: str,
              max_depth: int = None,
              max_urls:  int = None) -> dict:
        """
        Crawl a target website and collect all pages and forms.
        Returns a dict with all discovered pages, forms and stats.
        """
        max_depth = max_depth or SCAN_MAX_DEPTH
        max_urls  = max_urls  or SCAN_MAX_URLS

        self.start_time = time.time()
        self.parser     = HTMLParser(target_url)

        # Reset state for fresh crawl
        self.visited.clear()
        self.pages.clear()
        self.forms.clear()
        self.errors.clear()

        print(f'\n{Fore.CYAN}{"="*55}')
        print(f'  🕷️  Starting crawl: {target_url}')
        print(f'  Max depth: {max_depth} | Max URLs: {max_urls}')
        print(f'{"="*55}{Style.RESET_ALL}\n')

        # Check target is reachable before crawling
        if not self.http.is_reachable(target_url):
            return self._build_result(target_url, success=False)

        # Start recursive crawl from root URL
        self._crawl_url(target_url, depth=0,
                        max_depth=max_depth, max_urls=max_urls)

        return self._build_result(target_url, success=True)

    # ── Recursive crawler ─────────────────────────────────────
    def _crawl_url(self, url: str, depth: int,
                   max_depth: int, max_urls: int):
        """Recursively crawl a URL and all links found on it."""

        # Stop conditions
        if url in self.visited:
            return
        if depth > max_depth:
            return
        if len(self.visited) >= max_urls:
            print(f'{Fore.YELLOW}  ⚠️  Max URLs limit reached ({max_urls}){Style.RESET_ALL}')
            return

        # Mark as visited
        self.visited.add(url)

        print(f'{Fore.WHITE}  [{len(self.visited)}] Depth {depth} → {url[:70]}{Style.RESET_ALL}')

        # Fetch the page
        response = self.http.get(url)
        if not response:
            self.errors.append({'url': url, 'error': 'No response'})
            return

        # Skip non-HTML responses
        content_type = response.headers.get('Content-Type', '')
        if 'text/html' not in content_type:
            return

        # Parse the page
        parsed = self.parser.parse(response.text, url)

        # Store page data
        page_data = {
            'url'         : url,
            'title'       : parsed['title'],
            'status_code' : response.status_code,
            'depth'       : depth,
            'forms_count' : len(parsed['forms']),
            'links_count' : len(parsed['links']),
            'headers'     : dict(response.headers),
            'response'    : response,
        }
        self.pages.append(page_data)

        # Store all forms found on this page
        for form in parsed['forms']:
            form['found_on'] = url
            self.forms.append(form)
            print(f'  {Fore.MAGENTA}📋 Form found: [{form["method"].upper()}] → {form["action"][:50]}{Style.RESET_ALL}')

        # Log if page has comments
        if parsed['comments']:
            print(f'  {Fore.YELLOW}💬 {len(parsed["comments"])} HTML comment(s) found{Style.RESET_ALL}')

        # Recursively follow all links
        for link in parsed['links']:
            next_url = link['url']
            if next_url not in self.visited:
                self._crawl_url(
                    next_url,
                    depth     = depth + 1,
                    max_depth = max_depth,
                    max_urls  = max_urls
                )

    # ── Build result dict ─────────────────────────────────────
    def _build_result(self, target_url: str, success: bool) -> dict:
        duration = round(time.time() - self.start_time, 2)

        # Collect unique form actions
        unique_forms = []
        seen_actions = set()
        for form in self.forms:
            key = f'{form["action"]}_{form["method"]}'
            if key not in seen_actions:
                seen_actions.add(key)
                unique_forms.append(form)

        result = {
            'success'     : success,
            'target_url'  : target_url,
            'pages'       : self.pages,
            'forms'       : unique_forms,
            'all_forms'   : self.forms,
            'errors'      : self.errors,
            'stats'       : {
                'total_pages'   : len(self.pages),
                'total_forms'   : len(unique_forms),
                'total_urls'    : len(self.visited),
                'total_errors'  : len(self.errors),
                'duration_secs' : duration,
            },
        }

        self._print_summary(result)
        return result

    # ── Print crawl summary ───────────────────────────────────
    def _print_summary(self, result: dict):
        stats = result['stats']
        print(f'\n{Fore.CYAN}{"="*55}')
        print(f'  🕷️  Crawl Complete')
        print(f'{"="*55}')
        print(f'  Pages discovered  : {stats["total_pages"]}')
        print(f'  Forms found       : {stats["total_forms"]}')
        print(f'  URLs visited      : {stats["total_urls"]}')
        print(f'  Errors            : {stats["total_errors"]}')
        print(f'  Duration          : {stats["duration_secs"]}s')
        print(f'{"="*55}{Style.RESET_ALL}\n')


# ── Standalone test ───────────────────────────────────────────
if __name__ == '__main__':
    print(f'\n{"="*55}')
    print('  🕷️  Testing Web Crawler')
    print(f'{"="*55}\n')

    # We test against httpbin.org — a safe public test site
    # When DVWA is set up we will test against that instead
    crawler = Crawler()
    result  = crawler.crawl(
        'http://httpbin.org',
        max_depth = 1,
        max_urls  = 5
    )

    print(f'✅ Success:      {result["success"]}')
    print(f'📄 Pages found:  {result["stats"]["total_pages"]}')
    print(f'📋 Forms found:  {result["stats"]["total_forms"]}')
    print(f'⏱️  Duration:     {result["stats"]["duration_secs"]}s')

    if result['pages']:
        print(f'\n📄 Pages discovered:')
        for page in result['pages']:
            print(f'   [{page["status_code"]}] {page["url"]}')

    if result['forms']:
        print(f'\n📋 Forms found:')
        for form in result['forms']:
            print(f'   [{form["method"].upper()}] {form["action"]}')
            for inp in form['inputs']:
                print(f'      Field: {inp["name"]} ({inp["type"]})')

    print(f'\n{"="*55}')
    print('  ✅ Crawler test complete!')
    print(f'{"="*55}\n')