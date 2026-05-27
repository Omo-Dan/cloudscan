# ============================================================
#  CloudScan – HTML Parser
#  File: scanner/parser.py
#
#  Extracts all forms, inputs, links and data from HTML pages.
#  Used by the crawler and all vulnerability detectors.
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


class HTMLParser:

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc

    # ── Parse full page ───────────────────────────────────────
    def parse(self, html: str, current_url: str) -> dict:
        """Parse an HTML page and extract all useful data."""
        soup = BeautifulSoup(html, 'lxml')
        return {
            'forms'   : self.extract_forms(soup, current_url),
            'links'   : self.extract_links(soup, current_url),
            'inputs'  : self.extract_inputs(soup),
            'title'   : self.extract_title(soup),
            'comments': self.extract_comments(soup),
        }

    # ── Extract all forms ─────────────────────────────────────
    def extract_forms(self, soup: BeautifulSoup,
                      current_url: str) -> list:
        """Extract all HTML forms with their inputs and action URLs."""
        forms = []

        for form in soup.find_all('form'):
            # Get form action URL
            action = form.get('action', '')
            if not action:
                action = current_url
            else:
                action = urljoin(current_url, action)

            # Get form method
            method = form.get('method', 'get').lower()

            # Extract all input fields
            inputs = []
            for tag in form.find_all(['input', 'textarea', 'select']):
                field = {
                    'name'    : tag.get('name', ''),
                    'type'    : tag.get('type', 'text'),
                    'value'   : tag.get('value', ''),
                    'required': tag.has_attr('required'),
                    'id'      : tag.get('id', ''),
                }
                # Only include fields with a name attribute
                if field['name']:
                    inputs.append(field)

            # Check for CSRF token
            has_csrf_token = any(
                inp['name'].lower() in [
                    'csrf_token', 'csrf', '_token',
                    'token', 'authenticity_token',
                    '_csrf_token', 'csrfmiddlewaretoken'
                ]
                for inp in inputs
            )

            forms.append({
                'action'         : action,
                'method'         : method,
                'inputs'         : inputs,
                'input_count'    : len(inputs),
                'has_csrf_token' : has_csrf_token,
                'raw'            : str(form)[:200],
            })

        return forms

    # ── Extract all links ─────────────────────────────────────
    def extract_links(self, soup: BeautifulSoup,
                      current_url: str) -> list:
        """Extract all hyperlinks, filtering to same domain only."""
        links = []
        seen  = set()

        for tag in soup.find_all('a', href=True):
            href = tag.get('href', '').strip()

            # Skip empty, javascript and anchor links
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue

            # Build absolute URL
            absolute = urljoin(current_url, href)

            # Remove fragment
            absolute = absolute.split('#')[0]

            # Only follow links on the same domain
            parsed = urlparse(absolute)
            if parsed.netloc and parsed.netloc != self.base_domain:
                continue

            # Only HTTP/HTTPS
            if parsed.scheme not in ('http', 'https'):
                continue

            if absolute not in seen:
                seen.add(absolute)
                links.append({
                    'url'  : absolute,
                    'text' : tag.get_text(strip=True)[:50],
                })

        return links

    # ── Extract standalone inputs ─────────────────────────────
    def extract_inputs(self, soup: BeautifulSoup) -> list:
        """Extract all input fields on the page (not just in forms)."""
        inputs = []
        for tag in soup.find_all(['input', 'textarea']):
            name = tag.get('name', '')
            if name:
                inputs.append({
                    'name' : name,
                    'type' : tag.get('type', 'text'),
                    'id'   : tag.get('id', ''),
                })
        return inputs

    # ── Extract page title ────────────────────────────────────
    def extract_title(self, soup: BeautifulSoup) -> str:
        title = soup.find('title')
        return title.get_text(strip=True) if title else 'No title'

    # ── Extract HTML comments ─────────────────────────────────
    def extract_comments(self, soup: BeautifulSoup) -> list:
        """Extract HTML comments — sometimes contain sensitive info."""
        from bs4 import Comment
        return [
            str(comment).strip()
            for comment in soup.find_all(string=lambda t: isinstance(t, Comment))
            if len(str(comment).strip()) > 3
        ]

    # ── Check if URL is same domain ───────────────────────────
    def is_same_domain(self, url: str) -> bool:
        return urlparse(url).netloc == self.base_domain


# ── Standalone test ───────────────────────────────────────────
if __name__ == '__main__':
    print(f'\n{"="*55}')
    print('  🔍 Testing HTML Parser')
    print(f'{"="*55}\n')

    # Sample HTML to parse
    sample_html = """
    <html>
    <head><title>Test Login Page</title></head>
    <body>
        <!-- Login form for testing -->
        <form action="/login" method="POST">
            <input type="text"     name="username" required>
            <input type="password" name="password" required>
            <input type="hidden"   name="redirect" value="/dashboard">
            <button type="submit">Login</button>
        </form>
        <form action="/search" method="GET">
            <input type="text" name="q" placeholder="Search...">
            <input type="submit" value="Search">
        </form>
        <a href="/about">About</a>
        <a href="/contact">Contact</a>
        <a href="https://external.com">External</a>
        <a href="mailto:test@test.com">Email</a>
    </body>
    </html>
    """

    parser = HTMLParser('http://testsite.local')
    result = parser.parse(sample_html, 'http://testsite.local/login')

    print(f'📄 Page title: {result["title"]}')
    print(f'\n📋 Forms found: {len(result["forms"])}')
    for i, form in enumerate(result['forms'], 1):
        print(f'\n   Form {i}:')
        print(f'   Action:          {form["action"]}')
        print(f'   Method:          {form["method"].upper()}')
        print(f'   Inputs:          {form["input_count"]}')
        print(f'   Has CSRF token:  {form["has_csrf_token"]}')
        for inp in form['inputs']:
            print(f'   Field: [{inp["type"]}] name="{inp["name"]}"')

    print(f'\n🔗 Links found: {len(result["links"])}')
    for link in result['links']:
        print(f'   {link["url"]} — "{link["text"]}"')

    print(f'\n💬 Comments found: {len(result["comments"])}')
    for comment in result['comments']:
        print(f'   {comment}')

    print(f'\n{"="*55}')
    print('  ✅ HTML Parser tests complete!')
    print(f'{"="*55}\n')