# ============================================================
#  CloudScan – Main Scanner Orchestrator
#  File: scanner/main_scanner.py
#
#  Ties all detection modules together into one complete scan.
#  Crawl → SQLi → XSS → CSRF → Headers → Save → Report
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from datetime import datetime
from colorama import Fore, Style, init

from scanner.http_engine    import HTTPEngine
from scanner.crawler        import Crawler
from scanner.sqli_detector  import SQLiDetector
from scanner.xss_detector   import XSSDetector
from scanner.csrf_detector  import CSRFDetector
from scanner.header_checker import HeaderChecker
from database.db_handler    import DatabaseHandler

init(autoreset=True)


class MainScanner:

    def __init__(self):
        self.http     = HTTPEngine()
        self.crawler  = Crawler(http_engine=self.http)
        self.sqli     = SQLiDetector(http_engine=self.http)
        self.xss      = XSSDetector(http_engine=self.http)
        self.csrf     = CSRFDetector(http_engine=self.http)
        self.headers  = HeaderChecker(http_engine=self.http)
        self.db       = DatabaseHandler()
        self.scan_id  = None

    # ── Main entry point ──────────────────────────────────────
    def scan(self, target_url: str, scan_depth: int = 3) -> dict:
        """
        Run a complete vulnerability scan on a target URL.
        Returns a full results dictionary.
        """
        start_time = time.time()

        self._print_banner(target_url)

        # ── Step 1: Create scan record in database ────────────
        self.scan_id = self.db.create_scan(target_url, scan_depth)
        self.db.update_scan_status(self.scan_id, 'running')
        self.db.log_activity(
            'SCAN_STARTED',
            f'Scan started on {target_url}',
            scan_id = self.scan_id
        )

        all_findings = []

        try:
            # ── Step 2: Crawl the target ──────────────────────
            self._print_step(1, 'Crawling target website')
            crawl_result = self.crawler.crawl(
                target_url,
                max_depth = scan_depth,
                max_urls  = 30
            )

            if not crawl_result['success']:
                self._handle_failed_scan('Target not reachable')
                return self._build_result(
                    target_url, all_findings,
                    crawl_result, start_time, success=False
                )

            pages = crawl_result['pages']
            forms = crawl_result['forms']

            print(f'\n{Fore.GREEN}  ✅ Crawl complete: '
                  f'{len(pages)} pages, {len(forms)} forms{Style.RESET_ALL}')

            # ── Step 3: SQL Injection scan ────────────────────
            self._print_step(2, 'Testing for SQL Injection')
            sqli_findings = self.sqli.scan(pages=pages, forms=forms)
            all_findings.extend(sqli_findings)
            self._save_findings(sqli_findings)
            print(f'{Fore.GREEN}  ✅ SQLi scan complete: '
                  f'{len(sqli_findings)} finding(s){Style.RESET_ALL}')

            # ── Step 4: XSS scan ──────────────────────────────
            self._print_step(3, 'Testing for Cross-Site Scripting (XSS)')
            xss_findings = self.xss.scan(pages=pages, forms=forms)
            all_findings.extend(xss_findings)
            self._save_findings(xss_findings)
            print(f'{Fore.GREEN}  ✅ XSS scan complete: '
                  f'{len(xss_findings)} finding(s){Style.RESET_ALL}')

            # ── Step 5: CSRF check ────────────────────────────
            self._print_step(4, 'Checking for CSRF vulnerabilities')
            csrf_findings = self.csrf.scan(pages=pages, forms=forms)
            all_findings.extend(csrf_findings)
            self._save_findings(csrf_findings)
            print(f'{Fore.GREEN}  ✅ CSRF check complete: '
                  f'{len(csrf_findings)} finding(s){Style.RESET_ALL}')

            # ── Step 6: Security headers check ───────────────
            self._print_step(5, 'Checking security headers')
            header_findings = self.headers.scan(pages=pages, forms=forms)
            all_findings.extend(header_findings)
            self._save_findings(header_findings)
            print(f'{Fore.GREEN}  ✅ Headers check complete: '
                  f'{len(header_findings)} finding(s){Style.RESET_ALL}')

        except Exception as e:
            self._handle_failed_scan(str(e))
            raise

        # ── Step 7: Calculate stats ───────────────────────────
        duration = round(time.time() - start_time)
        stats    = self._calculate_stats(all_findings, crawl_result, duration)

        # ── Step 8: Save completed scan to database ───────────
        self.db.complete_scan(self.scan_id, stats)
        self.db.update_daily_metrics(stats)
        self.db.log_activity(
            'SCAN_COMPLETED',
            f'Found {len(all_findings)} vulnerabilities in {duration}s',
            scan_id = self.scan_id
        )

        # ── Step 9: Build and return final results ────────────
        result = self._build_result(
            target_url, all_findings,
            crawl_result, start_time, success=True
        )

        self._print_final_report(result)
        return result

    # ── Save findings to database ─────────────────────────────
    def _save_findings(self, findings: list):
        """Save a batch of findings to the database."""
        for finding in findings:
            self.db.save_finding(self.scan_id, finding)

    # ── Calculate scan statistics ─────────────────────────────
    def _calculate_stats(self, findings: list,
                         crawl_result: dict,
                         duration: int) -> dict:
        """Calculate summary statistics from scan results."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 'info')
            counts[sev] = counts.get(sev, 0) + 1

        return {
            'duration_secs'  : duration,
            'total_urls'     : crawl_result['stats']['total_urls'],
            'total_forms'    : crawl_result['stats']['total_forms'],
            'total_vulns'    : len(findings),
            'critical_count' : counts['critical'],
            'high_count'     : counts['high'],
            'medium_count'   : counts['medium'],
            'low_count'      : counts['low'],
            'info_count'     : counts['info'],
            'total_scans'    : 1,
            'critical_vulns' : counts['critical'],
            'high_vulns'     : counts['high'],
            'medium_vulns'   : counts['medium'],
            'low_vulns'      : counts['low'],
            'targets_scanned': 1,
            'avg_scan_time'  : duration,
            'report_path'    : None,
        }

    # ── Handle failed scan ────────────────────────────────────
    def _handle_failed_scan(self, reason: str):
        """Mark scan as failed in the database."""
        if self.scan_id:
            self.db.fail_scan(self.scan_id, reason)
            self.db.log_activity(
                'SCAN_FAILED',
                f'Scan failed: {reason}',
                scan_id = self.scan_id
            )
        print(f'\n{Fore.RED}❌ Scan failed: {reason}{Style.RESET_ALL}')

    # ── Build final result dictionary ─────────────────────────
    def _build_result(self, target_url: str, findings: list,
                      crawl_result: dict, start_time: float,
                      success: bool) -> dict:
        """Build the final result dictionary."""
        duration = round(time.time() - start_time)

        # Group findings by severity
        by_severity = {
            'critical' : [],
            'high'     : [],
            'medium'   : [],
            'low'      : [],
            'info'     : [],
        }
        for f in findings:
            sev = f.get('severity', 'info')
            by_severity[sev].append(f)

        # Group findings by type
        by_type = {}
        for f in findings:
            ftype = f.get('type', 'Unknown')
            if ftype not in by_type:
                by_type[ftype] = []
            by_type[ftype].append(f)

        return {
            'scan_id'      : self.scan_id,
            'target_url'   : target_url,
            'success'      : success,
            'timestamp'    : datetime.now().isoformat(),
            'duration_secs': duration,
            'crawl'        : crawl_result.get('stats', {}),
            'findings'     : findings,
            'by_severity'  : by_severity,
            'by_type'      : by_type,
            'stats'        : {
                'total'    : len(findings),
                'critical' : len(by_severity['critical']),
                'high'     : len(by_severity['high']),
                'medium'   : len(by_severity['medium']),
                'low'      : len(by_severity['low']),
                'info'     : len(by_severity['info']),
            },
        }

    # ── Print helpers ─────────────────────────────────────────
    def _print_banner(self, target_url: str):
        print(f'\n{Fore.CYAN}{"="*60}')
        print(f'  🔍 CloudScan — Web Vulnerability Scanner')
        print(f'  Target : {target_url}')
        print(f'  Started: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        print(f'{"="*60}{Style.RESET_ALL}\n')

    def _print_step(self, step_num: int, description: str):
        print(f'\n{Fore.CYAN}[Step {step_num}/5] {description}...{Style.RESET_ALL}')

    def _print_final_report(self, result: dict):
        stats = result['stats']
        print(f'\n{Fore.CYAN}{"="*60}')
        print(f'  ✅ SCAN COMPLETE')
        print(f'{"="*60}')
        print(f'  Target     : {result["target_url"]}')
        print(f'  Scan ID    : {result["scan_id"]}')
        print(f'  Duration   : {result["duration_secs"]}s')
        print(f'  Pages      : {result["crawl"].get("total_pages", 0)}')
        print(f'  Forms      : {result["crawl"].get("total_forms", 0)}')
        print(f'{"="*60}')
        print(f'  VULNERABILITIES FOUND: {stats["total"]}')
        print(f'{"="*60}')

        if stats['critical'] > 0:
            print(f'  {Fore.RED}🔴 Critical : {stats["critical"]}{Style.RESET_ALL}')
        if stats['high'] > 0:
            print(f'  {Fore.YELLOW}🟠 High     : {stats["high"]}{Style.RESET_ALL}')
        if stats['medium'] > 0:
            print(f'  {Fore.YELLOW}🟡 Medium   : {stats["medium"]}{Style.RESET_ALL}')
        if stats['low'] > 0:
            print(f'  {Fore.GREEN}🟢 Low      : {stats["low"]}{Style.RESET_ALL}')
        if stats['info'] > 0:
            print(f'  {Fore.CYAN}ℹ️  Info     : {stats["info"]}{Style.RESET_ALL}')

        if stats['total'] == 0:
            print(f'  {Fore.GREEN}✅ No vulnerabilities found{Style.RESET_ALL}')

        print(f'{Fore.CYAN}{"="*60}{Style.RESET_ALL}')

        # List all findings
        if result['findings']:
            print(f'\n{Fore.WHITE}  FINDINGS DETAIL:')
            print(f'  {"─"*56}{Style.RESET_ALL}')
            for i, f in enumerate(result['findings'], 1):
                sev   = f['severity']
                color = {
                    'critical' : Fore.RED,
                    'high'     : Fore.YELLOW,
                    'medium'   : Fore.YELLOW,
                    'low'      : Fore.GREEN,
                    'info'     : Fore.CYAN,
                }.get(sev, Fore.WHITE)

                print(f'  {color}[{i}] [{sev.upper()}] {f["type"]}{Style.RESET_ALL}')
                print(f'      URL      : {f["url"][:60]}')
                print(f'      Parameter: {f["parameter"]}')
                print(f'      CVSS     : {f["cvss"]}')
                print()


# ── Entry point ───────────────────────────────────────────────
if __name__ == '__main__':
    import sys

    # Get target from command line or use default test target
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://httpbin.org'

    print(f'\n{"="*60}')
    print(f'  🔍 CloudScan Main Scanner Test')
    print(f'{"="*60}\n')

    scanner = MainScanner()
    result  = scanner.scan(target, scan_depth=1)

    print(f'\n📊 Final result summary:')
    print(f'   Scan ID  : {result["scan_id"]}')
    print(f'   Success  : {result["success"]}')
    print(f'   Findings : {result["stats"]["total"]}')
    print(f'   Duration : {result["duration_secs"]}s')