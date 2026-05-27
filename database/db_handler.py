# ============================================================
#  CloudScan – MySQL Database Handler
#  File: database/db_handler.py
#
#  Handles all database operations for the scanner.
#  Uses PyMySQL to connect to XAMPP MySQL.
# ============================================================

import pymysql
import pymysql.cursors
from datetime import datetime
from config.config import (
    DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT
)


class DatabaseHandler:

    def __init__(self):
        self.connection = None
        self.connect()

    # ── Connection ────────────────────────────────────────────
    def connect(self):
        try:
            self.connection = pymysql.connect(
                host     = DB_HOST,
                user     = DB_USER,
                password = DB_PASS,
                database = DB_NAME,
                port     = DB_PORT,
                charset  = 'utf8mb4',
                cursorclass = pymysql.cursors.DictCursor,
                autocommit  = True
            )
            print(f'✅ Database connected: {DB_NAME}@{DB_HOST}')
        except pymysql.Error as e:
            print(f'❌ Database connection failed: {e}')
            self.connection = None

    def disconnect(self):
        if self.connection:
            self.connection.close()
            print('📴 Database disconnected')

    def is_connected(self):
        if not self.connection:
            return False
        try:
            self.connection.ping(reconnect=True)
            return True
        except:
            return False

    # ── Scans ─────────────────────────────────────────────────
    def create_scan(self, target_url: str, scan_depth: int = 3) -> int:
        """Create a new scan record and return its ID."""
        sql = """
            INSERT INTO scans (target_url, status, scan_depth, started_at)
            VALUES (%s, 'queued', %s, %s)
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (target_url, scan_depth, datetime.now()))
            scan_id = cursor.lastrowid
            print(f'📋 Scan created: ID={scan_id} Target={target_url}')
            return scan_id

    def update_scan_status(self, scan_id: int, status: str):
        """Update the status of a scan."""
        sql = "UPDATE scans SET status = %s WHERE id = %s"
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (status, scan_id))

    def complete_scan(self, scan_id: int, stats: dict):
        """Mark a scan as completed and save final statistics."""
        sql = """
            UPDATE scans SET
                status         = 'completed',
                completed_at   = %s,
                duration_secs  = %s,
                total_urls     = %s,
                total_forms    = %s,
                total_vulns    = %s,
                critical_count = %s,
                high_count     = %s,
                medium_count   = %s,
                low_count      = %s,
                info_count     = %s,
                report_path    = %s
            WHERE id = %s
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (
                datetime.now(),
                stats.get('duration_secs',  0),
                stats.get('total_urls',     0),
                stats.get('total_forms',    0),
                stats.get('total_vulns',    0),
                stats.get('critical_count', 0),
                stats.get('high_count',     0),
                stats.get('medium_count',   0),
                stats.get('low_count',      0),
                stats.get('info_count',     0),
                stats.get('report_path',    None),
                scan_id
            ))
        print(f'✅ Scan {scan_id} completed: {stats.get("total_vulns", 0)} vulnerabilities found')

    def fail_scan(self, scan_id: int, reason: str = ''):
        """Mark a scan as failed."""
        sql = """
            UPDATE scans
            SET status = 'failed', completed_at = %s, notes = %s
            WHERE id = %s
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (datetime.now(), reason, scan_id))

    def get_scan(self, scan_id: int) -> dict:
        """Get a single scan by ID."""
        sql = "SELECT * FROM scans WHERE id = %s"
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (scan_id,))
            return cursor.fetchone()

    def get_all_scans(self, limit: int = 50) -> list:
        """Get all scans ordered by most recent first."""
        sql = "SELECT * FROM scans ORDER BY started_at DESC LIMIT %s"
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (limit,))
            return cursor.fetchall()

    def get_recent_scans(self, limit: int = 5) -> list:
        """Get the most recent scans for dashboard."""
        sql = """
            SELECT id, target_url, status, total_vulns,
                   critical_count, started_at, completed_at
            FROM scans
            ORDER BY started_at DESC
            LIMIT %s
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (limit,))
            return cursor.fetchall()

    # ── Findings ──────────────────────────────────────────────
    def save_finding(self, scan_id: int, finding: dict) -> int:
        """Save a single vulnerability finding."""
        sql = """
            INSERT INTO findings (
                scan_id, vuln_type, severity, url_affected,
                parameter, payload_used, evidence, description,
                recommendation, cvss_score, owasp_category
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (
                scan_id,
                finding.get('type',           'Unknown'),
                finding.get('severity',        'info'),
                finding.get('url',             ''),
                finding.get('parameter',       ''),
                finding.get('payload',         ''),
                finding.get('evidence',        ''),
                finding.get('description',     ''),
                finding.get('recommendation',  ''),
                finding.get('cvss',            0.0),
                finding.get('owasp',           ''),
            ))
            return cursor.lastrowid

    def save_findings_bulk(self, scan_id: int, findings: list) -> int:
        """Save multiple findings at once. Returns count saved."""
        if not findings:
            return 0
        count = 0
        for finding in findings:
            self.save_finding(scan_id, finding)
            count += 1
        print(f'💾 Saved {count} findings for scan {scan_id}')
        return count

    def get_findings(self, scan_id: int) -> list:
        """Get all findings for a scan."""
        sql = """
            SELECT * FROM findings
            WHERE scan_id = %s
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high'     THEN 2
                    WHEN 'medium'   THEN 3
                    WHEN 'low'      THEN 4
                    WHEN 'info'     THEN 5
                END,
                cvss_score DESC
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (scan_id,))
            return cursor.fetchall()

    def get_findings_by_severity(self, scan_id: int, severity: str) -> list:
        """Get findings filtered by severity."""
        sql = """
            SELECT * FROM findings
            WHERE scan_id = %s AND severity = %s
            ORDER BY cvss_score DESC
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (scan_id, severity))
            return cursor.fetchall()

    # ── Activity Logs ─────────────────────────────────────────
    def log_activity(self, action: str, details: str = '',
                     scan_id: int = None, ip: str = None):
        """Log a scanner activity event."""
        sql = """
            INSERT INTO activity_logs
                (action, details, scan_id, ip_address)
            VALUES (%s, %s, %s, %s)
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (action, details, scan_id, ip))

    def get_activity_logs(self, limit: int = 50) -> list:
        """Get recent activity logs."""
        sql = """
            SELECT * FROM activity_logs
            ORDER BY created_at DESC LIMIT %s
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (limit,))
            return cursor.fetchall()

    # ── Metrics ───────────────────────────────────────────────
    def update_daily_metrics(self, stats: dict):
        """Update or insert today's metrics."""
        sql = """
            INSERT INTO scan_metrics
                (metric_date, total_scans, total_vulns,
                 critical_vulns, high_vulns, medium_vulns,
                 low_vulns, targets_scanned, avg_scan_time)
            VALUES (CURDATE(), %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                total_scans     = total_scans     + VALUES(total_scans),
                total_vulns     = total_vulns     + VALUES(total_vulns),
                critical_vulns  = critical_vulns  + VALUES(critical_vulns),
                high_vulns      = high_vulns      + VALUES(high_vulns),
                medium_vulns    = medium_vulns    + VALUES(medium_vulns),
                low_vulns       = low_vulns       + VALUES(low_vulns),
                targets_scanned = targets_scanned + VALUES(targets_scanned),
                avg_scan_time   = VALUES(avg_scan_time)
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (
                stats.get('total_scans',     1),
                stats.get('total_vulns',     0),
                stats.get('critical_vulns',  0),
                stats.get('high_vulns',      0),
                stats.get('medium_vulns',    0),
                stats.get('low_vulns',       0),
                stats.get('targets_scanned', 1),
                stats.get('avg_scan_time',   0),
            ))

    def get_metrics_last_7_days(self) -> list:
        """Get metrics for the last 7 days for charts."""
        sql = """
            SELECT * FROM scan_metrics
            WHERE metric_date >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
            ORDER BY metric_date ASC
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql)
            return cursor.fetchall()

    def get_dashboard_summary(self) -> dict:
        """Get summary statistics for the dashboard home page."""
        with self.connection.cursor() as cursor:
            # Total scans
            cursor.execute("SELECT COUNT(*) AS cnt FROM scans")
            total_scans = cursor.fetchone()['cnt']

            # Total vulnerabilities
            cursor.execute("SELECT COUNT(*) AS cnt FROM findings")
            total_vulns = cursor.fetchone()['cnt']

            # Critical findings
            cursor.execute(
                "SELECT COUNT(*) AS cnt FROM findings WHERE severity='critical'"
            )
            critical = cursor.fetchone()['cnt']

            # Scans today
            cursor.execute(
                "SELECT COUNT(*) AS cnt FROM scans WHERE DATE(started_at)=CURDATE()"
            )
            today_scans = cursor.fetchone()['cnt']

            # Most recent scan
            cursor.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT 1"
            )
            last_scan = cursor.fetchone()

        return {
            'total_scans'  : total_scans,
            'total_vulns'  : total_vulns,
            'critical'     : critical,
            'today_scans'  : today_scans,
            'last_scan'    : last_scan,
        }

    # ── Alert Configs ─────────────────────────────────────────
    def get_alert_configs(self) -> list:
        """Get all active alert configurations."""
        sql = "SELECT * FROM alert_configs WHERE is_active = 1"
        with self.connection.cursor() as cursor:
            cursor.execute(sql)
            return cursor.fetchall()

    def save_alert_config(self, email: str, alert_on: str) -> int:
        """Save a new alert configuration."""
        sql = """
            INSERT INTO alert_configs (email, alert_on)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE alert_on = VALUES(alert_on)
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (email, alert_on))
            return cursor.lastrowid

    # ── Scan Targets ──────────────────────────────────────────
    def get_scan_targets(self) -> list:
        """Get all saved scan targets."""
        sql = """
            SELECT * FROM scan_targets
            WHERE is_active = 1
            ORDER BY name
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql)
            return cursor.fetchall()

    def save_scan_target(self, name: str, url: str,
                         schedule: str = 'manual') -> int:
        """Save a new scan target."""
        sql = """
            INSERT INTO scan_targets (name, url, schedule)
            VALUES (%s, %s, %s)
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (name, url, schedule))
            return cursor.lastrowid


# ── Standalone test ───────────────────────────────────────────
if __name__ == '__main__':
    print('\n🔍 Testing DatabaseHandler...\n')

    db = DatabaseHandler()

    if not db.is_connected():
        print('❌ Could not connect to database')
        print('   Make sure XAMPP MySQL is running')
        print('   Make sure cloudscan database exists')
        exit(1)

    # Test 1 — Create a scan
    print('\n📋 Test 1: Creating a test scan...')
    scan_id = db.create_scan('http://testsite.local', scan_depth=3)
    print(f'   Scan ID: {scan_id}')

    # Test 2 — Update status
    print('\n🔄 Test 2: Updating scan status to running...')
    db.update_scan_status(scan_id, 'running')
    scan = db.get_scan(scan_id)
    print(f'   Status: {scan["status"]}')

    # Test 3 — Save a finding
    print('\n🐛 Test 3: Saving a test finding...')
    finding = {
        'type'          : 'SQL Injection',
        'severity'      : 'critical',
        'url'           : 'http://testsite.local/login.php',
        'parameter'     : 'username',
        'payload'       : "' OR 1=1--",
        'evidence'      : 'MySQL error in response',
        'description'   : 'SQL Injection vulnerability found in login form',
        'recommendation': 'Use prepared statements and parameterized queries',
        'cvss'          : 9.8,
        'owasp'         : 'A03:2021 - Injection',
    }
    finding_id = db.save_finding(scan_id, finding)
    print(f'   Finding ID: {finding_id}')

    # Test 4 — Complete the scan
    print('\n✅ Test 4: Completing the scan...')
    db.complete_scan(scan_id, {
        'duration_secs'  : 45,
        'total_urls'     : 12,
        'total_forms'    : 4,
        'total_vulns'    : 1,
        'critical_count' : 1,
        'high_count'     : 0,
        'medium_count'   : 0,
        'low_count'      : 0,
        'info_count'     : 0,
        'report_path'    : 'storage/reports/test_report.pdf',
    })

    # Test 5 — Dashboard summary
    print('\n📊 Test 5: Getting dashboard summary...')
    summary = db.get_dashboard_summary()
    print(f'   Total scans:  {summary["total_scans"]}')
    print(f'   Total vulns:  {summary["total_vulns"]}')
    print(f'   Critical:     {summary["critical"]}')

    # Test 6 — Log activity
    print('\n📝 Test 6: Logging activity...')
    db.log_activity(
        'SCAN_COMPLETED',
        f'Scan {scan_id} completed successfully',
        scan_id=scan_id
    )
    logs = db.get_activity_logs(limit=1)
    print(f'   Last log: {logs[0]["action"]} — {logs[0]["details"]}')

    # Test 7 — Get findings
    print('\n🔍 Test 7: Retrieving findings...')
    findings = db.get_findings(scan_id)
    print(f'   Found {len(findings)} finding(s)')
    for f in findings:
        print(f'   [{f["severity"].upper()}] {f["vuln_type"]} on {f["url_affected"]}')

    db.disconnect()
    print('\n' + '='*50)
    print('  ✅ All database tests passed!')
    print('  🚀 DatabaseHandler is ready to use')
    print('='*50 + '\n')