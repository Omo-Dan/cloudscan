-- ============================================================
--  CloudScan – Complete Database Schema
--  Database: cloudscan
-- ============================================================

USE cloudscan;

-- ── SCANS ─────────────────────────────────────────────────────
-- Stores every scan job that has been run
CREATE TABLE IF NOT EXISTS scans (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  target_url      VARCHAR(500)  NOT NULL,
  status          ENUM('queued','running','completed','failed')
                  DEFAULT 'queued',
  scan_depth      INT DEFAULT 3,
  started_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  completed_at    TIMESTAMP NULL,
  duration_secs   INT DEFAULT 0,
  total_urls      INT DEFAULT 0,
  total_forms     INT DEFAULT 0,
  total_vulns     INT DEFAULT 0,
  critical_count  INT DEFAULT 0,
  high_count      INT DEFAULT 0,
  medium_count    INT DEFAULT 0,
  low_count       INT DEFAULT 0,
  info_count      INT DEFAULT 0,
  report_path     VARCHAR(1000) NULL,
  notes           TEXT NULL
) ENGINE=InnoDB;

-- ── FINDINGS ──────────────────────────────────────────────────
-- Stores every individual vulnerability found
CREATE TABLE IF NOT EXISTS findings (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  scan_id         INT UNSIGNED  NOT NULL,
  vuln_type       VARCHAR(100)  NOT NULL,
  severity        ENUM('critical','high','medium','low','info')
                  NOT NULL DEFAULT 'info',
  url_affected    VARCHAR(500)  NOT NULL,
  parameter       VARCHAR(200)  NULL,
  payload_used    TEXT          NULL,
  evidence        TEXT          NULL,
  description     TEXT          NOT NULL,
  recommendation  TEXT          NOT NULL,
  cvss_score      DECIMAL(3,1)  DEFAULT 0.0,
  owasp_category  VARCHAR(100)  NULL,
  is_confirmed    TINYINT(1)    DEFAULT 1,
  created_at      TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (scan_id)
    REFERENCES scans(id)
    ON DELETE CASCADE
) ENGINE=InnoDB;

-- ── ALERT CONFIGS ─────────────────────────────────────────────
-- Stores email alert settings
CREATE TABLE IF NOT EXISTS alert_configs (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email           VARCHAR(200)  NOT NULL,
  alert_on        SET('critical','high','medium','low')
                  DEFAULT 'critical,high',
  is_active       TINYINT(1)    DEFAULT 1,
  created_at      TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP     DEFAULT CURRENT_TIMESTAMP
                  ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ── SCAN TARGETS ──────────────────────────────────────────────
-- Stores saved targets for scheduled scanning
CREATE TABLE IF NOT EXISTS scan_targets (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name            VARCHAR(200)  NOT NULL,
  url             VARCHAR(500)  NOT NULL,
  schedule        ENUM('manual','daily','weekly')
                  DEFAULT 'manual',
  last_scanned    TIMESTAMP     NULL,
  is_active       TINYINT(1)    DEFAULT 1,
  created_at      TIMESTAMP     DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ── SCAN METRICS ──────────────────────────────────────────────
-- Stores daily summary stats for dashboard charts
CREATE TABLE IF NOT EXISTS scan_metrics (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  metric_date     DATE          NOT NULL UNIQUE,
  total_scans     INT           DEFAULT 0,
  total_vulns     INT           DEFAULT 0,
  critical_vulns  INT           DEFAULT 0,
  high_vulns      INT           DEFAULT 0,
  medium_vulns    INT           DEFAULT 0,
  low_vulns       INT           DEFAULT 0,
  targets_scanned INT           DEFAULT 0,
  avg_scan_time   INT           DEFAULT 0
) ENGINE=InnoDB;

-- ── ACTIVITY LOGS ─────────────────────────────────────────────
-- Stores all scanner activity (replaces AWS CloudTrail)
CREATE TABLE IF NOT EXISTS activity_logs (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  action          VARCHAR(100)  NOT NULL,
  details         TEXT          NULL,
  scan_id         INT UNSIGNED  NULL,
  ip_address      VARCHAR(45)   NULL,
  created_at      TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (scan_id)
    REFERENCES scans(id)
    ON DELETE SET NULL
) ENGINE=InnoDB;

-- ── SAMPLE DATA ───────────────────────────────────────────────
-- Insert a default alert config
INSERT INTO alert_configs (email, alert_on, is_active)
VALUES ('admin@cloudscan.local', 'critical,high', 1);

-- Insert a sample scan target
INSERT INTO scan_targets (name, url, schedule)
VALUES ('DVWA Local', 'http://localhost/dvwa', 'manual');

-- Insert sample metric for today
INSERT INTO scan_metrics (metric_date, total_scans, total_vulns)
VALUES (CURDATE(), 0, 0);