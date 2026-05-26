# ============================================================
#  CloudScan – Application Configuration
#  File: config/config.py
# ============================================================

import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# ── Database ──────────────────────────────────────────────────
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_USER = os.getenv('DB_USER', 'root')
DB_PASS = os.getenv('DB_PASS', '')
DB_NAME = os.getenv('DB_NAME', 'cloudscan')
DB_PORT = int(os.getenv('DB_PORT', 3306))

# ── Email ──────────────────────────────────────────────────────
SMTP_HOST   = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT   = int(os.getenv('SMTP_PORT', 587))
SMTP_USER   = os.getenv('SMTP_USER', '')
SMTP_PASS   = os.getenv('SMTP_PASS', '')
ALERT_EMAIL = os.getenv('ALERT_EMAIL', '')

# ── App ────────────────────────────────────────────────────────
APP_NAME       = os.getenv('APP_NAME', 'CloudScan')
APP_VERSION    = os.getenv('APP_VERSION', '1.0.0')
APP_ENV        = os.getenv('APP_ENV', 'development')
REPORTS_FOLDER = os.getenv('REPORTS_FOLDER', 'storage/reports')
LOG_FILE       = os.getenv('LOG_FILE', 'logs/activity.log')

# ── Scanner Settings ───────────────────────────────────────────
SCAN_TIMEOUT    = 10
SCAN_MAX_DEPTH  = 3
SCAN_RATE_LIMIT = 1
SCAN_MAX_URLS   = 50
SCAN_USER_AGENT = 'CloudScan Security Scanner 1.0 (Educational Project)'

# ── Severity Levels ────────────────────────────────────────────
SEVERITY_LEVELS = {
    'critical' : {'color': '#dc2626', 'cvss_min': 9.0},
    'high'     : {'color': '#ea580c', 'cvss_min': 7.0},
    'medium'   : {'color': '#d97706', 'cvss_min': 4.0},
    'low'      : {'color': '#65a30d', 'cvss_min': 0.1},
    'info'     : {'color': '#0284c7', 'cvss_min': 0.0},
}

# ── Validate and initialize ────────────────────────────────────
def validate():
    print(f'\n{"="*50}')
    print(f'  {APP_NAME} v{APP_VERSION}')
    print(f'  Environment: {APP_ENV}')
    print(f'{"="*50}')

    checks = {
        'Database host'  : DB_HOST,
        'Database name'  : DB_NAME,
        'Reports folder' : REPORTS_FOLDER,
    }

    for name, value in checks.items():
        if value:
            print(f'  ✅ {name}: {value}')
        else:
            print(f'  ❌ {name}: NOT SET')

    # Create folders if they do not exist
    os.makedirs(REPORTS_FOLDER, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    print(f'  📁 Reports folder ready: {REPORTS_FOLDER}')
    print(f'  📁 Logs folder ready: {os.path.dirname(LOG_FILE)}')
    print(f'{"="*50}\n')


if __name__ == '__main__':
    validate()