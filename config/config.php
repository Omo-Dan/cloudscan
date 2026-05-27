<?php
// ============================================================
//  CloudScan – PHP Database Configuration
//  File: config/config.php
// ============================================================

// ── Database Settings ─────────────────────────────────────────
define('DB_HOST',    'localhost');
define('DB_USER',    'root');
define('DB_PASS',    '');
define('DB_NAME',    'cloudscan');
define('DB_PORT',    3306);
define('DB_CHARSET', 'utf8mb4');

// ── App Settings ──────────────────────────────────────────────
define('APP_NAME',    'CloudScan');
define('APP_VERSION', '1.0.0');
define('APP_ENV',     'development');
define('REPORTS_DIR', __DIR__ . '/../storage/reports/');

// ── PDO Database Connection ───────────────────────────────────
function getDB(): PDO {
    static $pdo = null;

    if ($pdo === null) {
        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=%s',
            DB_HOST, DB_PORT, DB_NAME, DB_CHARSET
        );
        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]);
        } catch (PDOException $e) {
            die(json_encode([
                'error'   => true,
                'message' => 'Database connection failed',
                'detail'  => $e->getMessage(),
            ]));
        }
    }
    return $pdo;
}

// ── Helper Functions ──────────────────────────────────────────
function clean(string $s): string {
    return htmlspecialchars(strip_tags(trim($s)), ENT_QUOTES, 'UTF-8');
}

function jsonResponse(array $data, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

function timeAgo(string $datetime): string {
    $time = time() - strtotime($datetime);
    if ($time < 60)     return $time . ' seconds ago';
    if ($time < 3600)   return round($time/60) . ' minutes ago';
    if ($time < 86400)  return round($time/3600) . ' hours ago';
    return round($time/86400) . ' days ago';
}

function severityBadge(string $severity): string {
    $colors = [
        'critical' => '#dc2626',
        'high'     => '#ea580c',
        'medium'   => '#d97706',
        'low'      => '#65a30d',
        'info'     => '#0284c7',
    ];
    $color = $colors[$severity] ?? '#64748b';
    return sprintf(
        '<span style="background:%s;color:white;padding:2px 8px;
                border-radius:4px;font-size:11px;font-weight:700;">%s</span>',
        $color,
        strtoupper($severity)
    );
}