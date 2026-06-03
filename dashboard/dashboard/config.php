<?php
$AUDIT_LOG           = '/var/log/httpd/modsec_audit.log';
$RULES_DIR_ACTIVATED = '/etc/httpd/modsecurity.d/activated_rules';
$RULES_DIR_LOCAL     = '/etc/httpd/modsecurity.d/local_rules';
$WHITELIST_FILE      = '/etc/httpd/modsecurity.d/whitelist.conf';


$INFRA_RULES = [949110, 980130, 949100, 959100];

// Generate password: php -r "echo password_hash('your_password', PASSWORD_DEFAULT);"
$BASIC_AUTH_USER = 'WafAdministrator';
$BASIC_AUTH_PASS_HASH = '$2y$12$ljmwwv8wyzaUtOaJ7HSxl.JW5tmnKcCj7HP6FNA9KVjIX49dgkwFK'; // Erosebb jelszó

define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'modsec_db');
define('DB_USER', 'mate');
define('DB_PASS', 'Admin123!');

try {
    $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

?>