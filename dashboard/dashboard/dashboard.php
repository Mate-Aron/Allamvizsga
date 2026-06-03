<?php
session_start();
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/whitelist.php';
require_once __DIR__ . '/includes/actions.php';

// Bejelentkezés kezelése HTTP Basic Auth segítségével
if (empty($_SERVER['PHP_AUTH_USER']) && !empty($_SERVER['HTTP_AUTHORIZATION'])) {
    $auth = $_SERVER['HTTP_AUTHORIZATION'];
    
    if (str_starts_with(strtolower($auth), 'basic ')) {
        $decoded = base64_decode(substr($auth, 6));
        [$user, $pass] = explode(':', $decoded, 2);
        $_SERVER['PHP_AUTH_USER'] = $user;
        $_SERVER['PHP_AUTH_PW']   = $pass ?? '';
    }
}

$provided_user = $_SERVER['PHP_AUTH_USER'] ?? null;
$provided_pw   = $_SERVER['PHP_AUTH_PW'] ?? null;

if (!$provided_user || $provided_user !== $BASIC_AUTH_USER || !password_verify($provided_pw, $BASIC_AUTH_PASS_HASH)) {
    header('WWW-Authenticate: Basic realm="ModSecurity Dashboard"');
    header('HTTP/1.0 401 Unauthorized');
    die('<h1>Access Denied</h1><p>Please log in to access the dashboard.</p>');
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Itt adjuk át a config.php-ből érkező változót a függvénynek
$action_result = handle_post_action($WHITELIST_FILE);

$page = $_GET['page'] ?? 'logs';
$allowed_pages = ['logs', 'rules', 'edit_rule', 'analytics', 'testing'];
if (!in_array($page, $allowed_pages)) {
    $page = 'logs';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ModSec Dashboard</title>
    <link rel="stylesheet" href="style.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
</head>
<body>
<div class="top-navbar"></div>
<div class="dashboard-container">
    <aside class="sidebar">
        <div class="brand"><h2>Admin Panel</h2></div>
        <nav>
            <ul>
                <li><a href="?page=logs"      class="nav-link <?= $page === 'logs'      ? 'active' : '' ?>">Audit Logs</a></li>
                <li><a href="?page=rules"     class="nav-link <?= $page === 'rules'     ? 'active' : '' ?>">Rules</a></li>
                <li><a href="?page=edit_rule" class="nav-link <?= $page === 'edit_rule' ? 'active' : '' ?>">Edit Rule</a></li>
                <li><a href="?page=testing"   class="nav-link <?= $page === 'testing'   ? 'active' : '' ?>">Testing Console</a></li>
                <li><a href="?page=analytics" class="nav-link <?= $page === 'analytics' ? 'active' : '' ?>">Analytics</a></li>
            </ul>
        </nav>
        <div class="user-info">
            Logged in as: <strong><?= h($provided_user) ?></strong>
        </div>
    </aside>
    <main class="main-content">
        <?php if (is_array($action_result)): ?>
            <div id="flash-message" class="flash-alert flash-<?= h($action_result['status']) ?>">
                <?= h($action_result['msg']) ?>
            </div>
        <?php endif; ?>

        <?php require_once __DIR__ . '/pages/' . $page . '.php'; ?>
    </main>
</div> 

<script>
document.addEventListener("DOMContentLoaded", function() {
    const flashMessage = document.getElementById('flash-message');
    
    if (flashMessage) {
        setTimeout(() => {
            flashMessage.style.opacity = '0';
            setTimeout(() => {
                flashMessage.remove();
            }, 500);
        }, 2000);
    }
});
</script>

</body>
</html>