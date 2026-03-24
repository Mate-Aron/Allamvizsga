<?php
session_start();
require_once __DIR__ . '/functions.php';

$provided_user = $_SERVER['PHP_AUTH_USER'] ?? null;
$provided_pw   = $_SERVER['PHP_AUTH_PW'] ?? null;

if (!$provided_user || ($provided_user !== $BASIC_AUTH_USER || !password_verify($provided_pw, $BASIC_AUTH_PASS_HASH))) {
    header('WWW-Authenticate: Basic realm="ModSecurity Dashboard"');
    header('HTTP/1.0 401 Unauthorized');
    die('<h1>Access Denied</h1><p>Please log in to access the dashboard.</p>');
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$action_result = ''; 
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $posted_token = $_POST['csrf_token'] ?? '';
    
    if (empty($posted_token) || !hash_equals($_SESSION['csrf_token'], $posted_token)) {
        $action_result = '<div class="error">Security Error: Invalid CSRF Token. Please refresh the page!</div>';
    } else {
        $action = $_POST['action'] ?? '';
        
        if (!is_writable($WHITELIST_FILE) && !in_array($action, ['save_file'])) {
             $action_result = "<div class='error'>Error: The whitelist file is not writable.<br>$WHITELIST_FILE</div>";
        } else {
            if ($action === 'disable_target') {
                $rid = $_POST['rule_id']; 
                $source_ip = $_POST['source_ip'];
                $unique_id = rand(1000000, 9999999);
                $line = "SecRule REMOTE_ADDR \"@ipMatch $source_ip\" \"id:$unique_id,phase:1,pass,nolog,ctl:ruleRemoveById=$rid\"\n";

                if (atomic_append_file($WHITELIST_FILE, $line)) {
                    $action_result = "<div class='success'>✓ IP $source_ip whitelisted for rule $rid</div>";
                } else {
                    $action_result = "<div class='error'>Save failed. Permission denied.</div>";
                }
                
            } elseif ($action === 'undo_whitelist') {
                $rid = $_POST['rule_id']; 
                $source_ip = $_POST['source_ip'];
                $res = remove_line_from_file($WHITELIST_FILE, [$source_ip, "ruleRemoveById=$rid"]);
                
                if ($res === true) $action_result = "<div class='success'>↩ Whitelist revoked: $source_ip (Rule: $rid). ⚠️ Apache reload required!</div>";
                elseif ($res === false) $action_result = "<div class='error'>Save failed. No write permission?</div>";
                else $action_result = "<div class='error'>This rule is no longer in the whitelist.</div>";
                
            } elseif ($action === 'disable_rule_globally') {
                $rid = $_POST['rule_id']; 
                $line = "SecRuleRemoveById $rid\n";

                if (atomic_append_file($WHITELIST_FILE, $line)) {
                    $action_result = "<div class='success'>🌍 Rule $rid globally disabled! ⚠️ Apache reload required!</div>";
                } else {
                    $action_result = "<div class='error'>Save failed. Permission denied.</div>";
                }

            } elseif ($action === 'undo_global_whitelist') {
                $rid = $_POST['rule_id']; 
                $res = remove_line_from_file($WHITELIST_FILE, ["SecRuleRemoveById $rid"]);
                
                if ($res === true) $action_result = "<div class='success'>↩ Global whitelist revoked (Rule: $rid). ⚠️ Apache reload required!</div>";
                elseif ($res === false) $action_result = "<div class='error'>Save failed. No write permission?</div>";
                else $action_result = "<div class='error'>This rule is not globally whitelisted.</div>";
                
            } elseif ($action === 'save_file') {
                $path = $_POST['file_path'] ?? '';
                $content = $_POST['content'] ?? '';
                if (allowed_local_path(basename($path)) && save_rule_text($path, $content)) {
                    $action_result = "<div class='success'>File saved successfully. Backup created.<br>⚠️ Apache reload required!</div>";              
                } else {
                    $action_result = "<div class='error'>Save failed. Permission error or invalid path.</div>";
                }
                
            } elseif ($action === 'restart_httpd') {
                if (restart_httpd()) {
                    $action_result = "<div class='success'>🔄 Apache reload signal sent!</div>";
                } else {
                    $action_result = "<div class='error'>Failed to send reload signal.</div>";
                }
            }
        }
    }
}

function render_rules_table_local($rules, $is_editable = false) {
    if (empty($rules)) return '<p class="empty-state">No rules found.</p>';
    $html = '<table class="rules-table"><thead><tr><th class="col-id">ID</th><th>Message / Pattern</th><th>File</th>'.($is_editable ? '<th>Action</th>' : '').'</tr></thead><tbody>';
    foreach($rules as $r) {
        $html .= '<tr>';
        $html .= '<td><strong>'.h($r['id'] ?? '-').'</strong></td>';
        $html .= '<td><div class="rule-msg">'.h($r['msg'] ?? 'No Description').'</div><details class="rule-details"><summary>Show Code</summary><code class="rule-code">'.h($r['pattern']).'</code></details></td>';
        $html .= '<td class="file-name">'.h(basename($r['file'])).'</td>';
        if ($is_editable) {
            $html .= '<td>';
            if (allowed_local_path(basename($r['file']))) {
                $html .= '<a href="?page=edit_rule&file='.urlencode(basename($r['file'])).'" class="btn btn-sm">Edit</a>';
            }
            $html .= '</td>';
        }
        $html .= '</tr>';
    }
    $html .= '</tbody></table>';
    return $html;
}

$page = $_GET['page'] ?? 'logs';
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
                <li><a href="?page=logs" class="nav-link <?= $page==='logs'?'active':'' ?>">Audit Logs</a></li>
                <li><a href="?page=rules" class="nav-link <?= $page==='rules'?'active':'' ?>">Rules</a></li>
                <li><a href="?page=edit_rule" class="nav-link <?= $page==='edit_rule'?'active':'' ?>">Edit Rule</a></li>
                <li><a href="?page=testing" class="nav-link <?= $page==='testing'?'active':'' ?>">Testing Console</a></li>
                <li><a href="?page=analytics" class="nav-link <?= $page==='analytics'?'active':'' ?>">Analytics</a></li>         
            </ul>
        </nav>
        <div class="user-info">
            Logged in as: <strong><?= h($provided_user) ?></strong>
        </div>
    </aside>
    <main class="main-content">
        <?= $action_result ?>
        
            <?php switch($page): case 'logs': 
                $search_ip = trim($_GET['search_ip'] ?? '');
                
                $limit = ($search_ip !== '') ? 1000 : $MAX_ENTRIES;
                $raw_logs = parse_modsec_log($AUDIT_LOG, $limit); 
                
                $logs = [];
                
                if ($search_ip !== '') {
                    foreach ($raw_logs as $l) {
                        if (strpos($l['source_ip'], $search_ip) !== false) {
                            $logs[] = $l;
                        }
                    }
                } else {
                    $logs = $raw_logs;
                }
            ?>
            
            <div class="log-container">
                <div class="log-header-top">
                    <h3>Audit Logs</h3>
                        <div class="header-actions">
                            <form method="get" style="display: inline-block; margin-right: 15px;">
                                <input type="hidden" name="page" value="logs">
                                <input type="text" name="search_ip" value="<?= h($search_ip) ?>" placeholder="Search IP (e.g. 45.205...)" style="padding: 4px 8px; border-radius: 4px; border: 1px solid #ccc;">
                                <button type="submit" class="btn btn-primary btn-sm">Filter</button>
                                <?php if ($search_ip !== ''): ?>
                                    <a href="?page=logs" class="btn btn-warning btn-sm">Clear</a>
                                <?php endif; ?>
                            </form>
                            <form method="post" style="display: inline-block;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                <input type="hidden" name="action" value="restart_httpd">
                                <button type="submit" class="btn btn-warning btn-sm" title="Apply whitelist changes">🔄 Restart Apache</button>
                            </form>

                            <label class="auto-refresh-label">
                                <input type="checkbox" id="autoRefresh" checked> 🔴 Live Update
                            </label>
                            <span class="log-source">Source: <?= h(basename($AUDIT_LOG)) ?></span>
                        </div>
                    </div>
            
                <div id="live-logs-wrapper">
                    <?php if (empty($logs)): ?>
                        <div class="info-box">The file is not readable or empty: <code><?= h($AUDIT_LOG) ?></code></div>
                    <?php else: foreach ($logs as $log):
                
                        $is_card_whitelisted = false;
                        foreach ($log['root_cause_ids'] as $rid) {
                            if (is_ip_rule_whitelisted($WHITELIST_FILE, $log['source_ip'], $rid) || is_rule_globally_whitelisted($WHITELIST_FILE, $rid)) {
                                $is_card_whitelisted = true;
                                break; 
                            }
                        }
                        
                        $display_status = $is_card_whitelisted ? 'WHITELISTED' : $log['final_action'];
                        $card_class = $is_card_whitelisted ? 'whitelisted-card' : (($log['final_action'] === 'BLOCKED') ? 'blocked' : 'alert');
                    ?>
                    <div class="log-card <?= $card_class ?>">
                        <div class="log-header">
                            <div class="log-header-info">
                                <span class="log-time">📅 <?= h($log['time']) ?></span>
                                <span class="log-ip">IP: <strong><?= h($log['source_ip']) ?></strong></span>
                                <span class="log-hostname"><?= h($log['hostname']) ?></span>
                            </div>
                            <span class="badge status-<?= strtolower($display_status) ?>"><?= h($display_status) ?></span>
                        </div>
                        <div class="log-body">
                            <div class="log-row"><strong>Attack:</strong> <span class="attack-type"><?= h($log['attack_type']) ?></span></div>
                            <div class="log-row"><strong>Request:</strong> <code class="request-code"><?= h($log['method']) ?> <?= h($log['uri']) ?></code></div>
                            
                            <?php if (!empty($log['root_cause_ids'])): ?>
                                <div class="root-causes">
                                    <strong>Activated Rules:</strong>
                                    <?php foreach ($log['root_cause_ids'] as $rid): 
                                        $details = $log['rule_details'][$rid] ?? [];
                                        $target_val = $details['target'] ?? '';
                                        $severity = $details['severity'] ?? 'NOTICE';
                                        $severityClass = 'severity-' . strtolower($severity);

                                        $is_whitelisted = is_ip_rule_whitelisted($WHITELIST_FILE, $log['source_ip'], $rid);
                                        $is_globally_whitelisted = is_rule_globally_whitelisted($WHITELIST_FILE, $rid);
                                        $is_any_whitelisted = $is_whitelisted || $is_globally_whitelisted;
                                    ?>
                                    <div class="rule-action-row <?= $is_any_whitelisted ? 'whitelisted-row' : '' ?>">
                                        <div class="rule-info">
                                            <div class="rule-badges">
                                                <span class="rule-id">ID: <?= h($rid) ?></span>
                                                <span class="severity-badge <?= h($severityClass) ?>"><?= h($severity) ?></span>
                                                <?php if($target_val): ?><span class="target-badge">Target: <?= h($target_val) ?></span><?php endif; ?>
                                            </div>
                                            <div class="rule-message"><?= h($details['msg']) ?></div>
                                            <?php if (!empty($details['data'])): ?><div class="matched-data-box">Match: "<?= h($details['data']) ?>"</div><?php endif; ?>
                                            <?php if (!empty($details['tags'])): ?>
                                                <div class="tags-container">
                                                    <?php foreach(array_unique($details['tags']) as $tag): ?><span class="tag-item"><?= h($tag) ?></span><?php endforeach; ?>
                                                </div>
                                            <?php endif; ?>
                                        </div>
                                        <div class="action-buttons">
                                            <?php if($is_globally_whitelisted): ?>
                                                <form method="POST">
                                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                                    <input type="hidden" name="action" value="undo_global_whitelist">
                                                    <input type="hidden" name="rule_id" value="<?= h($rid) ?>">
                                                    <button type="submit" class="btn btn-sm btn-danger" title="Re-enable this rule globally">Undo Global</button>
                                                </form>
                                            <?php else: ?>
                                                <form method="POST">
                                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                                    <input type="hidden" name="action" value="disable_rule_globally">
                                                    <input type="hidden" name="rule_id" value="<?= h($rid) ?>">
                                                    <button type="submit" class="btn btn-sm btn-danger" title="Disable this rule entirely">Disable Globally</button>
                                                </form>
                                            <?php endif; ?>

                                            <?php if($target_val): ?>
                                                <?php if($is_whitelisted): ?>
                                                    <form method="POST">
                                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                                        <input type="hidden" name="action" value="undo_whitelist">
                                                        <input type="hidden" name="rule_id" value="<?= h($rid) ?>">
                                                        <input type="hidden" name="source_ip" value="<?= h($log['source_ip']) ?>">
                                                        <button type="submit" class="btn btn-sm btn-warning" title="Remove from whitelist">Undo IP+ID</button>
                                                    </form>
                                                <?php elseif(!$is_globally_whitelisted): ?>
                                                    <form method="POST">
                                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                                        <input type="hidden" name="action" value="disable_target">
                                                        <input type="hidden" name="rule_id" value="<?= h($rid) ?>">
                                                        <input type="hidden" name="source_ip" value="<?= h($log['source_ip']) ?>">
                                                        <button type="submit" class="btn btn-sm btn-info" title="Whitelist this IP for this rule">Whitelist IP+ID</button>
                                                    </form>
                                                <?php endif; ?>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                            <details class="raw-log-details"><summary>View Raw Log</summary><pre><?= h($log['raw']) ?></pre></details>
                        </div>
                    </div>
                    <?php endforeach; endif; ?>
                </div>
            </div>
            
        <?php break; case 'rules': 
            $activated_files = list_rule_files($RULES_DIR_ACTIVATED);
            $local_files = list_rule_files($RULES_DIR_LOCAL);

            $activated_rules = [];
            foreach ($activated_files as $f) {
                foreach (parse_rules_from_file($f) as $rule) $activated_rules[] = $rule;
            }

            $local_rules = [];
            foreach ($local_files as $f) {
                foreach (parse_rules_from_file($f) as $rule) $local_rules[] = $rule;
            }

            $whitelisted_rules = file_exists($WHITELIST_FILE) ? parse_rules_from_file($WHITELIST_FILE) : [];

            $q = $_GET['q'] ?? '';
            $filter_func = function($arr, $q) {
                if ($q === '') return $arr;
                $out = [];
                $q2 = mb_strtolower($q);
                foreach ($arr as $r) {
                    if (mb_strpos(mb_strtolower($r['msg'] ?? ''), $q2) !== false
                        || mb_strpos(mb_strtolower($r['pattern'] ?? ''), $q2) !== false
                        || mb_strpos(mb_strtolower(basename($r['file'])), $q2) !== false
                        || (isset($r['id']) && mb_strpos((string)$r['id'], $q2) !== false)) {
                        $out[] = $r;
                    }
                }
                return $out;
            };

            $act = $filter_func($activated_rules, $q);
            $loc = $filter_func($local_rules, $q);
            $wl = $filter_func($whitelisted_rules, $q);
        ?>
            <div class="toolbar">
                <form method="get">
                    <input type="hidden" name="page" value="rules">
                    <input type="text" name="q" value="<?=h($q)?>" class="search-input" placeholder="Search by ID, Message or Filename...">
                    <button type="submit" class="btn btn-primary">Search</button>
                </form>
            </div>
            <div>
                <h3 class="rules-table-section">Local Rules</h3>
                <?= render_rules_table_local($loc, false) ?>
            </div>
            <div class="rules-table-section">
                <h3>Whitelisted Rules</h3>
                <?= render_rules_table_local($wl, false) ?>
            </div>
            <div class="rules-table-section">
                <h3>Activated Rules (Read-only)</h3>
                <?= render_rules_table_local($act, false) ?>
            </div>
            
        <?php break; case 'edit_rule':
            $file = $_GET['file'] ?? null;
            if (!$file) {
                 echo '<h2 class="editor-title">Custom Rules Editor</h2>';
                 echo '<div class="file-list"><h3>Available Files</h3><ul>';
                 $found_files = scandir($RULES_DIR_LOCAL);
                 foreach($found_files as $f) {
                     if($f !== '.' && $f !== '..' && str_ends_with($f, '.conf')) {
                         echo '<li><a href="?page=edit_rule&file='.h($f).'">'.h($f).'</a></li>';
                     }
                 }
                 echo '<li><a href="?page=edit_rule&file=whitelist.conf">whitelist.conf</a></li>';
                 echo '</ul></div>';
            } else {
                $path = ($file === 'whitelist.conf') ? $WHITELIST_FILE : rtrim($RULES_DIR_LOCAL,'/').'/'.basename($file);
                if (!allowed_local_path(basename($file))) {
                    echo '<div class="error">Security error: Invalid file path.</div>';
                } else {
                    $content = file_exists($path) ? file_get_contents($path) : "# New ModSecurity Rule File\nSecRule ...\n";
        ?>
            <div class="editor-header">
                <h2>Editing: <?=h($file)?></h2>
                <a href="?page=edit_rule" class="btn btn-primary">Back to list</a>
            </div>
            <form method="post" class="editor-form">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <input type="hidden" name="action" value="save_file">
                <input type="hidden" name="file_path" value="<?= h($path) ?>">
                <textarea name="content" class="code-editor" spellcheck="false"><?=h($content)?></textarea>
                <div class="editor-actions">
                    <button type="submit" class="btn btn-success">Save</button>
                    <span class="restart-hint"> Apache restart required for changes to take effect.</span>
                </div>
            </form>
            <div class="editor-footer">
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                    <input type="hidden" name="action" value="restart_httpd">
                    <button type="submit" class="btn btn-warning">🔄 Restart Apache</button>
                </form>
            </div>
        <?php 
                }
            }
        break; case 'testing': 
            $payloads = get_test_payloads();
        ?>
            <div class="dashboard-section testing-console-section">
                <h2 class="testing-title">Penetration Testing Console</h2>

                <div class="payload-buttons">
                    <button type="button" class="btn btn-sm btn-payload" onclick="setPayload(<?= htmlspecialchars(json_encode($payloads['sqli']), ENT_QUOTES) ?>)">
                        SQL Injection (SQLi)
                    </button>
                    <button type="button" class="btn btn-sm btn-payload" onclick="setPayload(<?= htmlspecialchars(json_encode($payloads['xss']), ENT_QUOTES) ?>)">
                        Cross-Site Scripting (XSS)
                    </button>
                    <button type="button" class="btn btn-sm btn-payload" onclick="setPayload(<?= htmlspecialchars(json_encode($payloads['lfi']), ENT_QUOTES) ?>)">
                        Path Traversal (LFI)
                    </button>
                </div>

                <div class="terminal-input-group">
                    <span class="terminal-prompt">root@test:~#</span>
                    <input type="text" id="targetUrl" class="terminal-input" value="<?= h($payloads['base']) ?>/">
                    <button type="button" class="btn btn-success" onclick="fireAttack()">Attack</button>
                </div>

                <div class="iframe-container">
                    <div class="iframe-header">
                        <span>Target Response</span>
                        <span id="loadingIndicator" class="iframe-loader">Waiting for server...</span>
                    </div>
                    <iframe id="attackFrame" class="attack-iframe" src="<?= h($payloads['base']) ?>/"></iframe>
                </div>
            </div>

            <script>
                function setPayload(url) {
                    document.getElementById('targetUrl').value = url;
                    fireAttack();
                }

                function fireAttack() {
                    const url = document.getElementById('targetUrl').value;
                    if (!url) return;

                    const frame = document.getElementById('attackFrame');
                    const loader = document.getElementById('loadingIndicator');
                    
                    loader.style.display = 'inline';
                    frame.src = url;

                    frame.onload = function() {
                        loader.style.display = 'none';
                    };
                }
            </script>
        <?php break; case 'analytics': 

            $all_logs = parse_modsec_log($AUDIT_LOG, 1000);

            $total_events = count($all_logs);
            $blocked_count = 0;
            $ip_stats = [];
            $rule_stats = [];
            $rule_messages = [];

            foreach ($all_logs as $log) {
                if ($log['final_action'] === 'BLOCKED') {
                    $blocked_count++;
                }

                $ip = $log['source_ip'];
                $ip_stats[$ip] = ($ip_stats[$ip] ?? 0) + 1;

                foreach ($log['root_cause_ids'] as $rid) {
                    $rule_stats[$rid] = ($rule_stats[$rid] ?? 0) + 1;
                    if (!isset($rule_messages[$rid]) && isset($log['rule_details'][$rid]['msg'])) {
                        $rule_messages[$rid] = $log['rule_details'][$rid]['msg'];
                    }
                }
            }

            arsort($ip_stats);
            $top_ips = array_slice($ip_stats, 0, 50, true);

            arsort($rule_stats);
            $top_rules = array_slice($rule_stats, 0, 5, true);

            $chart_labels = json_encode(array_keys($top_rules));
            $chart_data = json_encode(array_values($top_rules));
            
            $blocked_percent = $total_events > 0 ? round(($blocked_count / $total_events) * 100) : 0;
        ?>
            <div class="dashboard-section analytics-section">
                <h2 class="analytics-title">ModSecurity Analytics</h2>
                
                <div class="stats-grid">
                    <div class="stat-card stat-blue">
                        <h4>Total Events Analyzed</h4>
                        <div class="stat-value"><?= $total_events ?></div>
                    </div>
                    
                    <div class="stat-card stat-red">
                        <h4>Blocked Requests</h4>
                        <div class="stat-value"><?= $blocked_count ?></div>
                    </div>

                    <div class="stat-card stat-yellow">
                        <h4>Block Rate</h4>
                        <div class="stat-value"><?= $blocked_percent ?>%</div>
                    </div>
                </div>

                <div class="analytics-panels">
                    <div class="panel-card">
                        <h3 class="panel-title">Top 50 Attacker IPs</h3>
                        <table class="attacker-table">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Hits</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($top_ips)): ?>
                                    <tr><td colspan="2" class="no-data">No data available.</td></tr>
                                <?php else: ?>
                                    <?php foreach ($top_ips as $ip => $count): ?>
                                    <tr>
                                        <td class="attacker-ip">
                                            <a href="?page=logs&search_ip=<?= urlencode($ip) ?>" style="color: #3b82f6; text-decoration: underline;" title="View all attacks from this IP">
                                                <?= h($ip) ?>
                                            </a>
                                        </td>
                                        <td class="attacker-hits"><?= $count ?></td>
                                    </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>

                    <div class="panel-card">
                        <h3 class="panel-title">📈 Top Triggered Rules</h3>
                        
                        <div class="chart-wrapper">
                            <?php if (empty($top_rules)): ?>
                                <span class="no-data">No rule data available.</span>
                            <?php else: ?>
                                <canvas id="rulesChart"></canvas>
                            <?php endif; ?>
                        </div>

                        <?php if (!empty($top_rules)): ?>
                        <div class="rule-descriptions">
                            <h4>Rule Descriptions</h4>
                            <ul class="rule-desc-list">
                                <?php foreach($top_rules as $rid => $count): ?>
                                    <li>
                                        <span class="rule-desc-id"><?= $rid ?></span> 
                                        <span><?= h($rule_messages[$rid] ?? 'Unknown Rule Description') ?></span>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                        <?php endif; ?>

                    </div>
                </div>
            </div>
        <?php break;
        default: echo "<div class='info-box'>The page was not found.</div>";
        endswitch; 
        ?>
    </main>
</div>
<script>
document.addEventListener("DOMContentLoaded", function() {
    const autoRefreshCheckbox = document.getElementById('autoRefresh');
    const logsWrapper = document.getElementById('live-logs-wrapper');
    let refreshTimer;

    if (!autoRefreshCheckbox || !logsWrapper) return;

    function fetchNewLogs() {
        if (!autoRefreshCheckbox.checked) return;
        fetch(window.location.href)
            .then(response => response.text())
            .then(html => {
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');
                const newWrapper = doc.getElementById('live-logs-wrapper');
                
                if (newWrapper && logsWrapper.innerHTML !== newWrapper.innerHTML) {
                    logsWrapper.innerHTML = newWrapper.innerHTML;
                }
            })
            .catch(err => console.error('Error refreshing logs:', err));
    }

    refreshTimer = setInterval(fetchNewLogs, 3000);
});
</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
document.addEventListener("DOMContentLoaded", function() {
    const ctx = document.getElementById('rulesChart');
    if (ctx) {
        const labels = <?= $chart_labels ?? '[]' ?>;
        const data = <?= $chart_data ?? '[]' ?>;

        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels.map(id => 'Rule ' + id),
                datasets: [{
                    data: data,
                    backgroundColor: [
                        '#ef4444', 
                        '#f59e0b', 
                        '#3b82f6', 
                        '#10b981', 
                        '#8b5cf6'  
                    ],
                    borderColor: '#1f2937', 
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#9ca3af',
                            font: { family: 'Inter, sans-serif' }
                        }
                    }
                }
            }
        });
    }
});
</script>
</body>
</html>