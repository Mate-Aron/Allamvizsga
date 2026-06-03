<?php
$search_ip = trim($_GET['search_ip'] ?? '');
$items_per_page = 20;
$p = max(1, (int)($_GET['p'] ?? 1));
$offset = ($p - 1) * $items_per_page;

$where = "1=1";
if ($search_ip !== '') {
    $where .= " AND source_ip = :source_ip";
}

$stmt = $pdo->prepare("SELECT COUNT(*) FROM audit_logs WHERE $where");
if ($search_ip !== '') {
    $stmt->bindValue(':source_ip', $search_ip);
}
$stmt->execute();
$total_items = $stmt->fetchColumn();
$total_pages = max(1, (int)ceil($total_items / $items_per_page));

$stmt = $pdo->prepare("SELECT * FROM audit_logs WHERE $where ORDER BY log_time DESC LIMIT :limit OFFSET :offset");
if ($search_ip !== '') {
    $stmt->bindValue(':source_ip', $search_ip);
}
$stmt->bindValue(':limit', $items_per_page, PDO::PARAM_INT);
$stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
$stmt->execute();
$db_logs = $stmt->fetchAll();

$current_page_logs = [];
foreach ($db_logs as $row) {
    $current_page_logs[] = [
        'id'             => $row['id'],
        'time'           => $row['log_time'],
        'source_ip'      => $row['source_ip'],
        'method'         => $row['method'],
        'uri'            => $row['uri'],
        'hostname'       => $row['hostname'],
        'attack_type'    => $row['attack_type'],
        'final_action'   => $row['final_action'],
        'root_cause_ids' => json_decode($row['root_cause_ids'], true) ?? [],
        'rule_details'   => json_decode($row['rule_details'], true) ?? [],
        'raw'            => $row['raw_log']
    ];
}
?>

<div class="log-container">
    <div class="log-header-top">
        <h3>Audit Logs</h3>
        <div class="header-actions">
            <form method="get" class="search-form">
                <input type="hidden" name="page" value="logs">
                <input type="text" name="search_ip" value="<?= h($search_ip) ?>" placeholder="Search IP" class="filter-input">
                <button type="submit" class="btn btn-primary btn-sm">Filter</button>
                <?php if ($search_ip !== ''): ?>
                    <a href="?page=logs" class="btn btn-warning btn-sm">Clear</a>
                <?php endif; ?>
            </form>

            <form method="post" class="inline-form">
                <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                <input type="hidden" name="action" value="restart_httpd">
                <button type="submit" class="btn btn-warning btn-sm" title="Apply whitelist changes">🔄 Restart Apache</button>
            </form>

            <label class="auto-refresh-label">
                <input type="checkbox" id="autoRefresh" checked> 🔴 Live Update
            </label>
        </div>
    </div>

    <div id="live-logs-wrapper">
        <?php if (empty($current_page_logs)): ?>
            <div class="info-box">No logs found in the database.</div>
        <?php else: ?>

            <?php foreach ($current_page_logs as $log):
                $is_card_whitelisted = false;
                foreach ($log['root_cause_ids'] as $rid) {
                    if (is_ip_rule_whitelisted($WHITELIST_FILE, $log['source_ip'], $rid) || is_rule_globally_whitelisted($WHITELIST_FILE, $rid)) {
                        $is_card_whitelisted = true;
                        break;
                    }
                }
                $display_status = $is_card_whitelisted ? 'WHITELISTED' : $log['final_action'];
                $card_class = match(true) {
                    $is_card_whitelisted                => 'whitelisted-card',
                    $log['final_action'] === 'BLOCKED'  => 'blocked',
                    $log['final_action'] === 'REJECTED' => 'rejected',
                    default                             => 'alert',
                };
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
                                $details         = $log['rule_details'][$rid] ?? [];
                                $severity        = $details['severity'] ?? 'NOTICE';
                                $severityClass   = 'severity-' . strtolower($severity);
                                $target_val      = $details['target'] ?? '';

                                $is_whitelisted          = is_ip_rule_whitelisted($WHITELIST_FILE, $log['source_ip'], $rid);
                                $is_globally_whitelisted = is_rule_globally_whitelisted($WHITELIST_FILE, $rid);
                                $is_any_whitelisted      = $is_whitelisted || $is_globally_whitelisted;
                            ?>
                            <div class="rule-action-row <?= $is_any_whitelisted ? 'whitelisted-row' : '' ?>">
                                <div class="rule-info">
                                    <div class="rule-badges">
                                        <span class="rule-id">ID: <?= h($rid) ?></span>
                                        <span class="severity-badge <?= h($severityClass) ?>"><?= h($severity) ?></span>
                                        <?php if ($target_val): ?>
                                            <span class="target-badge">Target: <?= h($target_val) ?></span>
                                        <?php endif; ?>
                                    </div>
                                    <div class="rule-message"><?= h($details['msg']) ?></div>
                                    <?php if (!empty($details['data'])): ?>
                                        <div class="matched-data-box">Match: "<?= h($details['data']) ?>"</div>
                                    <?php endif; ?>
                                    <?php if (!empty($details['tags'])): ?>
                                        <div class="tags-container">
                                            <?php foreach (array_unique($details['tags']) as $tag): ?>
                                                <span class="tag-item"><?= h($tag) ?></span>
                                            <?php endforeach; ?>
                                        </div>
                                    <?php endif; ?>
                                </div>

                                <div class="action-buttons">
                                    <?php if ($is_globally_whitelisted): ?>
                                        <form method="POST">
                                            <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                                            <input type="hidden" name="action" value="undo_global_whitelist">
                                            <input type="hidden" name="rule_id" value="<?= h($rid) ?>">
                                            <button type="submit" class="btn btn-sm btn-danger" title="Re-enable this rule globally">Undo Global</button>
                                        </form>
                                    <?php else: ?>
                                        <form method="POST">
                                            <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                                            <input type="hidden" name="action" value="disable_rule_globally">
                                            <input type="hidden" name="rule_id" value="<?= h($rid) ?>">
                                            <button type="submit" class="btn btn-sm btn-danger" title="Disable this rule entirely">Disable Globally</button>
                                        </form>
                                    <?php endif; ?>

                                    <?php if ($is_whitelisted): ?>
                                        <form method="POST">
                                            <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                                            <input type="hidden" name="action" value="undo_whitelist">
                                            <input type="hidden" name="rule_id" value="<?= h($rid) ?>">
                                            <input type="hidden" name="source_ip" value="<?= h($log['source_ip']) ?>">
                                            <button type="submit" class="btn btn-sm btn-warning" title="Remove from whitelist">Undo IP+ID</button>
                                        </form>
                                    <?php elseif (!$is_globally_whitelisted): ?>
                                        <form method="POST">
                                            <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                                            <input type="hidden" name="action" value="disable_target">
                                            <input type="hidden" name="rule_id" value="<?= h($rid) ?>">
                                            <input type="hidden" name="source_ip" value="<?= h($log['source_ip']) ?>">
                                            <button type="submit" class="btn btn-sm btn-info" title="Whitelist this IP for this rule">Whitelist IP+ID</button>
                                        </form>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>

                    <details class="raw-log-details">
                        <summary>View Raw Log</summary>
                        <pre><?= h($log['raw']) ?></pre>
                    </details>
                </div>
            </div>
            <?php endforeach; ?>

            <?php if ($total_pages > 1):
                $base_url = "?page=logs" . ($search_ip !== '' ? "&search_ip=" . urlencode($search_ip) : '');
            ?>
                <div class="pagination-container">
                    <?php if ($p > 1): ?>
                        <a href="<?= $base_url ?>&p=<?= $p - 1 ?>" class="btn btn-primary">⬅ Previous</a>
                    <?php else: ?>
                        <button class="btn btn-primary" disabled>⬅ Previous</button>
                    <?php endif; ?>

                    <span class="pagination-info">
                        Page: <?= $p ?> / <?= $total_pages ?>
                        <span class="pagination-total">(Total: <?= $total_items ?> logs)</span>
                    </span>

                    <?php if ($p < $total_pages): ?>
                        <a href="<?= $base_url ?>&p=<?= $p + 1 ?>" class="btn btn-primary">Next ➡</a>
                    <?php else: ?>
                        <button class="btn btn-primary" disabled>Next ➡</button>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

        <?php endif; ?>
    </div>
</div>

<script>
document.addEventListener("DOMContentLoaded", function () {
    const autoRefreshCheckbox = document.getElementById('autoRefresh');
    const logsWrapper         = document.getElementById('live-logs-wrapper');
    let isPaused = false;

    if (!autoRefreshCheckbox || !logsWrapper) return;

    setInterval(function () {
        if (!autoRefreshCheckbox.checked || isPaused) return;

        fetch(window.location.href)
            .then(r => r.text())
            .then(html => {
                const doc        = new DOMParser().parseFromString(html, 'text/html');
                const newWrapper = doc.getElementById('live-logs-wrapper');
                if (newWrapper && logsWrapper.innerHTML !== newWrapper.innerHTML) {
                    logsWrapper.innerHTML = newWrapper.innerHTML;
                }
            })
            .catch(err => console.error('Refresh error:', err));
    }, 3000);

    document.addEventListener('click', function (e) {
        if (e.target.closest('.raw-log-details')) {
            isPaused = !isPaused;
            autoRefreshCheckbox.checked = !isPaused;
        }
    });
});
</script>