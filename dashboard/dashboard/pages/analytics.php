<?php
$total_events = $pdo->query("SELECT COUNT(*) FROM audit_logs")->fetchColumn();
$blocked_count = $pdo->query("SELECT COUNT(*) FROM audit_logs WHERE final_action = 'BLOCKED'")->fetchColumn();

$top_ips = $pdo->query("SELECT source_ip, COUNT(*) as c FROM audit_logs GROUP BY source_ip ORDER BY c DESC LIMIT 50")->fetchAll(PDO::FETCH_KEY_PAIR);
$top_uris = $pdo->query("SELECT uri, COUNT(*) as c FROM audit_logs GROUP BY uri ORDER BY c DESC LIMIT 5")->fetchAll(PDO::FETCH_KEY_PAIR);
$attack_type_stats = $pdo->query("SELECT attack_type, COUNT(*) as c FROM audit_logs GROUP BY attack_type ORDER BY c DESC")->fetchAll(PDO::FETCH_KEY_PAIR);
$time_stats = $pdo->query("SELECT DATE_FORMAT(log_time, '%H:00') as h, COUNT(*) as c FROM audit_logs GROUP BY h ORDER BY h")->fetchAll(PDO::FETCH_KEY_PAIR);

$blocked_percent = $total_events > 0 ? round(($blocked_count / $total_events) * 100) : 0;

$trend_labels  = json_encode(array_keys($time_stats ?: []));
$trend_data    = json_encode(array_values($time_stats ?: []));
$uri_labels    = json_encode(array_keys($top_uris ?: []));
$uri_data      = json_encode(array_values($top_uris ?: []));
$attack_labels = json_encode(array_keys($attack_type_stats ?: []));
$attack_data   = json_encode(array_values($attack_type_stats ?: []));
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

    <div class="analytics-panels" style="margin-bottom: 20px;">
        <div class="panel-card" style="width: 100%;">
            <h3 class="panel-title">Attack Trend (Timeline)</h3>
            <div class="chart-wrapper" style="height: 300px;">
                <canvas id="trendChart"></canvas>
            </div>
        </div>
    </div>

    <div class="analytics-panels" style="margin-bottom: 20px;">
        <div class="panel-card">
            <h3 class="panel-title">Top Targeted URIs</h3>
            <div class="chart-wrapper">
                <canvas id="uriChart"></canvas>
            </div>
        </div>
        <div class="panel-card">
            <h3 class="panel-title">Attack Types</h3>
            <div class="chart-wrapper">
                <canvas id="attackTypeChart"></canvas>
            </div>
        </div>
    </div>

    <div class="analytics-panels">
        <div class="panel-card">
            <h3 class="panel-title">Top 50 Attacker IPs</h3>
            <table class="attacker-table">
                <thead>
                    <tr><th>IP Address</th><th>Hits</th></tr>
                </thead>
                <tbody>
                    <?php if (empty($top_ips)): ?>
                        <tr><td colspan="2" class="no-data">No data available.</td></tr>
                    <?php else: ?>
                        <?php foreach ($top_ips as $ip => $count): ?>
                        <tr>
                            <td class="attacker-ip-cell" data-ip="<?= h($ip) ?>">
                                <a href="?page=logs&search_ip=<?= urlencode($ip) ?>" class="ip-link" title="View all attacks from this IP">
                                    <?= h($ip) ?>
                                </a>
                                <span class="geo-info">
                                    <span class="geo-flag"></span>
                                    <span class="geo-country"></span>
                                </span>
                            </td>
                            <td class="attacker-hits"><?= $count ?></td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
document.addEventListener("DOMContentLoaded", function () {

    const ctxTrend = document.getElementById('trendChart');
    if (ctxTrend) {
        new Chart(ctxTrend, {
            type: 'line',
            data: {
                labels: <?= $trend_labels ?>,
                datasets: [{
                    label: 'Total Events',
                    data: <?= $trend_data ?>,
                    borderColor: '#4f46e5',
                    backgroundColor: 'rgba(79, 70, 229, 0.1)',
                    borderWidth: 2,
                    tension: 0.3,
                    fill: true
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    }

    const ctxUri = document.getElementById('uriChart');
    if (ctxUri) {
        new Chart(ctxUri, {
            type: 'bar',
            data: {
                labels: <?= $uri_labels ?>,
                datasets: [{ label: 'Hits', data: <?= $uri_data ?>, backgroundColor: '#3b82f6', borderRadius: 4 }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } }
            }
        });
    }

    const ctxAttack = document.getElementById('attackTypeChart');
    if (ctxAttack) {
        new Chart(ctxAttack, {
            type: 'pie',
            data: {
                labels: <?= $attack_labels ?>,
                datasets: [{
                    data: <?= $attack_data ?>,
                    backgroundColor: ['#f43f5e', '#8b5cf6', '#ec4899', '#14b8a6', '#f59e0b'],
                    borderWidth: 1
                }]
            },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right' } } }
        });
    }

    // GeoIP flag az IP-k mellé
    function getFlagEmoji(code) {
        if (!code) return '';
        return String.fromCodePoint(...code.toUpperCase().split('').map(c => 127397 + c.charCodeAt()));
    }

    document.querySelectorAll('.attacker-ip-cell').forEach(cell => {
        const ip = cell.getAttribute('data-ip');
        fetch(`https://get.geojs.io/v1/ip/geo/${ip}.json`)
            .then(r => r.json())
            .then(data => {
                if (data?.country) {
                    cell.querySelector('.geo-flag').textContent    = getFlagEmoji(data.country_code);
                    cell.querySelector('.geo-country').textContent = data.country;
                }
            })
            .catch(() => {});
    });
});
</script>