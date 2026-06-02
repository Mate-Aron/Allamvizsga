<?php
ini_set('memory_limit', '1024M');
require_once __DIR__ . '/../config.php';

if (!file_exists($AUDIT_LOG)) die("Log file not found.\n");


$stmt = $pdo->query("SELECT last_position FROM sync_status WHERE id = 1");
$last_pos = (int)$stmt->fetchColumn();

$file = fopen($AUDIT_LOG, 'r');
fseek($file, 0, SEEK_END);
$current_size = ftell($file);

if ($current_size < $last_pos) {
    $last_pos = 0;
} elseif ($current_size === $last_pos) {
    die("No new logs to import.\n");
}


fseek($file, $last_pos);
$new_data = stream_get_contents($file);
$new_pos = ftell($file);
fclose($file);

$entries = preg_split('/(?=^--[a-zA-Z0-9]{8}-A--$)/m', $new_data, -1, PREG_SPLIT_NO_EMPTY);

$insert_stmt = $pdo->prepare("INSERT IGNORE INTO audit_logs 
    (id, log_time, source_ip, method, uri, hostname, attack_type, final_action, root_cause_ids, rule_details, raw_log) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

$pdo->beginTransaction();
$imported = 0;

foreach ($entries as $raw_entry) {
    if (!str_contains($raw_entry, '-Z--')) continue;

    $id = preg_match('/^--([a-zA-Z0-9]+)-A--/m', $raw_entry, $m) ? $m[1] : null;
    if (!$id) continue;

    $time = ''; $ip = 'Unknown';
    if (preg_match('/^\[(.*?)\]\s+\S+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s/m', $raw_entry, $m)) {
        $time = $m[1]; $ip = $m[2];
    }

    $method = 'UNKNOWN'; $uri = ''; $hostname = 'Unknown';
    if (preg_match('/^--\w+-B--\s+(.*?)\n\n/ms', $raw_entry, $m)) {
        $headers = $m[1];
        if (preg_match('/^(POST|GET|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP/i', $headers, $r)) {
            $method = $r[1]; $uri = $r[2];
        }
        if (preg_match('/^Host:\s*(.*)$/im', $headers, $r)) $hostname = trim($r[1]);
    }

    $root_cause_ids = []; $rule_details = [];
    if (preg_match('/^--\w+-H--\s+(.*?)\n\n/ms', $raw_entry, $m)) {
        foreach (explode("\n", $m[1]) as $line) {
            if (!preg_match('/\[id "(\d+)"\]/', $line, $id_m)) continue;
            $rid = (int)$id_m[1];
            
            if (!in_array($rid, $root_cause_ids)) $root_cause_ids[] = $rid;
            if (!isset($rule_details[$rid])) {
                $rule_details[$rid] = ['msg' => 'No msg', 'severity' => 'UNKNOWN', 'tags' => [], 'data' => '', 'target' => ''];
            }
            if (preg_match('/\[msg "([^"]+)"\]/', $line, $r)) $rule_details[$rid]['msg'] = $r[1];
            if (preg_match('/\[severity "([^"]+)"\]/', $line, $r)) $rule_details[$rid]['severity'] = $r[1];
            if (preg_match('/\[data "([^"]+)"\]/', $line, $r)) $rule_details[$rid]['data'] = $r[1];
            if (preg_match('/found within ([^:]+:[^\]\s]+)/', $line, $r)) $rule_details[$rid]['target'] = str_replace(['[', ']'], '', $r[1]);
            if (preg_match_all('/\[tag "([^"]+)"\]/', $line, $r)) {
                foreach ($r[1] as $t) $rule_details[$rid]['tags'][] = $t;
            }
        }
    }

    $final_action = 'ALLOWED';
    if (stripos($raw_entry, 'Access denied') !== false || stripos($raw_entry, '403 Forbidden') !== false) {
        $final_action = 'BLOCKED';
    } elseif (!empty($root_cause_ids)) {
        $final_action = 'DETECTED';
    }

    $attack_type = !empty($root_cause_ids) ? ($rule_details[$root_cause_ids[0]]['msg'] ?? "Rule ID: {$root_cause_ids[0]}") : "Log Entry";

    $dateObj = DateTime::createFromFormat('d/M/Y:H:i:s.u O', $time);
    $mysql_time = $dateObj ? $dateObj->format('Y-m-d H:i:s.u') : date('Y-m-d H:i:s');

    $insert_stmt->execute([
        $id, $mysql_time, $ip, $method, $uri, $hostname, $attack_type, $final_action,
        json_encode($root_cause_ids), json_encode($rule_details), $raw_entry
    ]);
    
    if ($insert_stmt->rowCount() > 0) $imported++;
}

$pdo->prepare("UPDATE sync_status SET last_position = ? WHERE id = 1")->execute([$new_pos]);
$pdo->query("DELETE FROM audit_logs WHERE log_time < NOW() - INTERVAL 90 DAY");

$pdo->commit();
echo "Import complete. $imported new rows added. Position updated to $new_pos.\n";
?>