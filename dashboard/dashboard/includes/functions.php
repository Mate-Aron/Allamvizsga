<?php
require_once __DIR__ . '/../config.php';

function h($s) {
    return htmlspecialchars($s ?? '', ENT_QUOTES | ENT_SUBSTITUTE);
}

function atomic_append_file($filename, $content) {
    return file_put_contents($filename, trim($content) . "\n", FILE_APPEND) !== false;
}

function allowed_local_path($filename) {
    return str_ends_with($filename, '.conf') && basename($filename) === $filename;
}

function save_rule_text($path, $content) {
    return file_put_contents($path, $content) !== false;
}

function list_rule_files($dir) {
    if (!is_dir($dir)) return [];
    $out = [];
    foreach (scandir($dir) as $f) {
        if ($f !== '.' && $f !== '..' && str_ends_with($f, '.conf')) {
            $out[] = rtrim($dir, '/') . '/' . $f;
        }
    }
    return $out;
}

function remove_line_from_file($file, $match_conditions) {
    if (!file_exists($file)) return null;

    $lines     = file($file, FILE_IGNORE_NEW_LINES);
    $new_lines = [];
    $found     = false;

    foreach ($lines as $line) {
        $matches_all = true;
        foreach ($match_conditions as $condition) {
            if (strpos($line, $condition) === false) {
                $matches_all = false;
                break;
            }
        }
        if ($matches_all) {
            $found = true;
            continue;
        }
        $new_lines[] = $line;
    }

    if ($found) {
        return file_put_contents($file, implode("\n", $new_lines) . "\n") !== false;
    }
    return null;
}

function parse_rules_from_file($path) {
    if (!file_exists($path) || !($handle = fopen($path, "r"))) return [];

    $out    = [];
    $buffer = '';

    while (($line = fgets($handle)) !== false) {
        $trimmed = trim($line);

        if ($buffer === '' && ($trimmed === '' || $trimmed[0] === '#')) continue;

        if (substr($trimmed, -1) === '\\') {
            $buffer .= rtrim(substr($trimmed, 0, -1)) . ' ';
            continue;
        }

        $buffer  .= $trimmed;
        $fullRule = $buffer;
        $buffer   = '';

        $id  = null;
        $msg = 'No Description';

        if (preg_match('/^SecRuleRemoveById\s+([0-9]+)/i', trim($fullRule), $m)) {
            $id  = $m[1];
            $msg = "🌍 GLOBALLY DISABLED RULE";
        } elseif (stripos($fullRule, 'SecRule') !== false) {
            if (preg_match('/ctl:ruleRemoveById=([0-9]+)/i', $fullRule, $mTarget)) {
                $target_id = $mTarget[1];
                $ip  = preg_match('/@ipMatch\s+([^"]+)/i', $fullRule, $mIp) ? $mIp[1] : 'Unknown IP';
                $id  = preg_match('/\bid\s*:\s*([0-9]+)/i', $fullRule, $m) ? $m[1] : rand(1000, 9999);
                $msg = "👤 IP WHITELIST for Rule $target_id (IP: $ip)";
            } else {
                if (preg_match('/\bid\s*:\s*([0-9]+)/i', $fullRule, $m)) $id = $m[1];
                if (preg_match('/\bmsg\s*:\s*(?:[\'"])(.*?)(?:[\'"])/i', $fullRule, $m) ||
                    preg_match('/\bmsg\s*:\s*([^,\s"]+)/i', $fullRule, $m)) {
                    $msg = $m[1];
                }
            }
        }

        if (!$id) continue;

        $out[] = [
            'id'       => $id,
            'msg'      => $msg,
            'file'     => $path,
            'pattern'  => (strlen($fullRule) > 250) ? substr($fullRule, 0, 97) . '...' : $fullRule,
            'raw_text' => $fullRule
        ];
    }

    fclose($handle);
    return $out;
}

function render_rules_table($rules, $is_editable = false) {
    if (empty($rules)) return '<p class="empty-state">No rules found.</p>';

    $html  = '<table class="rules-table"><thead><tr>';
    $html .= '<th class="col-id">ID</th><th>Message / Pattern</th><th>File</th>';
    if ($is_editable) $html .= '<th>Action</th>';
    $html .= '</tr></thead><tbody>';

    foreach ($rules as $r) {
        $html .= '<tr>';
        $html .= '<td><strong>' . h($r['id'] ?? '-') . '</strong></td>';
        $html .= '<td><div class="rule-msg">' . h($r['msg'] ?? 'No Description') . '</div>';
        $html .= '<details class="rule-details"><summary>Show Code</summary>';
        $html .= '<code class="rule-code">' . h($r['pattern']) . '</code></details></td>';
        $html .= '<td class="file-name">' . h(basename($r['file'])) . '</td>';
        if ($is_editable) {
            $html .= '<td>';
            if (allowed_local_path(basename($r['file']))) {
                $html .= '<a href="?page=edit_rule&file=' . urlencode(basename($r['file'])) . '" class="btn btn-sm">Edit</a>';
            }
            $html .= '</td>';
        }
        $html .= '</tr>';
    }

    $html .= '</tbody></table>';
    return $html;
}

function getNextRuleId($filePath, $baseId = 1000000) {
    if (!file_exists($filePath) || filesize($filePath) === 0) return $baseId;

    $content = file_get_contents($filePath);
    if (preg_match_all('/id:(\d+)/', $content, $matches)) {
        return max($matches[1]) + 1;
    }
    return $baseId;
}

function restart_httpd() {
    $flag = '/var/www/html/studentworks/flags/restart.flag';
    return @touch($flag);
}

function get_test_payloads() {
    $base = "https://studentworks.ms.sapientia.ro";
    return [
        'base' => $base,
        'sqli' => $base . "/?id=1' OR '1'='1",
        'xss'  => $base . "/?search=<script>alert('XSS')</script>",
        'lfi'  => $base . "/?file=../../../../etc/passwd",
    ];
}