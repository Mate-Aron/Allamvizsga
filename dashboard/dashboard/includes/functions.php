<?php
declare(strict_types=1);

require_once __DIR__ . '/../config.php';

function h(?string $s): string {
    return htmlspecialchars($s ?? '', ENT_QUOTES | ENT_SUBSTITUTE);
}

function is_safe_filename(string $filename): bool {
    return str_ends_with($filename, '.conf') && basename($filename) === $filename;
}

function append_to_file(string $filename, string $content): bool {
    return file_put_contents($filename, trim($content) . "\n", FILE_APPEND) !== false;
}

function save_rule_file(string $path, string $content): bool {
    $backup = $path . '.' . date('Ymd_His') . '.bak';
    @copy($path, $backup);
    return file_put_contents($path, $content) !== false;
}

function remove_matching_line(string $file, array $match_conditions): ?bool {
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
        if ($matches_all && !$found) {
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

function list_rule_files(string $dir): array {
    if (!is_dir($dir)) return [];
    
    $out = [];
    foreach (scandir($dir) as $f) {
        if (str_ends_with($f, '.conf')) {
            $out[] = rtrim($dir, '/') . '/' . $f;
        }
    }
    return $out;
}



function next_rule_id(string $filePath, int $baseId = 1000000): int {
    if (!file_exists($filePath) || filesize($filePath) === 0) return $baseId;

    $content = file_get_contents($filePath);
    if (preg_match_all('/id:(\d+)/', $content, $matches)) {
        return max($matches[1]) + 1;
    }
    return $baseId;
}

function parse_rules_from_file(string $path): array {
    if (!file_exists($path) || !($handle = fopen($path, "r"))) return [];

    $out    = [];
    $buffer = '';

    while (($line = fgets($handle)) !== false) {
        $trimmed = trim($line);

        if ($buffer === '' && ($trimmed === '' || $trimmed[0] === '#')) continue;

        if (str_ends_with($trimmed, '\\')) {
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
            $msg = "GLOBALLY DISABLED RULE";
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

function restart_httpd(): bool {
    $flag = '/var/www/html/dashboard/flags/restart.flag';
    return @touch($flag);
}

function get_test_payloads(): array {
    $base = 'https://studentworks.ms.sapientia.ro';

    return [
        'base' => $base,
        'sqli' => $base . "/?id=1' OR '1'='1",
        'xss'  => $base . "/?search=<script>alert('XSS')</script>",
        'lfi'  => $base . "/?file=../../../../etc/passwd",
    ];
}

function render_rules_table(array $rules, bool $is_editable = false): string {
    if (empty($rules)) {
        return '<p class="empty-state">No rules found.</p>';
    }

    ob_start();
    ?>
    <table class="rules-table">
        <thead>
            <tr>
                <th class="col-id">ID</th>
                <th>Message / Pattern</th>
                <th>File</th>
                <?php if ($is_editable): ?><th>Action</th><?php endif; ?>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($rules as $r): ?>
                <tr>
                    <td><strong><?= h((string)($r['id'] ?? '-')) ?></strong></td>
                    <td>
                        <div class="rule-msg"><?= h($r['msg'] ?? 'No Description') ?></div>
                        <details class="rule-details">
                            <summary>Show Code</summary>
                            <code class="rule-code"><?= h($r['pattern']) ?></code>
                        </details>
                    </td>
                    <td class="file-name"><?= h(basename($r['file'])) ?></td>
                    <?php if ($is_editable): ?>
                        <td>
                            <?php if (is_safe_filename(basename($r['file']))): ?>
                                <a href="?page=edit_rule&file=<?= urlencode(basename($r['file'])) ?>" class="btn btn-sm">Edit</a>
                            <?php endif; ?>
                        </td>
                    <?php endif; ?>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <?php
    return ob_get_clean();
}