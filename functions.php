<?php
require_once __DIR__ . '/config.php';

function h($s) { return htmlspecialchars($s ?? '', ENT_QUOTES | ENT_SUBSTITUTE); }

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
            $out[] = rtrim($dir, '/').'/'.$f;
        }
    }
    return $out;
}

function remove_line_from_file($file, $match_conditions) {
    if (!file_exists($file)) return null;
    $lines = file($file, FILE_IGNORE_NEW_LINES);
    $new_lines = [];
    $found = false;

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
        $new_content = implode("\n", $new_lines) . "\n";
        return file_put_contents($file, $new_content) !== false;
    }
    return null;
}

// 5. PARSE RULES
function parse_rules_from_file($path) {
    if (!file_exists($path) || !($handle = fopen($path, "r"))) return [];
    
    $out = [];
    $buffer = '';
    
    while (($line = fgets($handle)) !== false) {
        $trimmed = trim($line);
        
        if ($buffer === '' && ($trimmed === '' || $trimmed[0] === '#')) continue;
        
        if (substr($trimmed, -1) === '\\') {
            $buffer .= rtrim(substr($trimmed, 0, -1)) . ' ';
            continue;
        }
        
        $buffer .= $trimmed;
        $fullRule = $buffer;
        $buffer = ''; 
        
        $id = null; 
        $msg = 'No Description';
        
        if (preg_match('/^SecRuleRemoveById\s+([0-9]+)/i', trim($fullRule), $m)) {
            $id = $m[1];
            $msg = "🌍 GLOBALLY DISABLED RULE";
        } elseif (stripos($fullRule, 'SecRule') !== false) {
            if (preg_match('/ctl:ruleRemoveById=([0-9]+)/i', $fullRule, $mTarget)) {
                $target_id = $mTarget[1];
                $ip = preg_match('/@ipMatch\s+([^"]+)/i', $fullRule, $mIp) ? $mIp[1] : 'Unknown IP';
                $id = preg_match('/\bid\s*:\s*([0-9]+)/i', $fullRule, $m) ? $m[1] : rand(1000,9999); 
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

// 6. LOG PARSER
function parse_modsec_log($logfile, $limit) {
    if (!file_exists($logfile)) return [];

    $bytes_to_read = $limit * 6000;
    $filesize = filesize($logfile);
    $offset = max(0, $filesize - $bytes_to_read);
    
    $raw_log = file_get_contents($logfile, false, null, $offset);
    if (!$raw_log) return [];

    $entries = preg_split('/(?=^--[a-zA-Z0-9]{8}-A--$)/m', $raw_log, -1, PREG_SPLIT_NO_EMPTY);
    $entries = array_reverse($entries);

    $parsed_data = [];
    global $INFRA_RULES; 

    foreach ($entries as $raw_entry) {
        if (count($parsed_data) >= $limit) break;
        if (!str_contains($raw_entry, '-Z--')) continue;

        $item = [
            'id' => '', 'time' => '', 'source_ip' => 'Unknown', 'method' => 'UNKNOWN',
            'uri' => '', 'hostname' => 'Unknown', 'user_agent' => 'Unknown',
            'attack_type' => 'Unknown', 'root_cause_ids' => [], 'rule_details' => [],
            'final_action' => 'ALLOWED', 'raw' => $raw_entry
        ];

        if (preg_match('/^--([a-zA-Z0-9]+)-A--/m', $raw_entry, $id_match)) $item['id'] = $id_match[1];
        if (preg_match('/^\[(.*?)\]\s+\S+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s/m', $raw_entry, $header_match)) {
            $item['time'] = $header_match[1];
            $item['source_ip'] = $header_match[2];
        }

        if (preg_match('/^--\w+-B--\s+(.*?)\n\n/ms', $raw_entry, $m_headers)) {
            $headers_block = $m_headers[1];
            if (preg_match('/^(POST|GET|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP/i', $headers_block, $m_req)) {
                $item['method'] = $m_req[1]; $item['uri'] = $m_req[2];
            }
            if (preg_match('/^Host:\s*(.*)$/im', $headers_block, $m_host)) $item['hostname'] = trim($m_host[1]);
            if (preg_match('/^User-Agent:\s*(.*)$/im', $headers_block, $m_ua)) $item['user_agent'] = trim($m_ua[1]);
        }

        if (preg_match('/^--\w+-H--\s+(.*?)\n\n/ms', $raw_entry, $m_audit)) {
            foreach (explode("\n", $m_audit[1]) as $line) {
                if (preg_match('/\[id "(\d+)"\]/', $line, $id_m)) {
                    $rid = (int)$id_m[1];
                    if (!empty($INFRA_RULES) && in_array($rid, $INFRA_RULES)) continue;

                    if (!in_array($rid, $item['root_cause_ids'])) $item['root_cause_ids'][] = $rid;
                    if (!isset($item['rule_details'][$rid])) {
                        $item['rule_details'][$rid] = ['msg' => 'No message', 'data' => null, 'severity' => 'UNKNOWN', 'tags' => [], 'target' => null];
                    }

                    if (preg_match('/\[msg "([^"]+)"\]/', $line, $m)) $item['rule_details'][$rid]['msg'] = $m[1];
                    if (preg_match('/\[data "([^"]+)"\]/', $line, $m)) $item['rule_details'][$rid]['data'] = $m[1];
                    if (preg_match('/\[severity "([^"]+)"\]/', $line, $m)) $item['rule_details'][$rid]['severity'] = $m[1];
                    if (preg_match('/found within ([^:]+:[^\]\s]+)/', $line, $m)) $item['rule_details'][$rid]['target'] = str_replace(['[',']'], '', $m[1]);
                    if (preg_match_all('/\[tag "([^"]+)"\]/', $line, $m_tags)) {
                        foreach ($m_tags[1] as $t) $item['rule_details'][$rid]['tags'][] = $t;
                    }
                }
            }
        }

        if (stripos($raw_entry, 'Access denied') !== false || stripos($raw_entry, '403 Forbidden') !== false) {
            $item['final_action'] = 'BLOCKED';
        } elseif (!empty($item['root_cause_ids'])) {
            $item['final_action'] = 'DETECTED';
        }

        if (!empty($item['root_cause_ids'])) {
            $first_id = $item['root_cause_ids'][0];
            $item['attack_type'] = $item['rule_details'][$first_id]['msg'] ?? "Rule ID: $first_id";
        } else {
            $item['attack_type'] = ($item['final_action'] === 'BLOCKED') ? "Anomaly Score Block" : "Log Entry";
        }

        $parsed_data[] = $item;
    }

    return $parsed_data;
}

// 7. WHITELISTED lines parser and checker
function get_whitelist_lines($whitelist_file) {
    static $lines = null;
    if ($lines === null) {
        $lines = file_exists($whitelist_file) ? file($whitelist_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    }
    return $lines;
}

function is_ip_rule_whitelisted($whitelist_file, $ip, $rid) {
    foreach (get_whitelist_lines($whitelist_file) as $line) {
        if (strpos($line, $ip) !== false && strpos($line, "ruleRemoveById=$rid") !== false) return true;
    }
    return false;
}

function is_rule_globally_whitelisted($whitelist_file, $rid) {
    foreach (get_whitelist_lines($whitelist_file) as $line) {
        if (trim($line) === "SecRuleRemoveById $rid") return true;
    }
    return false;
}

// 8. RESTART APACHE
function restart_httpd() {
    $flag = '/var/www/html/studentworks/flags/restart.flag';
    return @touch($flag);
}

// 9. PENETRATION TESTING HELPER
function get_test_payloads() {

    $base_url = "https://studentworks.ms.sapientia.ro";
    return [
        'base'  => $base_url,
        'sqli'  => $base_url . "/?id=1' OR '1'='1",
        'xss'   => $base_url . "/?search=<script>alert('XSS')</script>",
        'lfi'   => $base_url . "/?file=../../../../etc/passwd",
    ];
}

// 10. NEW RULE ID GENERATOR
function getNextRuleId($filePath, $baseId = 1000000) {
    if (!file_exists($filePath) || filesize($filePath) === 0) {
        return $baseId;
    }

    $content = file_get_contents($filePath);
    
    if (preg_match_all('/id:(\d+)/', $content, $matches)) {
        $maxId = max($matches[1]);
        return $maxId + 1;
    }
    return $baseId;
}