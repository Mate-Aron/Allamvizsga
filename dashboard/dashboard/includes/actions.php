<?php
declare(strict_types=1);

function handle_post_action(string $whitelist_path): ?array {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') return null;

    $posted_token = $_POST['csrf_token'] ?? '';
    if (empty($posted_token) || !hash_equals($_SESSION['csrf_token'], $posted_token)) {
        return ['status' => 'error', 'msg' => 'Security Error: Invalid CSRF Token.'];
    }

    $action = $_POST['action'] ?? '';

    if (!is_writable($whitelist_path) && $action !== 'save_file' && $action !== 'restart_httpd') {
        return ['status' => 'error', 'msg' => 'Error: The whitelist file is not writable.'];
    }

    switch ($action) {
        case 'disable_target':
            $rid       = (string)($_POST['rule_id'] ?? '');
            $source_ip = (string)($_POST['source_ip'] ?? '');
            $unique_id = next_rule_id($whitelist_path, 1000004);
            $line = "SecRule REMOTE_ADDR \"@ipMatch $source_ip\" \"id:$unique_id,phase:1,pass,nolog,ctl:ruleRemoveById=$rid\"\n";
            if (append_to_file($whitelist_path, $line)) {
                return ['status' => 'success', 'msg' => "✓ IP $source_ip whitelisted for rule $rid (New ID: $unique_id)"];
            }
            return ['status' => 'error', 'msg' => 'Save failed. Permission denied.'];

        case 'undo_whitelist':
            $rid       = (string)($_POST['rule_id'] ?? '');
            $source_ip = (string)($_POST['source_ip'] ?? '');
            $res = remove_matching_line($whitelist_path, [$source_ip, "ruleRemoveById=$rid"]);
            if ($res === true)  return ['status' => 'success', 'msg' => "↩ Whitelist revoked: $source_ip (Rule: $rid). Apache reload required!"];
            if ($res === false) return ['status' => 'error', 'msg' => 'Save failed. No write permission?'];
            return ['status' => 'error', 'msg' => 'This rule is no longer in the whitelist.'];

        case 'disable_rule_globally':
            $rid  = (string)($_POST['rule_id'] ?? '');
            $line = "SecRuleRemoveById $rid\n";
            if (append_to_file($whitelist_path, $line)) {
                return ['status' => 'success', 'msg' => "Rule $rid globally disabled! Apache reload required!"];
            }
            return ['status' => 'error', 'msg' => 'Save failed. Permission denied.'];

        case 'undo_global_whitelist':
            $rid = (string)($_POST['rule_id'] ?? '');
            $res = remove_matching_line($whitelist_path, ["SecRuleRemoveById $rid"]);
            if ($res === true)  return ['status' => 'success', 'msg' => "↩ Global whitelist revoked (Rule: $rid). Apache reload required!"];
            if ($res === false) return ['status' => 'error', 'msg' => 'Save failed. No write permission?'];
            return ['status' => 'error', 'msg' => 'This rule is not globally whitelisted.'];

        case 'save_file':
            $path    = (string)($_POST['file_path'] ?? '');
            $content = (string)($_POST['content'] ?? '');
            if (is_safe_filename(basename($path)) && save_rule_file($path, $content)) {
                return ['status' => 'success', 'msg' => 'File saved successfully. Backup created. Apache reload required!'];
            }
            return ['status' => 'error', 'msg' => 'Save failed. Permission error or invalid path.'];

        case 'restart_httpd':
            if (restart_httpd()) return ['status' => 'success', 'msg' => 'Apache reload signal sent!'];
            return ['status' => 'error', 'msg' => 'Failed to send reload signal.'];
    }

    return null;
}