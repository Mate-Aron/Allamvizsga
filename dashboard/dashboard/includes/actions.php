<?php
function handle_post_action() {
    global $WHITELIST_FILE;

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') return '';

    $posted_token = $_POST['csrf_token'] ?? '';
    if (empty($posted_token) || !hash_equals($_SESSION['csrf_token'], $posted_token)) {
        return '<div class="error">Security Error: Invalid CSRF Token. Please refresh the page!</div>';
    }

    $action = $_POST['action'] ?? '';

    if (!is_writable($WHITELIST_FILE) && $action !== 'save_file') {
        return "<div class='error'>Error: The whitelist file is not writable.<br>$WHITELIST_FILE</div>";
    }

    switch ($action) {
        case 'disable_target':
            $rid       = $_POST['rule_id'];
            $source_ip = $_POST['source_ip'];
            $unique_id = getNextRuleId($WHITELIST_FILE, 1000004);
            $line = "SecRule REMOTE_ADDR \"@ipMatch $source_ip\" \"id:$unique_id,phase:1,pass,nolog,ctl:ruleRemoveById=$rid\"\n";
            if (atomic_append_file($WHITELIST_FILE, $line)) {
                return "<div class='success'>✓ IP $source_ip whitelisted for rule $rid (New ID: $unique_id)</div>";
            }
            return "<div class='error'>Save failed. Permission denied.</div>";

        case 'undo_whitelist':
            $rid       = $_POST['rule_id'];
            $source_ip = $_POST['source_ip'];
            $res = remove_line_from_file($WHITELIST_FILE, [$source_ip, "ruleRemoveById=$rid"]);
            if ($res === true)  return "<div class='success'>↩ Whitelist revoked: $source_ip (Rule: $rid). ⚠️ Apache reload required!</div>";
            if ($res === false) return "<div class='error'>Save failed. No write permission?</div>";
            return "<div class='error'>This rule is no longer in the whitelist.</div>";

        case 'disable_rule_globally':
            $rid  = $_POST['rule_id'];
            $line = "SecRuleRemoveById $rid\n";
            if (atomic_append_file($WHITELIST_FILE, $line)) {
                return "<div class='success'>Rule $rid globally disabled! ⚠️ Apache reload required!</div>";
            }
            return "<div class='error'>Save failed. Permission denied.</div>";

        case 'undo_global_whitelist':
            $rid = $_POST['rule_id'];
            $res = remove_line_from_file($WHITELIST_FILE, ["SecRuleRemoveById $rid"]);
            if ($res === true)  return "<div class='success'>↩ Global whitelist revoked (Rule: $rid). ⚠️ Apache reload required!</div>";
            if ($res === false) return "<div class='error'>Save failed. No write permission?</div>";
            return "<div class='error'>This rule is not globally whitelisted.</div>";

        case 'save_file':
            $path    = $_POST['file_path'] ?? '';
            $content = $_POST['content'] ?? '';
            if (allowed_local_path(basename($path)) && save_rule_text($path, $content)) {
                return "<div class='success'>File saved successfully. Backup created.<br>⚠️ Apache reload required!</div>";
            }
            return "<div class='error'>Save failed. Permission error or invalid path.</div>";

        case 'restart_httpd':
            if (restart_httpd()) return "<div class='success'>🔄 Apache reload signal sent!</div>";
            return "<div class='error'>Failed to send reload signal.</div>";
    }

    return '';
}