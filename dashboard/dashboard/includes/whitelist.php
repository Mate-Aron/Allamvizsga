<?php
function get_whitelist_lines($whitelist_file) {
    return file_exists($whitelist_file) ? file($whitelist_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
}

function is_ip_rule_whitelisted($whitelist_file, $ip, $rid) {
    foreach (get_whitelist_lines($whitelist_file) as $line) {
        if (strpos($line, $ip) !== false && strpos($line, "ruleRemoveById=$rid") !== false) {
            return true;
        }
    }
    return false;
}

function is_rule_globally_whitelisted($whitelist_file, $rid) {
    foreach (get_whitelist_lines($whitelist_file) as $line) {
        if (trim($line) === "SecRuleRemoveById $rid") return true;
    }
    return false;
}