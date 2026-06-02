<?php
$activated_rules   = [];
$local_rules       = [];

foreach (list_rule_files($RULES_DIR_ACTIVATED) as $f) {
    foreach (parse_rules_from_file($f) as $rule) $activated_rules[] = $rule;
}

foreach (list_rule_files($RULES_DIR_LOCAL) as $f) {
    foreach (parse_rules_from_file($f) as $rule) $local_rules[] = $rule;
}

$whitelisted_rules = file_exists($WHITELIST_FILE) ? parse_rules_from_file($WHITELIST_FILE) : [];

// Keresés/szűrés
$q = $_GET['q'] ?? '';
$filter = function ($arr, $q) {
    if ($q === '') return $arr;
    $q = mb_strtolower($q);
    return array_filter($arr, function ($r) use ($q) {
        return mb_strpos(mb_strtolower($r['msg'] ?? ''), $q) !== false
            || mb_strpos(mb_strtolower($r['pattern'] ?? ''), $q) !== false
            || mb_strpos(mb_strtolower(basename($r['file'])), $q) !== false
            || (isset($r['id']) && mb_strpos((string)$r['id'], $q) !== false);
    });
};

$loc = $filter($local_rules, $q);
$wl  = $filter($whitelisted_rules, $q);
$act = $filter($activated_rules, $q);
?>

<div class="toolbar">
    <form method="get">
        <input type="hidden" name="page" value="rules">
        <input type="text" name="q" value="<?= h($q) ?>" class="search-input" placeholder="Search by ID, Message or Filename...">
        <button type="submit" class="btn btn-primary">Search</button>
    </form>
</div>

<div>
    <h3 class="rules-table-section">Local Rules</h3>
    <?= render_rules_table($loc, false) ?>
</div>

<div class="rules-table-section">
    <h3>Whitelisted Rules</h3>
    <?= render_rules_table($wl, false) ?>
</div>

<div class="rules-table-section">
    <h3>Activated Rules (Read-only)</h3>
    <?= render_rules_table($act, false) ?>
</div>