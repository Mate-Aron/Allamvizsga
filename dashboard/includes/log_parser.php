<?php
function parse_modsec_log($logfile, $limit) {
    if (!file_exists($logfile)) return [];

    $bytes_to_read = $limit * 6000;
    $filesize      = filesize($logfile);
    $offset        = max(0, $filesize - $bytes_to_read);

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
            'id'             => '',
            'time'           => '',
            'source_ip'      => 'Unknown',
            'method'         => 'UNKNOWN',
            'uri'            => '',
            'hostname'       => 'Unknown',
            'user_agent'     => 'Unknown',
            'attack_type'    => 'Unknown',
            'root_cause_ids' => [],
            'rule_details'   => [],
            'final_action'   => 'ALLOWED',
            'raw'            => $raw_entry
        ];

        if (preg_match('/^--([a-zA-Z0-9]+)-A--/m', $raw_entry, $m)) {
            $item['id'] = $m[1];
        }

        if (preg_match('/^\[(.*?)\]\s+\S+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s/m', $raw_entry, $m)) {
            $item['time']      = $m[1];
            $item['source_ip'] = $m[2];
        }

        if (preg_match('/^--\w+-B--\s+(.*?)\n\n/ms', $raw_entry, $m)) {
            $headers = $m[1];
            if (preg_match('/^(POST|GET|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP/i', $headers, $r)) {
                $item['method'] = $r[1];
                $item['uri']    = $r[2];
            }
            if (preg_match('/^Host:\s*(.*)$/im', $headers, $r))       $item['hostname']   = trim($r[1]);
            if (preg_match('/^User-Agent:\s*(.*)$/im', $headers, $r)) $item['user_agent'] = trim($r[1]);
        }

        if (preg_match('/^--\w+-H--\s+(.*?)\n\n/ms', $raw_entry, $m)) {
            foreach (explode("\n", $m[1]) as $line) {
                if (!preg_match('/\[id "(\d+)"\]/', $line, $id_m)) continue;

                $rid = (int)$id_m[1];
                if (!empty($INFRA_RULES) && in_array($rid, $INFRA_RULES)) continue;

                if (!in_array($rid, $item['root_cause_ids'])) $item['root_cause_ids'][] = $rid;

                if (!isset($item['rule_details'][$rid])) {
                    $item['rule_details'][$rid] = [
                        'msg'      => 'No message',
                        'data'     => null,
                        'severity' => 'UNKNOWN',
                        'tags'     => [],
                        'target'   => null
                    ];
                }

                if (preg_match('/\[msg "([^"]+)"\]/', $line, $r))      $item['rule_details'][$rid]['msg']      = $r[1];
                if (preg_match('/\[data "([^"]+)"\]/', $line, $r))     $item['rule_details'][$rid]['data']     = $r[1];
                if (preg_match('/\[severity "([^"]+)"\]/', $line, $r)) $item['rule_details'][$rid]['severity'] = $r[1];
                if (preg_match('/found within ([^:]+:[^\]\s]+)/', $line, $r)) {
                    $item['rule_details'][$rid]['target'] = str_replace(['[', ']'], '', $r[1]);
                }
                if (preg_match_all('/\[tag "([^"]+)"\]/', $line, $r)) {
                    foreach ($r[1] as $t) $item['rule_details'][$rid]['tags'][] = $t;
                }
            }
        }

        if (stripos($raw_entry, 'Access denied') !== false || stripos($raw_entry, '403 Forbidden') !== false) {
            $item['final_action'] = 'BLOCKED';
        } elseif (!empty($item['root_cause_ids'])) {
            $item['final_action'] = 'DETECTED';
        }

        if (!empty($item['root_cause_ids'])) {
            $first = $item['root_cause_ids'][0];
            $item['attack_type'] = $item['rule_details'][$first]['msg'] ?? "Rule ID: $first";
        } else {
            $item['attack_type'] = ($item['final_action'] === 'BLOCKED') ? "Anomaly Score Block" : "Log Entry";
        }

        $parsed_data[] = $item;
    }

    return $parsed_data;
}