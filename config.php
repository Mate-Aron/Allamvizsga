<?php
$AUDIT_LOG           = '/var/log/httpd/modsec_audit.log';
$RULES_DIR_ACTIVATED = '/etc/httpd/modsecurity.d/activated_rules';
$RULES_DIR_LOCAL     = '/etc/httpd/modsecurity.d/local_rules';
$WHITELIST_FILE      = '/etc/httpd/modsecurity.d/whitelist.conf';

$MAX_ENTRIES = 7000;

$INFRA_RULES = [949110, 980130, 949100, 959100];

// Generate password: php -r "echo password_hash('your_password', PASSWORD_DEFAULT);"
$BASIC_AUTH_USER = 'admin';
$BASIC_AUTH_PASS_HASH = '$2y$10$/Mv1VZfexCsbnDLzifRiJ.qH9zJbfHJc/zNIJaeJuNFWkmn1RitfO'; // admin123
?>