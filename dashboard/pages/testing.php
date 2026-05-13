<?php
$payloads = get_test_payloads();
?>

<div class="dashboard-section testing-console-section">
    <h2 class="testing-title">Penetration Testing Console</h2>

    <div class="payload-buttons">
        <button type="button" class="btn btn-sm btn-payload"
            onclick="setPayload(<?= htmlspecialchars(json_encode($payloads['sqli']), ENT_QUOTES) ?>)">
            SQL Injection (SQLi)
        </button>
        <button type="button" class="btn btn-sm btn-payload"
            onclick="setPayload(<?= htmlspecialchars(json_encode($payloads['xss']), ENT_QUOTES) ?>)">
            Cross-Site Scripting (XSS)
        </button>
        <button type="button" class="btn btn-sm btn-payload"
            onclick="setPayload(<?= htmlspecialchars(json_encode($payloads['lfi']), ENT_QUOTES) ?>)">
            Path Traversal (LFI)
        </button>
    </div>

    <div class="terminal-input-group">
        <span class="terminal-prompt">root@test:~#</span>
        <input type="text" id="targetUrl" class="terminal-input" value="<?= h($payloads['base']) ?>/">
        <button type="button" class="btn btn-success" onclick="fireAttack()">Attack</button>
    </div>

    <div class="iframe-container">
        <div class="iframe-header">
            <span>Target Response</span>
            <span id="loadingIndicator" class="iframe-loader" style="display:none;">Waiting for server...</span>
        </div>
        <iframe id="attackFrame" class="attack-iframe" src="<?= h($payloads['base']) ?>/"></iframe>
    </div>
</div>

<script>
function setPayload(url) {
    document.getElementById('targetUrl').value = url;
    fireAttack();
}

function fireAttack() {
    const url = document.getElementById('targetUrl').value;
    if (!url) return;

    const frame  = document.getElementById('attackFrame');
    const loader = document.getElementById('loadingIndicator');

    loader.style.display = 'inline';
    frame.src = url;
    frame.onload = () => loader.style.display = 'none';
}
</script>