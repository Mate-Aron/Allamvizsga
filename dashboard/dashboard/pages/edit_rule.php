<?php
$file = $_GET['file'] ?? null;

// Fájlválasztó lista
if (!$file):
?>
    <h2 class="editor-title">Custom Rules Editor</h2>
    <div class="file-list">
        <h3>Available Files</h3>
        <ul>
            <?php foreach (scandir($RULES_DIR_LOCAL) as $f):
                if ($f === '.' || $f === '..' || !str_ends_with($f, '.conf')) continue;
            ?>
                <li><a href="?page=edit_rule&file=<?= h($f) ?>"><?= h($f) ?></a></li>
            <?php endforeach; ?>
            <li><a href="?page=edit_rule&file=whitelist.conf">whitelist.conf</a></li>
        </ul>
    </div>

<?php
// Biztonsági ellenőrzés
elseif (!allowed_local_path(basename($file))):
?>
    <div class="error">Security error: Invalid file path.</div>

<?php
// Szerkesztő
else:
    $path    = ($file === 'whitelist.conf') ? $WHITELIST_FILE : rtrim($RULES_DIR_LOCAL, '/') . '/' . basename($file);
    $content = file_exists($path) ? file_get_contents($path) : "# New ModSecurity Rule File\nSecRule ...\n";
?>
    <div class="editor-header">
        <h2>Editing: <?= h($file) ?></h2>
        <a href="?page=edit_rule" class="btn btn-primary">Back to list</a>
    </div>

    <form method="post" class="editor-form">
        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
        <input type="hidden" name="action" value="save_file">
        <input type="hidden" name="file_path" value="<?= h($path) ?>">
        <textarea name="content" class="code-editor" spellcheck="false"><?= h($content) ?></textarea>
        <div class="editor-actions">
            <button type="submit" class="btn btn-success">Save</button>
            <span class="restart-hint">Apache restart required for changes to take effect.</span>
        </div>
    </form>

    <div class="editor-footer">
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
            <input type="hidden" name="action" value="restart_httpd">
            <button type="submit" class="btn btn-warning">🔄 Restart Apache</button>
        </form>
    </div>

<?php endif; ?>