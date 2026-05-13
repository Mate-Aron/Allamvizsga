<?php
session_start();

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $error = "You can't login right now.";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Login — StudentWorks</title>
    <link rel="stylesheet" href="style_frontend.css">
</head>
<body>
    <main class="auth-box">
        <h1>Login</h1>
        
        <?php if (!empty($no_user)): ?>
            <div class="info">No users found. Please register first.</div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="error"><?=htmlspecialchars($error)?></div>
        <?php endif; ?>
        
        <div class="register-block">
            <form method="post" action="login.php">
                <label>Username
                    <input name="username" type="text" required>
                </label>
                <label>Password
                    <input name="password" type="password" required>
                </label>
                <button type="submit" class="btn btn-primary btn-block">Login</button>
            </form>
        
        <div class="back-link-container">
                <a href="index.php" class="btn btn-secondary btn-block">Back to Home</a>
        </div>
        </div>
        <p>Don't have an account? <a href="register.php">Register</a></p>
    </main>
</body>
</html>