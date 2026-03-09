<?php
session_start();

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $error = 'Database error.';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Register — StudentWorks</title>
    <link rel="stylesheet" href="style_frontend.css">
</head>
<body>
    <main class="auth-box">
        <h1>Register</h1>
        
        <?php if ($error): ?>
            <div class="error"><?=htmlspecialchars($error)?></div>
        <?php endif; ?>
        
        <div class="register-block">
            <form method="post" action="register.php">
                <label>Username
                    <input name="username" type="text" required>
                </label>
                <label>Password
                    <input name="password" type="password" required>
                </label>
                <button type="submit" name="action" value="register" class="btn btn-primary btn-block">Create account</button>
            </form>
            
            <div class="back-link-container">
                <a href="index.php" class="btn btn-secondary btn-block">Back to Home</a>
            </div>
        </div>
        
        <p>Already have an account? <a href="login.php">Login here</a></p>
    </main>
</body>
</html>