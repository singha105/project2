<?php
session_start();

// Session timeout - 15 minutes
$timeout = 15 * 60; // 900 seconds

if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeout) {
    session_unset();
    session_destroy();
    header("Location: login.php?error=timeout");
    exit();
}
$_SESSION['last_activity'] = time();


require_once "includes/db.php";

if (!isset($_SESSION['username']) || $_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
    session_unset();
    session_destroy();
    header("Location: login.php?error=session");
    exit();
}

$username = $_SESSION['username'];

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF token validation failed");
    }

    $current_password = trim($_POST['current_password']);
    $new_password = trim($_POST['new_password']);
    $confirm_password = trim($_POST['confirm_password']);

    if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
        $error = "All fields are required.";
    } elseif ($new_password !== $confirm_password) {
        $error = "New passwords do not match.";
    } else {
        $stmt = $pdo->prepare("SELECT password FROM users WHERE username = :username");
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($current_password, $user['password'])) {
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
            $update_stmt = $pdo->prepare("UPDATE users SET password = :password WHERE username = :username");
            $update_stmt->execute(['password' => $hashed_password, 'username' => $username]);
            header("Location: profile.php?success=password");
            exit();
        } else {
            $error = "Current password is incorrect.";
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Change Password</title>
    <style>
        body { background: linear-gradient(135deg, #74ebd5, #ACB6E5); font-family: 'Segoe UI', sans-serif; display:flex; align-items:center; justify-content:center; height:100vh; }
        .container { background:#fff; padding:40px; border-radius:10px; text-align:center; width:420px; box-shadow:0 4px 12px rgba(0,0,0,0.2); }
        input { width:100%; padding:12px; margin:10px 0; border-radius:6px; border:1px solid #ccc; }
        .btn { background:#4CAFEE; color:#fff; padding:12px; border:none; border-radius:6px; font-size:16px; cursor:pointer; width:100%; }
        .btn:hover { background:#3a94d9; }
        .error { color:red; margin-bottom:10px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Change Password</h2>
        <?php if (isset($error)) echo "<p class='error'>$error</p>"; ?>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="password" name="current_password" placeholder="Current Password" required>
            <input type="password" name="new_password" placeholder="New Password" required>
            <input type="password" name="confirm_password" placeholder="Confirm New Password" required>
            <button type="submit" class="btn">Update Password</button>
        </form>
        <a href="profile.php" style="display:block;margin-top:10px;">Back to Profile</a>
    </div>
</body>
</html>
