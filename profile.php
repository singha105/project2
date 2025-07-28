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


if (!isset($_SESSION['username']) || $_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
    session_unset();
    session_destroy();
    header("Location: login.php?error=session");
    exit();
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Profile</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <style>
        body { background: linear-gradient(135deg, #74ebd5, #ACB6E5); font-family: 'Segoe UI', sans-serif; display:flex; align-items:center; justify-content:center; height:100vh; }
        .container { background:#fff; padding:40px; border-radius:10px; text-align:center; width:420px; box-shadow:0 4px 12px rgba(0,0,0,0.2); }
        .container h2 { margin-bottom:20px; color:#2c3e50; }
        .btn { display:inline-block; margin:10px 5px; background:#4CAFEE; color:#fff; padding:12px; border:none; border-radius:6px; text-decoration:none; font-weight:bold; }
        .btn:hover { background:#3a94d9; }
        .message { margin-bottom:10px; color:green; }
    </style>
</head>
<body>
    <div class="container">
        <i class="fa-solid fa-user-circle" style="font-size:50px; color:#4CAFEE;"></i>
        <h2>Welcome, <?php echo htmlspecialchars($_SESSION['name']); ?>!</h2>
        <?php if (isset($_GET['success'])): ?>
            <p class="message">
                <?php if ($_GET['success'] == 'login') echo "Login successful!"; ?>
                <?php if ($_GET['success'] == 'profile') echo "Profile updated!"; ?>
                <?php if ($_GET['success'] == 'password') echo "Password changed!"; ?>
            </p>
        <?php endif; ?>
        <p><strong>Username:</strong> <?php echo htmlspecialchars($_SESSION['username']); ?></p>
        <a href="editprofile.php" class="btn">Edit Profile</a>
        <a href="updatepassword.php" class="btn">Change Password</a>
        <a href="logout.php" class="btn">Logout</a>
    </div>
</body>
</html>
