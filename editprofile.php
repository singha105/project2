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

$current_username = $_SESSION['username'];

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF token validation failed");
    }

    $username = trim($_POST['username']);
    $name = trim($_POST['name']);
    $email = trim($_POST['email']);

    if (empty($username) || empty($name) || empty($email)) {
        $error = "All fields are required.";
    } elseif (!preg_match("/^\w+$/", $username)) {
        $error = "Username can only contain letters, numbers, and underscores.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email format.";
    } else {
        // Check if username already exists (and is not the current one)
        $check_stmt = $pdo->prepare("SELECT username FROM users WHERE username = :username AND username != :current");
        $check_stmt->execute(['username' => $username, 'current' => $current_username]);

        if ($check_stmt->rowCount() > 0) {
            $error = "Username is already taken.";
        } else {
            // Update user details
            $stmt = $pdo->prepare("UPDATE users SET username = :username, name = :name, email = :email WHERE username = :current");
            $stmt->execute([
                'username' => $username,
                'name' => $name,
                'email' => $email,
                'current' => $current_username
            ]);

            // Update session username if changed
            $_SESSION['username'] = $username;
            $_SESSION['name'] = $name;

            header("Location: profile.php?success=profile");
            exit();
        }
    }
}

// Fetch user details for display
$stmt = $pdo->prepare("SELECT username, name, email FROM users WHERE username = :username");
$stmt->execute(['username' => $current_username]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Edit Profile</title>
    <style>
        body { 
            background: linear-gradient(135deg, #74ebd5, #ACB6E5); 
            font-family: 'Segoe UI', sans-serif; 
            display:flex; align-items:center; justify-content:center; 
            height:100vh; 
        }
        .container { 
            background:#fff; padding:40px; border-radius:10px; 
            text-align:center; width:420px; 
            box-shadow:0 4px 12px rgba(0,0,0,0.2); 
        }
        label { 
            display:block; text-align:left; font-weight:bold; 
            margin-top:10px; color:#2c3e50; 
        }
        input { 
            width:100%; padding:12px; margin:8px 0; 
            border-radius:6px; border:1px solid #ccc; 
        }
        .btn { 
            background:#4CAFEE; color:#fff; padding:12px; 
            border:none; border-radius:6px; font-size:16px; 
            cursor:pointer; width:100%; 
        }
        .btn:hover { background:#3a94d9; }
        .error { color:red; margin-bottom:10px; }
        a { display:block; margin-top:10px; text-decoration:none; color:#007BFF; }
        a:hover { text-decoration:underline; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Edit Profile</h2>
        <?php if (isset($error)) echo "<p class='error'>$error</p>"; ?>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

            <label for="username">Username:</label>
            <input type="text" id="username" name="username" 
                   value="<?php echo htmlspecialchars($user['username']); ?>" required>

            <label for="name">Full Name:</label>
            <input type="text" id="name" name="name" 
                   value="<?php echo htmlspecialchars($user['name']); ?>" required>

            <label for="email">Email Address:</label>
            <input type="email" id="email" name="email" 
                   value="<?php echo htmlspecialchars($user['email']); ?>" required>

            <button type="submit" class="btn">Update</button>
        </form>
        <a href="profile.php">Back to Profile</a>
    </div>
</body>
</html>
