<?php
session_start();

// Create CSRF token if not exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <style>
        * { margin:0; padding:0; box-sizing: border-box; }
        html, body { height:100%; width:100%; }
        body {
            background: linear-gradient(135deg, #74ebd5, #ACB6E5);
            font-family: 'Segoe UI', Arial, sans-serif;
            display:flex; justify-content:center; align-items:center;
        }
        .container {
            background:#ffffff;
            width:420px;
            padding:40px 30px;
            border-radius:10px;
            box-shadow:0 4px 12px rgba(0,0,0,0.2);
            text-align:center;
        }
        .container h2 { margin-bottom:25px; font-size:28px; color:#2c3e50; }
        .message { margin-bottom:15px; font-size:15px; }
        .error { color:red; }
        .success { color:green; }

        .input-group { position:relative; margin-bottom:20px; }
        .input-group i {
            position:absolute; top:50%; left:10px;
            transform:translateY(-50%); color:#888; font-size:16px;
        }
        .input-group input {
            width:100%; padding:12px 12px 12px 40px;
            border:1px solid #ccc; border-radius:6px; font-size:15px;
            outline:none;
        }
        .btn {
            background:#4CAFEE; color:#fff; border:none; width:100%;
            padding:16px; border-radius:6px; font-size:18px; font-weight:bold;
            cursor:pointer; letter-spacing:1px; transition:background 0.3s, transform 0.2s;
        }
        .btn:hover { background:#3a94d9; transform:scale(1.04); }
        .link { margin-top:15px; display:block; color:#007BFF; text-decoration:none; }
        .link:hover { text-decoration:underline; }
    </style>
</head>
<body>
    <div class="container">
        <h2>LOGIN</h2>

        <!-- Error and Success Messages -->
        <?php if (isset($_GET['error'])): ?>
            <p class="message error">
                <?php if ($_GET['error'] == 'invalid') echo "Invalid password. Please try again."; ?>
                <?php if ($_GET['error'] == 'notfound') echo "Username not found."; ?>
                <?php if ($_GET['error'] == 'session') echo "Session expired or invalid. Please log in again."; ?>
                <?php if ($_GET['error'] == 'timeout') echo "You were logged out due to inactivity."; ?>
            </p>
        <?php endif; ?>

        <?php if (isset($_GET['success']) && $_GET['success'] == 'logout'): ?>
            <p class="message success">You have successfully logged out.</p>
        <?php endif; ?>

        <form method="post" action="login_process.php">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <div class="input-group">
                <i class="fa fa-user"></i>
                <input type="text" name="username" placeholder="Username" required>
            </div>
            <div class="input-group">
                <i class="fa fa-lock"></i>
                <input type="password" name="password" placeholder="Password" required>
            </div>
            <button type="submit" class="btn">Login</button>
        </form>

        <a href="registrationform.php" class="link">Don't have an account? Sign up</a>
    </div>
</body>
</html>
