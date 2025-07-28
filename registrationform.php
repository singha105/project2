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
    <title>Sign Up</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <style>
        * { margin:0; padding:0; box-sizing: border-box; }
        html,body { height:100%; width:100%; }
        body {
            background: linear-gradient(135deg, #74ebd5, #ACB6E5);
            font-family: 'Segoe UI', Arial, sans-serif;
            display: flex; justify-content: center; align-items: center;
        }
        .container { 
            background:#fff; width:420px; padding:40px 30px; 
            border-radius:10px; box-shadow:0 4px 12px rgba(0,0,0,0.2); 
            text-align:center; 
        }
        .container h2 { margin-bottom:25px; font-size:28px; color:#2c3e50; }
        .input-group { position:relative; margin-bottom:20px; }
        .input-group i { 
            position:absolute; top:50%; left:10px; transform:translateY(-50%); 
            color:#888; font-size:16px; 
        }
        .input-group input, .full-name-input {
            width:100%; padding:12px 12px 12px 40px; 
            border:1px solid #ccc; border-radius:6px; 
            font-size:15px; 
        }
        .btn { 
            background:#4CAFEE; color:#fff; border:none; width:100%; 
            padding:16px; border-radius:6px; font-size:18px; 
            font-weight:bold; cursor:pointer; transition:0.3s; 
        }
        .btn:hover { background:#3a94d9; transform:scale(1.04); }
        .message { color:red; margin-bottom:10px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>SIGN UP</h2>
        <?php if (isset($_GET['error'])): ?>
            <p class="message">
                <?php if ($_GET['error'] == 'csrf') echo "Security check failed. Please try again."; ?>
                <?php if ($_GET['error'] == 'exists') echo "Username already exists."; ?>
                <?php if ($_GET['error'] == 'invalid') echo "Invalid input. Please try again."; ?>
            </p>
        <?php endif; ?>
        <form method="post" action="addnewuser.php">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <div class="input-group">
                <i class="fa fa-user"></i>
                <input type="text" name="username" placeholder="Your username" required pattern="\w+">
            </div>
            <div class="input-group">
                <i class="fa fa-envelope"></i>
                <input type="email" name="email" placeholder="Your email" required>
            </div>
            <div class="input-group">
                <i class="fa fa-key"></i>
                <input type="password" name="password" placeholder="Your password" required>
            </div>
            <div class="input-group">
                <i class="fa fa-key"></i>
                <input type="password" name="confirm_password" placeholder="Confirm your password" required>
            </div>
            <!-- Full name styled same as others -->
            <div class="input-group">
                <i class="fa fa-id-card"></i>
                <input type="text" class="full-name-input" name="name" placeholder="Full name" required>
            </div>
            <button type="submit" class="btn">SIGN UP</button>
        </form>
        <a href="login.php" style="display:block;margin-top:10px;">Already have an account? Login</a>
    </div>
</body>
</html>
