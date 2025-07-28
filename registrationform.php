<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign Up</title>
    <link rel="stylesheet" type="text/css" href="css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <style>
    body {
        background: red !important;
    }
</style>
</head>
<body>
    <div class="container">
        <h2>SIGN UP</h2>
        <form method="post" action="addnewuser.php">
            <div class="input-group">
                <i class="fa fa-user"></i>
                <input type="text" name="username" placeholder="Your username" required pattern="\w+" title="Only letters, numbers, and underscores">
            </div>

            <div class="input-group">
                <i class="fa fa-envelope"></i>
                <input type="email" name="email" placeholder="Your email" required>
            </div>

            <div class="input-group">
                <i class="fa fa-key"></i>
                <input type="password" name="password" placeholder="Your password" required
                pattern="^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&])[\w!@#$%^&]{8,}$"
                title="At least 8 characters, 1 uppercase, 1 lowercase, 1 number, and 1 special character">
            </div>

            <div class="input-group">
                <i class="fa fa-key"></i>
                <input type="password" name="confirm_password" placeholder="Please confirm your password" required>
            </div>

            <input type="text" name="name" placeholder="Full name" required pattern="[A-Za-z ]+" title="Letters and spaces only">

            <button type="submit" class="btn">SIGN UP</button>
        </form>
    </div>
</body>
</html>
