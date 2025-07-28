<?php
session_start();
ini_set('display_errors', 1);
error_reporting(E_ALL);

require_once "includes/db.php";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    $stmt = $pdo->prepare("SELECT username, password, name FROM users WHERE username = :username");
    $stmt->execute(['username' => $username]);

    if ($stmt->rowCount() === 1) {
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (password_verify($password, $user['password'])) {
            // Session hardening
            session_regenerate_id(true);
            $_SESSION['username'] = $user['username'];
            $_SESSION['name'] = $user['name'];
            $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];

            // CSRF token
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

            header("Location: profile.php?success=login");
            exit();
        } else {
            header("Location: login.php?error=invalid");
            exit();
        }
    } else {
        header("Location: login.php?error=notfound");
        exit();
    }
} else {
    echo "Invalid request!";
}
?>
