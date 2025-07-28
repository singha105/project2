<?php
session_start();
require_once "includes/db.php";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // CSRF token validation
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        header("Location: registrationform.php?error=csrf");
        exit();
    }

    // Sanitize and validate input
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);
    $confirm_password = trim($_POST['confirm_password']);
    $name = trim($_POST['name']);
    $email = trim($_POST['email']);

    if (empty($username) || empty($password) || empty($confirm_password) || empty($name) || empty($email)) {
        header("Location: registrationform.php?error=invalid");
        exit();
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $password !== $confirm_password) {
        header("Location: registrationform.php?error=invalid");
        exit();
    }

    // Check if username exists
    $stmt = $pdo->prepare("SELECT username FROM users WHERE username = :username");
    $stmt->execute(['username' => $username]);
    if ($stmt->rowCount() > 0) {
        header("Location: registrationform.php?error=exists");
        exit();
    }

    // Hash password and insert user
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("INSERT INTO users (username, password, name, email) VALUES (:username, :password, :name, :email)");
    $stmt->execute([
        'username' => $username,
        'password' => $hashed_password,
        'name' => $name,
        'email' => $email
    ]);

    // Clear CSRF token and redirect to success
    unset($_SESSION['csrf_token']);
    header("Location: success.php");
    exit();
} else {
    echo "Invalid request!";
}
?>
