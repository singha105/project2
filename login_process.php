<?php
session_start();
ini_set('display_errors', 1);
error_reporting(E_ALL);

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = htmlspecialchars($_POST['username']);
    $password = htmlspecialchars($_POST['password']);

    // For now just print the values (v0.0)
    echo "<h2>Login Attempt</h2>";
    echo "Username: " . $username . "<br>";
    echo "Password: " . $password . "<br>";

    // Later: Verify user from DB and redirect
} else {
    echo "Invalid request!";
}
?>
