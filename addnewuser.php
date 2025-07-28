<?php
// Version 0.0 - Just print submitted data
ini_set('display_errors', 1);
error_reporting(E_ALL);

echo "<h2>Submitted Registration Data</h2>";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    echo "Username: " . htmlspecialchars($_POST['username']) . "<br>";
    echo "Password: " . htmlspecialchars($_POST['password']) . "<br>";
    echo "Confirm Password: " . htmlspecialchars($_POST['confirm_password']) . "<br>";
    echo "Name: " . htmlspecialchars($_POST['name']) . "<br>";
    echo "Email: " . htmlspecialchars($_POST['email']) . "<br>";
    header("Location: success.php");
    exit();
} else {
    echo "Invalid request method!";
}
?>
