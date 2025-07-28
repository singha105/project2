<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Registration Successful</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">

    <style>
        /* Same style as registration page */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        html, body {
            height: 100%;
            width: 100%;
        }

        body {
            background: linear-gradient(135deg, #74ebd5, #ACB6E5);
            font-family: 'Segoe UI', Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .container {
            background: #ffffff;
            width: 420px;
            padding: 40px 30px;
            border-radius: 10px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
            text-align: center;
        }

        .container h2 {
            color: #2c3e50;
            margin-bottom: 20px;
        }

        .container p {
            font-size: 16px;
            margin-bottom: 20px;
        }

        .btn {
            background: #4CAFEE;
            color: #fff;
            border: none;
            width: 100%;
            padding: 16px;
            border-radius: 6px;
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }

        .btn:hover {
            background: #3a94d9;
            transform: scale(1.04);
        }

        .icon {
            color: #4CAF50;
            font-size: 50px;
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        <i class="fa-solid fa-circle-check icon"></i>
        <h2>Registration Successful!</h2>
        <p>You have successfully signed up.</p>
        <a href="login.php" class="btn">Go to Login</a>
    </div>
</body>
</html>
