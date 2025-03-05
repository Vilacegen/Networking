<?php
// Ensure all required PHP extensions are enabled
if (!extension_loaded('session')) {
    die('Session extension is not loaded');
}

session_start();

// Database connection
$conn = new mysqli("localhost", "root", "", "secure_login");

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Registration
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['register'])) {
    // Use built-in PHP functions without additional import
    $username = htmlspecialchars(trim($_POST['username']));
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
    
    $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();
    echo "Registration successful!";
}

// Login
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['login'])) {
    $username = htmlspecialchars(trim($_POST['username']));
    $password = $_POST['password'];
    
    $stmt = $conn->prepare("SELECT id, password FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        if (password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            // Use httponly and secure flags for increased security
            setcookie("user", $username, [
                'expires' => time() + 3600,
                'path' => '/',
                'domain' => '', 
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Strict' // Added for modern browsers
            ]);
            echo "Login successful!";
        } else {
            echo "Invalid credentials!";
        }
    } else {
        echo "Invalid credentials!";
    }
}

// Logout
if (isset($_GET['logout'])) {
    session_destroy();
    setcookie("user", "", time() - 3600, "/", "", true, true);
    echo "Logged out successfully!";
}
?>