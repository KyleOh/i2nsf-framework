<?php
$servername = "localhost";
$username = "root";
$password = "secu";


$conn = new mysqli($servername, $username, $password);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
} 


$sql = "CREATE DATABASE I2NSF_DB";
if ($conn->query($sql) === TRUE) {
    echo "I2NSF Database created successfully";
} else {
    echo "Error creating database: " . $conn->error;
}
$sql = "CREATE DATABASE DPI_DB";
if ($conn->query($sql) === TRUE) {
    echo "DPI Database created successfully";
} else {
    echo "Error creating database: " . $conn->error;
}

$conn->close();
?>
