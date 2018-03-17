<?php
$servername = "localhost";
$username = "root";
$password = "secu";


$conn = new mysqli($servername, $username, $password);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
} 


$sql = "CREATE DATABASE SC_Blacklist";
if ($conn->query($sql) === TRUE) {
    echo "Blacklist Database created successfully";
} else {
    echo "Error creating database: " . $conn->error;
}

$conn->close();
?>
