<?php
$servername = "localhost";
$username = "root";
$password = "skku";
$dbname = "DPI_DB";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
} 
/* echo "Connected successfully"."\r\n"; 
*/

$sql = "CREATE TABLE Blacklist (
id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
Rule_name VARCHAR(30) NOT NULL,
Caller_ID VARCHAR(30) NOT NULL,
Action VARCHAR(10) NOT NULL
)";

if (mysqli_query($conn, $sql)){
	echo "Table Blacklist created successfully";
}else {
	echo "Error creaing table: " .mysqli_error($conn);
}

$sql = "CREATE TABLE UserAgent (
id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
Rule_name VARCHAR(30) NOT NULL,
UserAgent VARCHAR(100) NOT NULL,
Action VARCHAR(10) NOT NULL
)";

if (mysqli_query($conn, $sql)){
	echo "Table UserAgent created successfully";
}else {
	echo "Error creaing table: " .mysqli_error($conn);
}

$conn->close();

?>
