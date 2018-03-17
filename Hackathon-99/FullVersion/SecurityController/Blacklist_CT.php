<?php
$servername = "localhost";
$username = "root";
$password = "secu";
$dbname = "SC_Blacklist";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
} 
/* echo "Connected successfully"."\r\n"; 
*/

$sql = "CREATE TABLE Blacklist (
ID INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
SIP_URI VARCHAR(30) NOT NULL,
)";

if (mysqli_query($conn, $sql)){
	echo "Table Blacklist created successfully";
}else {
	echo "Error creaing table: " .mysqli_error($conn);
}

$conn->close();

?>
