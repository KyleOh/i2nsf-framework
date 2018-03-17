<?php
$servername = "localhost";
$username = "root";
$password = "skku";
$dbname = "I2NSF_DB";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
} 
/* echo "Connected successfully"."\r\n"; 
*/

$sql = "CREATE TABLE Policies (
id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
Policy_name VARCHAR(30) NOT NULL,
Position VARCHAR(50) NOT NULL,
Web VARCHAR(50) Not NULL,
Start_time VARCHAR(5) NOT NULL,
End_time VARCHAR(5) NOT NULL,
Action VARCHAR(10) NOT NULL
)";

if (mysqli_query($conn, $sql)){
	echo "Table Policies created successfully";
}else {
	echo "Error creaing table: " .mysqli_error($conn);
}


$conn->close();

?>
