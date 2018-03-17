<?php
function array_to_xml($data, &$xml_data){
	//TODO

}
$servername = "localhost";
$username = "root";
$password = "secu";
$dbname = "DPI_DB";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
} 


if ($_SERVER["REQUEST_METHOD"] == "POST") {
  if (empty($_POST["rule_name"])||empty($_POST["caller_id"])||empty($_POST["Action"])) {
    echo nl2br('<span style="color:#FF0000;text-align:center;">Please fill in all required fields.</span><br><br>');

    header( "refresh:3;url=bss.php" );
    return false;

  }else{

if (strlen($_POST["rule_name"]) < 3) {
    echo nl2br('<span style="color:#FF0000;text-align:center;">Rule name must be at least 3 characters long.</span><br><br>');
    header( "refresh:3;url=bss.php" );

    return false;

  } else {
    if (strlen($_POST["rule_name"]) > 32) {
    echo nl2br('<span style="color:#FF0000;text-align:center;">Rule name should be no longer than 32 characters.</span><br><br>');
    header( "refresh:3;url=bss.php" );

    return false;

    }
  
}

}
  
}

$rule_name = $_POST["rule_name"];
$caller_id = $_POST["caller_id"];
$Action = $_POST["Action"];

$sql = "INSERT INTO Blacklist (rule_name, caller_id, Action) VALUES ('$rule_name', '$caller_id', '$Action')";

$result = mysqli_query($conn, $sql);
/*if ($result) {
	echo "New record created successfully". "<br>";
	
	
	} else {
		echo "Error: " . $sql . "<br>" . $conn->error;
		}

*/

$sql = "SELECT * FROM Blacklist ORDER BY ID DESC LIMIT 1";
$result = mysqli_query($conn, $sql);

while ($row = mysqli_fetch_assoc($result)){
$data[] = array(
			    'id' => $row["id"],
			    'rule_name' => $row["Rule_name"],
			    'caller_id' => $row["Caller_ID"],
			    'Action' => $row["Action"]
);

}



mysqli_close($conn);
// TODO - ~~~
// Creating an XML File //
// TODO

// Connect to a local server //
// TODO

// Creating a text log file //

$date = date_create("NOW");
$file = 'log_BSS.txt';
$test = date_format($date,"Y/m/d H:i:s") . '-' . $_POST["rule_name"] . '-' . $_POST["caller_id"] . '-' . $_POST["Action"] . "\n";
$ret = file_put_contents($file, $test, FILE_APPEND | LOCK_EX);



?>
