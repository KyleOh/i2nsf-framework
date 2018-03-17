<?php


if ($_SERVER["REQUEST_METHOD"] == "POST") {
  if (empty($_POST["rule_name"])||empty($_POST["ua"])||empty($_POST["Action"])) {
    echo nl2br('<span style="color:#FF0000;text-align:center;">Please fill in all required fields.</span><br><br>');

    header( "refresh:3;url=uas.php" );
    return false;

  }else{

if (strlen($_POST["rule_name"]) < 3) {
    echo nl2br('<span style="color:#FF0000;text-align:center;">Rule name must be at least 3 characters long.</span><br><br>');
    header( "refresh:3;url=uas.php" );

    return false;

  } else {
    if (strlen($_POST["rule_name"]) > 32) {
    echo nl2br('<span style="color:#FF0000;text-align:center;">Rule name should be no longer than 32 characters.</span><br><br>');
    header( "refresh:3;url=uas.php" );

    return false;

    }
  
}

}
  
}

$servername = "localhost";
$username = "root";
$password = "secu";
$dbname = "DPI_DB";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
} 


//   if ($result) {
// 	echo "New record created successfully". "<br>";
	
	
// 	} else {
// 		echo "Error: " . $sql . "<br>" . $conn->error;
// 		}

// */

/*$fp = fopen("Dark_Knight.xml","wb");
fwrite($fp, $formattedXML);
fclose($fp); 
*/
$rule = $_POST["rule_name"]; 
$useragent= $_POST["ua"]; 
$action = $_POST["Action"];


foreach ($useragent as $g) { 

$ua .= $g." ";

} 

$sql = "INSERT INTO UserAgent (Rule_name, UserAgent, Action) VALUES ('$rule' , '$ua', '$action')";

$result = mysqli_query($conn, $sql);

$sql = "SELECT * FROM UserAgent ORDER BY ID DESC LIMIT 1";
$result = mysqli_query($conn, $sql);

$date = date_create("NOW");
$file = 'log_UA.txt';
$test = date_format($date,"Y/m/d H:i:s") . '-' . $_POST["rule_name"] . '-' . $ua . '-' . $_POST["Action"] . "\n";
$ret = file_put_contents($file, $test, FILE_APPEND | LOCK_EX);

// Creating an XML File //
// TODO



// Creating connect local server //
// TODO




mysqli_close($conn);



?>
