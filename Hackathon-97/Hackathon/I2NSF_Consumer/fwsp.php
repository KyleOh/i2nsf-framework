<?php
function array_to_xml( $data, &$xml_data ) {
    foreach( $data as $key => $value ) {
        if( is_array($value) ) {
            if(is_numeric($key)){
                $key = 'Policies';
            }
            $subnode = $xml_data->addChild($key);
            array_to_xml($value, $subnode);
        } else {
            $xml_data->addChild($key, htmlspecialchars($value));
        }
    }
}
$servername = "localhost";
$username = "root";
$password = "secu";
$dbname = "I2NSF_DB";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
} 


if ($_SERVER["REQUEST_METHOD"] == "POST") {
  if (empty($_POST["Policy_name"])||empty($_POST["Position"])||empty($_POST["Website"])||empty($_POST["Starting_Time"])||empty($_POST["Starting_Time"])||empty($_POST["Ending_Time"])||empty($_POST["Action"])) {
    echo nl2br('<span style="color:#FF0000;text-align:center;">Please fill in all required fields.</span><br><br>');

    header( "refresh:3;url=fws.php" );
    return false;

  }else{

if (strlen($_POST["Policy_name"]) < 3) {
    echo nl2br('<span style="color:#FF0000;text-align:center;">Policy name must be at least 3 characters long.</span><br><br>');
    header( "refresh:3;url=fws.php" );

    return false;

  } else {
    if (strlen($_POST["Policy_name"]) > 32) {
    echo nl2br('<span style="color:#FF0000;text-align:center;">Policy name should be no longer than 32 characters.</span><br><br>');
    header( "refresh:3;url=fws.php" );

    return false;

    }
  
}

}
  
}

$Policy_name = $_POST["Policy_name"];
$Title = $_POST["Position"];
$Web_name = $_POST["Website"];
$Start_time = $_POST["Starting_Time"];
$End_time = $_POST["Ending_Time"];
$Action = $_POST["Action"];

$sql = "INSERT INTO Policies (Policy_name, Position, Web, Start_time, End_time, Action) VALUES ('$Policy_name' , '$Title', '$Web_name', '$Start_time', '$End_time', '$Action')";

$result = mysqli_query($conn, $sql);
/*if ($result) {
	echo "New record created successfully". "<br>";
	
	
	} else {
		echo "Error: " . $sql . "<br>" . $conn->error;
		}

*/

$sql = "SELECT * FROM Policies ORDER BY ID DESC LIMIT 1";
$result = mysqli_query($conn, $sql);

while ($row = mysqli_fetch_assoc($result)){
$data[] = array(
			    'id' => $row["id"],
			    'Policy_name' => $row["Policy_name"],
			    'Position' => $row["Position"],
			    'Website' => $row["Web"],
			    'Start_time' => $row["Start_time"],
			    'End_time' => $row["End_time"],
			    'Action' => $row["Action"]
);

}

/*$fp = fopen("Dark_Knight.xml","wb");
fwrite($fp, $formattedXML);
fclose($fp); 
*/



/*echo json_encode($data);*/


mysqli_close($conn);

// Creating an XML File //

$xml_data = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><I2NSF></I2NSF>');
array_to_xml($data, $xml_data);
$xml_result = $xml_data -> asXML();
header('Content-Type: text/xml; charset=UTF-8');
$dom = new DOMDocument();
$dom->loadXML($xml_result);
$dom->formatOutput = true;
$formattedXML = $dom->saveXML();
echo $formattedXML;


// Connect to a local server //
$host = "127.0.0.1";
$TCP_PORT = 6000;
$output=$formattedXML;
$socket = socket_create(AF_INET, SOCK_STREAM,0) or die("Could not create socket\n");
socket_connect ($socket , $host,$TCP_PORT ) ;
$index = "firewall,";
socket_write($socket, $index, strlen ($index)) or die("Could not write output\n");
socket_write($socket, $output, strlen ($output)) or die("Could not write output\n");
socket_close($socket);


// Creating a text log file //

$date = date_create("NOW");
$file = 'log.txt';
$test = date_format($date,"Y/m/d H:i:s") . '-' . $_POST["Policy_name"] . '-' . $_POST["Position"] . '-' . $_POST["Website"] . '-' . $_POST["Starting_Time"] . '-' . $_POST["Ending_Time"] . '-' . $_POST["Action"] . "\n";
$ret = file_put_contents($file, $test, FILE_APPEND | LOCK_EX);


//header("refresh:0;url=qfc2.php/api/Policies");

/*
$url = "http://localhost/policy.txt";


$postvars='';

$sep='';

foreach($data as $key=>$value)
{
        $postvars.= $sep.urlencode($key).'='.urlencode($value);
        $sep='&';
}

echo $postvars;

$ch = curl_init();

curl_setopt($ch,CURLOPT_URL,$url);
curl_setopt($ch,CURLOPT_POST,count($data));
curl_setopt($ch,CURLOPT_POSTFIELDS,$postvars);
curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);

$result = curl_exec($ch);

curl_close($ch);

echo $result;

*/



?>
