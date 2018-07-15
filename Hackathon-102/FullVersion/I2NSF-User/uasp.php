<?php

// function array_to_xml( $data, &$xml_data ) {
//     foreach( $data as $key => $value ) {
//         if( is_array($value) ) {
//             if(is_numeric($key)){
//                 $key = 'UserAgent';
//             }
//             $subnode = $xml_data->addChild($key);
//             array_to_xml($value, $subnode);
//         } else {
//             $xml_data->addChild($key, htmlspecialchars($value));
//         }
//     }
// }

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
$xmlhead = "<?xml version='1.0' encoding='UTF-8'?>";
$xml_document = $xmlhead;
$rootELementStart = "<DPI>"; 
$rootElementEnd = "</DPI>";


$xml_document .= $rootELementStart; 
$xml_document .= "<User_Agent>"; 

while ($row = mysqli_fetch_assoc($result)){
$xml_document .= "<ID>"; 
$xml_document .= $row["id"]; 
$xml_document .= "</ID>";
}

$xml_document .= "<Rule_name>"; 
$xml_document .= $rule; 
$xml_document .= "</Rule_name>"; 



foreach ($useragent as $f) { 

$xml_document .= "<UA>"; 
$xml_document .= $f; 
$xml_document .= "</UA>";

} 

$xml_document .= "<Action>"; 
$xml_document .= $action; 
$xml_document .= "</Action>"; 

$xml_document .= "</User_Agent>"; 
$xml_document .= $rootElementEnd; 

header('Content-Type: text/xml; charset=UTF-8');
$xmlstring = $xml_document;
$dom = new DOMDocument;
$dom->preserveWhiteSpace = true;
$dom->loadXML($xmlstring);
$dom->formatOutput = true;
$formattedXML = $dom->saveXML();
echo $formattedXML;


$host = "127.0.0.1";
$TCP_PORT = 6000;
$output = "dpi_user_agent,";
$output .= $formattedXML;
$socket = socket_create(AF_INET, SOCK_STREAM,0) or die("Could not create socket\n");
socket_connect ($socket , $host,$TCP_PORT );
socket_write($socket, $output, strlen ($output)) or die("Could not write output\n");
socket_close($socket);




/*$xml_data = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><DPI></DPI>');
array_to_xml($data, $xml_data);
$xml_result = $xml_data -> asXML();
header('Content-Type: text/xml; charset=UTF-8');
$dom = new DOMDocument();
$dom->loadXML($xml_result);
$dom->formatOutput = true;
$formattedXML = $dom->saveXML();
echo $formattedXML;
*/

// Creating a text log file //



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
mysqli_close($conn);



?>
