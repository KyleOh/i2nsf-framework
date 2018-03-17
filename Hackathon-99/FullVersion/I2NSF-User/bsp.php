<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
  if (empty($_POST["rule_name"])) {
    echo nl2br('<span style="color:#FF0000;text-align:center;">Please fill in all required fields.</span><br><br>');

    header( "refresh:3;url=bs.php" );
    return false;

  }else{

if (strlen($_POST["rule_name"]) < 3) {
    echo nl2br('<span style="color:#FF0000;text-align:center;">Rule name must be at least 3 characters long.</span><br><br>');
    header( "refresh:3;url=bs.php" );

    return false;

  } else {
    if (strlen($_POST["rule_name"]) > 32) {
    echo nl2br('<span style="color:#FF0000;text-align:center;">Rule name should be no longer than 32 characters.</span><br><br>');
    header( "refresh:3;url=bs.php" );

    return false;

    }
  
}

}
  
}

$data = $_POST["rule_name"];

echo nl2br("Default Blacklist has been setup successfully!"."\n");
echo nl2br("You will be redirected to the firs page shortly.");

header( "refresh:3;url=select_page.php" );
// Creating an XML File //




// Connect to a local server //
$host = "127.0.0.1";
$TCP_PORT = 6000;
$output = "dpi_default_blacklist,";
$output .= $data;
$socket = socket_create(AF_INET, SOCK_STREAM,0) or die("Could not create socket\n");
socket_connect ($socket , $host,$TCP_PORT ) ;
socket_write($socket, $output, strlen ($output)) or die("Could not write output\n");
socket_close($socket);


// Creating a text log file //

$date = date_create("NOW");
$file = 'log_DBS.txt';
$test = date_format($date,"Y/m/d H:i:s") . '-' . $_POST["rule_name"] . "\n";
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
