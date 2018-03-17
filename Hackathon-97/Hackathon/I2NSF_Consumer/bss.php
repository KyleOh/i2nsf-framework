<TYPE HTML>
<html>
<head>
<style>
.center {
    margin: left;
    width: 90%;
    border: 3px solid green;
    padding: 10px;
}
input[type=text], select {
    width: 100%;
    padding: 12px 20px;
    margin: 8px 0;
    display: inline-block;
    border: 1px solid #ccc;
    border-radius: 4px;
    box-sizing: border-box;
}

input[type=submit] {
    width: 100%;
    background-color: #4CAF50;
    color: white;
    padding: 12px 20px;
    margin: 8px 0;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}

input[type=submit]:hover {
    background-color: #00FF00;
}

select {
    width: 100%;
    padding: 16px 20px;
    border: none;
    border-radius: 4px;
    background-color: white;
}


div {
    border-radius: 5px;
    background-color: #f2f2f2;
    padding: 20px;
}

.error {color: #FF0000;}
</style>
</head>
<body>

<?php
$ruleErr = $agentErr = $actErr = "";
$id = $pos = $act = $web = $stime = $etime = "";


function test_input($data) {
  $data = trim($data);
  $data = stripslashes($data);
  $data = htmlspecialchars($data);
  return $data;

}




?>
<div class = "center">
<p><span class="error">* required field.</span></p>
<form method="post" id = "form" action="bssp.php"> 
  <span class="error">* <?php echo $ruleErr;?></span>
  Rule Name:
  <br><br> 
  <input type="text" name = "rule_name" id = "rule_name">
  <br><br>
  <span class="error">* <?php echo $callerErr;?></span>
  Caller ID:
  <br><br> 
  <input type="text" name = "caller_id" id = "caller_id">
  <br><br>
  <span class="error">* <?php echo $actErr;?></span>
  Action:
  <select name="Action" id = "Action">
  <option value="">Select...</option>
  <option value="Block">Block</option>
  <option value="Unblock">Unblock</option>
  </select>
  <br><br>
<input type="submit" value="Submit"/>
</form>
</div>
</body>
</html>


