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

#img img{

  max-width: 20px; 
  max-height: 20px;
}

#image {
    display: none;
    border: 0px solid green;
    background-color: #F0E68C;
    max-height:50px;
    max-width:400px;
    margin-top: 10px;
}

a:hover + #image {
    display: block;
}

.error {color: #FF0000;}
</style>
</head>
<body>

<?php
$ruleErr = $uaErr = $actErr = "";
$id = $pos = $act = $web = "";


function test_input($data) {
  $data = trim($data);
  $data = stripslashes($data);
  $data = htmlspecialchars($data);
  return $data;

}




?>
<div class = "center">
<p><span class="error">* required field.</span></p>
<form method="post" id = "form" action="uasp.php"> 
  <span class="error">* <?php echo $ruleErr;?></span>
  Rule Name: <a id = "img"><img src='qsm.png'></a>
  <div id = "image">This field is where you enter the name of your policy to distinguish it from others.</div>
  <input type="text" name = "rule_name" id = "rule name">
  <br><br> 
  <span class="error">* <?php echo $uaErr;?></span>
  UserAgent: <a id = "img"><img src='qsm.png'></a>
  <div id = "image">Here, choose the useragent/s which you want to block or unblock.</div>
  <br><br>
  <input type="checkbox" name="ua[]" value="eyebeam">Eyebeam
  <input type="checkbox" name="ua[]" value="friendly-scanner">Friendly-scanner
  <input type="checkbox" name="ua[]" value="sipcli">Sipcli
  <br><br>
  <span class="error">* <?php echo $actErr;?></span>
  Action: <a id = "img"><img src='qsm.png'></a>
  <div id = "image">Here, you can choose either to block or unblock the useragent you've selected from above.</div>
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
