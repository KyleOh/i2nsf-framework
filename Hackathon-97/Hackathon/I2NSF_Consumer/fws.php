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
// $idErr = $posErr = $webErr = $stimeErr = $etimeErr = $actErr = "";
// $id = $pos = $act = $web = $stime = $etime = "";


function test_input($data) {
  $data = trim($data);
  $data = stripslashes($data);
  $data = htmlspecialchars($data);
  return $data;

}




?>
<div class = "center">
<p><span class="error">* required field.</span></p>
<form method="post" id = "form" action="fwsp.php"> 
  <span class="error">* <?php echo $idErr;?></span>
  Policy Name: 
  <input type="text" name = "Policy_name" id = "Policy name">
  <br><br>
  <span class="error">* <?php echo $posErr; ?></span>
  Position:
  <select name="Position" id = "Position">
  <option value="">Select...</option>
  <option value="President">President</option>
  <option value="Vice_President">Vice President</option>
  <option value="Senior Managing Director">Senior Managing Director</option>
  <option value="Managing Director">Managing Director</option>
  <option value="Department Manager">Department Manager</option>
  <option value="Manager">Manager</option>
  <option value="Assistant Manager">Assistant Manager</option>
  <option value="Staff">Staff</option>
  </select>
  <br><br>
  <span class="error">* <?php echo $webErr; ?></span>
  Website:
  <select name="Website" id = "Website">
  <option value="">Select...</option>
  <option value="Facebook">Facebook</option>
  <option value="Google">Google</option>
  <option value="Naver">Naver</option>
  <option value="Instagram">Instagram</option>
  </select>
  <br><br>
  <span class="error">* <?php echo $stimeErr; ?></span>
  Starting Time :
  <select name = "Starting_Time" id="Starting Time">
  <option value="">Select...</option>
  <option value="01:00">01:00</option>
  <option value="02:00">02:00</option>
  <option value="03:00">03:00</option>
  <option value="04:00">04:00</option>
  <option value="05:00">05:00</option>
  <option value="06:00">06:00</option>
  <option value="07:00">07:00</option>
  <option value="08:00">08:00</option>
  <option value="09:00">09:00</option>
  <option value="10:00">10:00</option>
  <option value="11:00">11:00</option>
  <option value="12:00">12:00</option>
  <option value="13:00">13:00</option>
  <option value="14:00">14:00</option>
  <option value="15:00">15:00</option>
  <option value="16:00">16:00</option>
  <option value="17:00">17:00</option>
  <option value="18:00">18:00</option>
  <option value="19:00">19:00</option>
  <option value="20:00">20:00</option>
  <option value="21:00">21:00</option>
  <option value="22:00">22:00</option>
  <option value="23:00">23:00</option>
  <option value="00:00">00:00</option>
  </select>
  <br><br>
  <span class="error">* <?php echo $etimeErr;?></span>
  Ending Time :
  <select name = "Ending_Time" id="Ending Time">
  <option value="">Select...</option>
  <option value="01:00">01:00</option>
  <option value="02:00">02:00</option>
  <option value="03:00">03:00</option>
  <option value="04:00">04:00</option>
  <option value="05:00">05:00</option>
  <option value="06:00">06:00</option>
  <option value="07:00">07:00</option>
  <option value="08:00">08:00</option>
  <option value="09:00">09:00</option>
  <option value="10:00">10:00</option>
  <option value="11:00">11:00</option>
  <option value="12:00">12:00</option>
  <option value="13:00">13:00</option>
  <option value="14:00">14:00</option>
  <option value="15:00">15:00</option>
  <option value="16:00">16:00</option>
  <option value="17:00">17:00</option>
  <option value="18:00">18:00</option>
  <option value="19:00">19:00</option>
  <option value="20:00">20:00</option>
  <option value="21:00">21:00</option>
  <option value="22:00">22:00</option>
  <option value="23:00">23:00</option>
  <option value="00:00">00:00</option>
  </select>
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


