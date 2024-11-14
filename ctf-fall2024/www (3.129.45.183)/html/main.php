<?php
	session_start();
	if ($_SESSION['login'] == null)
	{
		header("Location: admin.php");
		exit;
	}
	if (!isset($_COOKIE['admin'])) {
	   setcookie('admin', 'false');
	   $_COOKIE['admin'] = 'false';
	   echo '
<html>
<head><title>404 Not Found</title></head>
<body bgcolor="white">
<center><h1>404 Not Found</h1><p>Have you visited <a href="https://18.191.188.105/homer/">Eval Homer</a>?</.p></center>
<hr><center>nginx/1.14.12</center>
</body>
</html>
<!-- Hmmm, the plot thickens... key{4fc3c2e9b4d7e6680ae326fded7bbbb74ea63437b7b8bbfbda89a0ce222c76f8}-->';
     }
     elseif (isset($_COOKIE['admin']) && strcmp($_COOKIE['admin'], 'true') == 0) {
     	    echo "<!DOCTYPE html><html><head><title>Main</title></head><body><p>Congratulations! Here you go: key{e470cdee843bfc7718bc6ce7031cb3218122d285ece8690e97859268fa36c4d6}</p></body></html>";
     }
     else {
                echo '
<html>
<head><title>404 Not Found</title></head>
<body bgcolor="white">
<center><h1>404 Not Found</h1><p>Have you visited <a href="https://18.191.188.105/homer/">Eval Homer</a>?</.p></center>
<hr><center>nginx/1.14.12</center>
</body>
</html>
<!-- Hmmm, the plot thickens... key{4fc3c2e9b4d7e6680ae326fded7bbbb74ea63437b7b8bbfbda89a0ce222c76f8}-->';}
?>
