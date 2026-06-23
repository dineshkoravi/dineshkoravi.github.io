---
publish: true
created: 2026-02-06T18:24:03.556+05:30
modified: 2026-06-22T09:02:18.676+05:30
---

Things to note.

1. It needs a community string.
2. There are 3 versions. `v1, v2c, v3`.

### snmp-check

1. can work with _2c_ version, but cannot input a _wordlist_. displays well if community string is already present.

Enumeration using **snmp** protocol. here community string is 'public'. does not help if you have wordlist.

```
snmp-check 10.129.230.91 -t 10 -c public -v 1
```

### snmp-brute

Use this for best case scenario. checks both versions at once.

<https://github.com/SECFORCE/SNMP-Brute/blob/master/snmpbrute.py>

```
$ python snmpbrute.py -f /usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt -t 10.129.118.141 -p 161 -b
   _____ _   ____  _______     ____             __
  / ___// | / /  |/  / __ \   / __ )_______  __/ /____
  \__ \/  |/ / /|_/ / /_/ /  / __  / ___/ / / / __/ _ \
 ___/ / /|  / /  / / ____/  / /_/ / /  / /_/ / /_/  __/
/____/_/ |_/_/  /_/_/      /_____/_/   \__,_/\__/\___/

SNMP Bruteforce & Enumeration Script v2.0
http://www.secforce.com / nikos.vassakis <at> secforce.com
###############################################################

Trying ['public', 'private', '0', '0392a0', '1234', '2read', '4changes', 'ANYCOM', 'Admin', 'C0de', 'CISCO', 'CR52401', 'IBM', 'ILMI', 'Intermec', 'NoGaH$@!', 'OrigEquipMfr', 'PRIVATE', 'PUBLIC', 'Private', 'Public', 'SECRET', 'SECURITY', 'SNMP', 'SNMP_trap', 'SUN', 'SWITCH', 'SYSTEM', 'Secret', 'Security', 'Switch', 'System', 'TENmanUFactOryPOWER', 'TEST', 'access', 'adm', 'admin', 'agent', 'agent_steal', 'all', 'all private', 'all public', 'apc', 'bintec', 'blue', 'c', 'cable-d', 'canon_admin', 'cc', 'cisco', 'community', 'core', 'debug', 'default', 'dilbert', 'enable', 'field', 'field-service', 'freekevin', 'fubar', 'guest', 'hello', 'hp_admin', 'ibm', 'ilmi', 'intermec', 'internal', 'l2', 'l3', 'manager', 'mngt', 'monitor', 'netman', 'network', 'none', 'openview', 'pass', 'password', 'pr1v4t3', 'proxy', 'publ1c', 'read', 'read-only', 'read-write', 'readwrite', 'red', 'regional', 'rmon', 'rmon_admin', 'ro', 'root', 'router', 'rw', 'rwa', 'san-fran', 'sanfran', 'scotty', 'secret', 'security', 'seri', 'snmp', 'snmpd', 'snmptrap', 'solaris', 'sun', 'superuser', 'switch', 'system', 'tech', 'test', 'test2', 'tiv0li', 'tivoli', 'trap', 'world', 'write', 'xyzzy', 'yellow'] community strings ...
10.129.118.141 : 161 	Version (v1):	public
10.129.118.141 : 161 	Version (v2c):	public
10.129.118.141 : 161 	Version (v2c):	internal
Waiting for late packets (CTRL+C to stop)

Trying identified strings for READ-WRITE ...

Identified Community strings
	0) 10.129.118.141  public (v1)(RO)
	1) 10.129.118.141  public (v2c)(RO)
	2) 10.129.118.141  internal (v2c)(RO)
Finished!
```

### Nmap - snmpbrute

Nmap can do both versions.

```
$ nmap -sU -p161 --script snmp-brute 10.129.118.141 --script-args snmp-brute.communitiesdb=/usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt,snmp.version=v2c
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-10 06:47 -0500
Nmap scan report for mentorquotes.htb (10.129.118.141)
Host is up (0.14s latency).

PORT    STATE SERVICE
161/udp open  snmp
| snmp-brute:
|   public - Valid credentials
|_  internal - Valid credentials

Nmap done: 1 IP address (1 host up) scanned in 9.35 seconds
```
