---
publish: true
created: 2026-01-24T16:14:55.893+05:30
modified: 2026-06-21T20:12:57.204+05:30
---

# Validation

## Kerbrute

You could use usernames list from seclists too.

```
 kerbrute userenum true_users -d nagoya-industries.com --dc 192.168.158.21
```

# Bruteforce

passwordspray  -Test a single password against a list of users.

```
$ kerbrute passwordspray -d nagoya-industries.com --dc 192.168.158.21 true_users 'Service1'
```

bruteforce    Bruteforce username:password combos, from a file or stdin.

The file should have `username:password` format.

```
$ kerbrute bruteforce -d nagoya-industries.com --dc 192.168.158.21 true_users
```

# Generation

## Username-Anarchy

```
$ username-anarchy --list-formats
Plugin name         	Example
--------------------------------------------------------------------------------
first               	anna
firstlast           	annakey
first.last          	anna.key
firstlast[8]        	annakey
first[4]last[4]     	annakey
firstl              	annak
f.last              	a.key
flast               	akey
lfirst              	kanna
l.first             	k.anna
lastf               	keya
last                	key
last.f              	key.a
last.first          	key.anna
FLast               	AKey
first1              	anna0,anna1,anna2
fl                  	ak
fmlast              	abkey
firstmiddlelast     	annaboomkey
fml                 	abk
FL                  	AK
FirstLast           	AnnaKey
First.Last          	Anna.Key
Last                	Key
```

have the usernames in space separated format like `firstname lastname` in users file.

```
$ username-anarchy -i users -f first.last,flast,
```

## usernamer.py

<https://github.com/jseidl/usernamer/blob/master/usernamer.py>

```
 usernamer.py -f users ---
option --- not recognized
usage: /home/kali/.local/bin/usernamer.py [ -f <file> ] [ -n <full name> ] [ -l ]

flags:
	-n	supplies a single name
	-f	supplies name entries from text file
	-l	converts result to lowercase
	-p	manually specify plugins (comma-separated) [default: all]
		['normal', 'two_terms', 'one_term', 'normal_abbreviated', 'dotted_two_terms', 'starts_with', 'under_score']
```

# Enumeration

## rpcclient

```
# Get Usernames list from domain
$ rpcclient -U '%' 10.10.10.161 -c "enumdomusers" | awk '{print $1}' | cut -d ':' -f 2 | sed 's/\[\(.*\)\]/\1/'

# same as above, but with credentials
$ rpcclient -U 'sequel.htb/rose%KxEPkKe6R8su' 10.10.11.51 -c "enumdomusers"
```

## enum4linux

```
# get users list from autorecons output
$ cat results/forest.htb/scans/enum4linux-ng.txt | grep username: | awk '{print $2}'

# get users list from enum4linux
$ enum4linux -U 10.10.10.161 | grep 'user:' | awk '{print $1}' | cut -d ':' -f 2 | sed 's/\[\(.*\)\]/\1/'
```

## LDAP

[[LDAP]]
