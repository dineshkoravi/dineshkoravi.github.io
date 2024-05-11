---
title: Hack The Boo CTF - Web Challenges
date: 2022-11-03 16:31:00 +0530
categories: [HackTheBox, Hack The Boo 2022]
tags: [hackthebox, Easy]
---

-------

```Hack The Boo``` is the CTF by Hack The Box team on the occasion of Halloween 2022.

Here, are two web challenges i have solved.

# Spookifier
---
Difficulty : Easy

![Spookifier View](/assets/img/hacktheboo_ctf/spooky1.png)

> Input text to see the text in spooky fonts.
{: .prompt-info }

After downloading the source code and verifying, we can come to a conclusion that

1. The fourth font text will not be escaped properly.
2. The `Template().Render()` is part of `mako` template library which is vulnerable to `Server Side Template Injection`.

A Quick google search for `mako` payloads to get direct access to `os` from `TemaplteNamespace` can be found in [**PayloadAllTheThings**](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#direct-access-to-os-from-templatenamespace)

## Payload

```python
 {self.module.cache.util.os.popen('cat /flag.txt').read()}
```

Using the payload in the textbox, we can see the flag.

![Spookifier View](/assets/img/hacktheboo_ctf/spooky2.png)
---

# Evaluation Deck
---
![Evaluation Deck web UI](/assets/img/hacktheboo_ctf/evaluation1.png)

## The Game

1. Cards are placed backwards.
2. You can flip the cards only 8 times.
3. some cards cause damage to the ghost and some add health to the ghost. 
4. If ghost health is reaches `0`, we win, if we run out of tries, we loose.

![Burpsuite request UI](/assets/img/hacktheboo_ctf/evaluation2.png)
_Capturing the request in Burpsuite_

## Source Code

```python
code = compile(f'result = {int(current_health)} {operator} {int(attack_power)}',\
 '<string>', 'exec')
exec(code,result)
```
{: file='routes.py'}

By looking at the above code, we can expect that `operator` variable is vulnerable to `Command Injection`. we can verify this using burpsuite again.

![Burpsuite request UI](/assets/img/hacktheboo_ctf/evaluation3.png)
_Request and Response after replacing '+' with '+1;1+'_

![Burpsuite request UI](/assets/img/hacktheboo_ctf/evaluation4.png)
_Request and Response after replacing '+' with '+1;result = 1;1+'_

The above response is proof that we can run python code on the web app server. we simply set the `result` variable to `1` and we were able to return it in `message`.

## Payload

```python
"+1; import os; os.popen('cat /flag.txt').read(); 1+"
```
`+1` and `1+` are used to escape the before and after python variables. The code in-between is used to print out the flag.txt content.

![Burpsuite request UI](/assets/img/hacktheboo_ctf/evaluation5.png)
_Flag acquired_

---
