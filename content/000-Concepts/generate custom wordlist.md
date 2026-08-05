---
publish: true
created: 2026-02-06T17:16:07.926+05:30
modified: 2026-06-23T12:15:35.376+05:30
---

### CeWL

Custom wordlist generator. crawls a site and can form wordlists or mail lists.

```
cewl -d 5 www.site.com
cewl -d 5 http://monster.pg/blog/ -w custom-wordlist.txt
```

convert the wordlist to lowercase.

```
$ tr A-Z a-z < wordlist.txt > wordlist1.txt
```
