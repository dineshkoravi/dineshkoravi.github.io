---
publish: true
created: 2026-10-03T08:40:24.748Z
modified: 2026-10-03T08:40:24.748Z
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
