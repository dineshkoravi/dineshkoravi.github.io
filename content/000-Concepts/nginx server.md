---
publish: true
created: 2026-03-16T19:10:43.025+05:30
modified: 2026-06-22T09:01:14.440+05:30
---

## Introduction

conf files are located here `/etc/nginx/nginx.conf`.
The file also includes other conf files for other web apps.

```
include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/variatype.htb;
        include /etc/nginx/sites-enabled/portal.variatype.htb;
```
