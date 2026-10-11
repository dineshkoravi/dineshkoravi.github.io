---
publish: true
created: 2026-10-03T08:40:24.748Z
modified: 2026-10-03T08:40:24.748Z
---

## Introduction

conf files are located here `/etc/nginx/nginx.conf`.
The file also includes other conf files for other web apps.

```
include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/variatype.htb;
        include /etc/nginx/sites-enabled/portal.variatype.htb;
```
