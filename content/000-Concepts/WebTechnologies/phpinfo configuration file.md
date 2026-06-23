---
publish: true
created: 2026-01-31T11:21:22.943+05:30
modified: 2026-06-22T08:52:06.599+05:30
tags:
  - lfi
  - rfi
---

Contains all the information about current php installation setup.

1. Turning `allow_url_include` to _on_ state, allows `include()` and `require()` functions to load remote code directly. it is disabled by default from PHP 5.
2. Turning `allow_url_fopen` should allow remote file inclusions if `allow_url_include` is on.

if you can access phpinfo page, you could save the file to html and run the script to check vulnerabilities as well. <https://github.com/teambi0s/dfunc-bypasser>
