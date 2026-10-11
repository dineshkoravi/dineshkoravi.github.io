---
publish: true
created: 2026-10-03T08:40:24.744Z
modified: 2026-10-03T08:40:24.744Z
---

1. Enumerate which file types are actually allowed.
2. Check if any of the allowed types give us code execution.
3. if none of them are useful. Try to bypass file extension verification.

# Apache - .htaccess

if server allows to upload `.htaccess`, you can upload a customised version of this file, which considers a custom extension (`.test`) as your required extension `.php` for example.

```
echo 'AddType application/x-httpd-php .test' > .htaccess
```

Now you can name a php coded files as `.test.` and upload and execute it.
