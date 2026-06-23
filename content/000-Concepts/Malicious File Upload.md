---
publish: true
created: 2026-03-23T17:55:49.728+05:30
modified: 2026-06-22T09:00:59.508+05:30
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
