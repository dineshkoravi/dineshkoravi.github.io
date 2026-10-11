---
publish: true
created: 2026-10-03T08:40:24.748Z
modified: 2026-10-03T08:40:24.748Z
---

Show databases

```
mysql -h 127.0.0.1 -P 3306 -u 'lewis' -p'P4ntherg0t1n5r3c0n##' -e 'SHOW DATABASES;'
```

show all tables.

```
mysql -h 127.0.0.1 -P 3306 -u 'lewis' -p'P4ntherg0t1n5r3c0n##' -e 'SELECT table_schema, table_name FROM information_schema.tables;'
```

show rows and columns from a specific database.

```
mysql -h 127.0.0.1 -P 3306 -u 'lewis' -p'P4ntherg0t1n5r3c0n##' -D 'joomla' -e 'SELECT * from sd4fg_users;'
```
