---
publish: true
created: 2026-02-17T15:27:48.315+05:30
modified: 2026-06-22T08:58:48.528+05:30
---

Cron is a time-based job scheduler in Unix-like operating systems (Linux, macOS) that automatically runs scripts or commands at scheduled intervals. Users define these automated tasks, known as "cron jobs," in a crontab (cron table) file using a specific 5- or 6-field syntax forMinute, Hour, Day, Month, and Day of Week.

**Syntax**

- `* * * * * command_to_execute`

* Minute (0-59), Hour (0-23), Day of Month (1-31), Month (1-12), Day of Week (0-7, 0 and 7 are Sunday).
  **Special Characters:**

- `*` (Asterisk): Any value.
- `,` (Comma): Value list separator (e.g., 1,3,5).
- `-` (Hyphen): Range of values (e.g., 1-5).
- `/` (Slash): Step values (e.g., `*/15` in minute field means every 15 minutes).

**Management:** Users manage their jobs with `crontab -e` (edit), `crontab -l` (list), and `crontab -r` (remove) commands.

**Common Examples:**
\- `0 0 * * *`: Runs at midnight every day.
\- `30 8 * * 1-5`: Runs at 8:30 AM, Monday through Friday.
\- `*/10 * * * *`: Runs every 10 minutes.
