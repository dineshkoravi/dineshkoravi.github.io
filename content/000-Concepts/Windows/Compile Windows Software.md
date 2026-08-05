---
publish: true
created: 2026-02-06T18:48:38.293+05:30
modified: 2026-06-22T08:52:39.744+05:30
---

Compile github repositories that have `sln` file.

## Linux

in kali linux, you could use `Mono C# compiler`.

```
mcs -out:SharpSuccessor.exe \  
-target:exe \  
-platform:anycpu \  
-reference:System.DirectoryServices \  
-reference:System.DirectoryServices.Protocols \  
Program.cs Modules/*.cs Properties/AssemblyInfo.cs
```

## Windows

in visual studio ide, build config manager select and build.
