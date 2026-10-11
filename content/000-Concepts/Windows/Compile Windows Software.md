---
publish: true
created: 2026-10-03T08:40:24.748Z
modified: 2026-10-03T08:40:24.748Z
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
